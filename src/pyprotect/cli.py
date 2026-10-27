from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

import click

from pyprotect import __version__
from pyprotect.compiler import compile_batch
from pyprotect.config import ProjectConfig
from pyprotect.encryptor import encrypt_file, generate_key
from pyprotect.key_inject import inject_hex
from pyprotect.license_gen import generate_keys, generate_license as gen_lic, verify_license as ver_lic, get_license_info

_TEMPLATES_DIR = Path(__file__).parent / "templates"

PLACEHOLDER_NACL = "_KEY = bytes(32)"
PLACEHOLDER_ED25519 = "_ED25519_PUBLIC_KEY = bytes(32)"


def _find_config(start: Path | None = None) -> tuple[Path, ProjectConfig] | None:
    d = (start or Path.cwd()).resolve()
    for parent in [d, *d.parents]:
        cfg = parent / "pyprotect.yaml"
        if cfg.exists():
            return parent, ProjectConfig.from_file(cfg)
    return None


def _collect_py_files(project_root: Path, config: ProjectConfig) -> list[Path]:
    files = []
    for pkg in config.packages:
        pkg_dir = project_root / pkg
        if not pkg_dir.is_dir():
            click.echo(f"  Warning: package dir not found: {pkg_dir}", err=True)
            continue
        for root, dirs, filenames in os.walk(pkg_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in sorted(filenames):
                if f.endswith(".py"):
                    files.append(Path(root) / f)
    return files


def _cleanup(project_root: Path, config: ProjectConfig) -> None:

    keep = set()
    for k in config.keep_plain:
        keep.add(str(project_root / k))

    for pkg in config.packages:
        pkg_dir = project_root / pkg
        if not pkg_dir.is_dir():
            continue
        for root, _dirs, filenames in os.walk(pkg_dir):
            for f in filenames:
                full = Path(root) / f
                if f.endswith((".py", ".pyc", ".pyo", ".c")):
                    if str(full) in keep:
                        continue
                    full.unlink(missing_ok=True)

    # Root-level .c leftovers from _bootstrap.py / license_verify.py compilation
    for name in ("_bootstrap.c", "license_verify.c"):
        (project_root / name).unlink(missing_ok=True)

    for glob_pat in ["__pycache__", "build", "*.egg-info"]:
        if "*" in glob_pat:
            for p in project_root.glob(glob_pat):
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
        else:
            for root, dirs, _ in os.walk(project_root):
                if glob_pat in dirs:
                    shutil.rmtree(Path(root) / glob_pat, ignore_errors=True)


@click.group()
@click.version_option(__version__, prog_name="pyprotect")
def main():
    """pyprotect — Python code protection & licensing toolkit."""


# ── init ──────────────────────────────────────────────────────


@main.command()
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--packages", "-p", multiple=True, help="Package dirs to protect")
@click.option("--keep-plain", "-k", multiple=True, help=".py files to keep as plaintext")
def init(project_dir: str, packages: tuple[str, ...], keep_plain: tuple[str, ...]):
    """Initialize pyprotect.yaml in PROJECT_DIR and copy template files."""

    root = Path(project_dir).resolve()

    cfg = ProjectConfig.from_file(root / "pyprotect.yaml")
    if packages:
        cfg.packages = list(packages)
    if keep_plain:
        cfg.keep_plain = list(keep_plain)

    (root / "pyprotect.yaml").write_text(cfg.to_yaml())
    click.echo(f"  Created {root / 'pyprotect.yaml'}")

    if not cfg.packages:
        click.echo("  Hint: re-run with --packages <dir> to configure")

    _bootstrap_template = _TEMPLATES_DIR / "_bootstrap.py"
    dest = root / "_bootstrap.py"
    if not dest.exists():
        shutil.copy2(str(_bootstrap_template), str(dest))
        click.echo(f"  Copied _bootstrap.py template")

    verify_template = _TEMPLATES_DIR / "license_verify.py"
    verify_dest = root / "license_verify.py"
    if not verify_dest.exists():
        shutil.copy2(str(verify_template), str(verify_dest))
        click.echo(f"  Copied license_verify.py template")

    click.echo("  Done. Next: pyprotect build")


# ── build ─────────────────────────────────────────────────────


@main.command()
@click.argument("project_dir", type=click.Path(exists=True, file_okay=False), required=False)
@click.option("--skip-cython", is_flag=True, help="Skip Cython, encrypt only")
@click.option("--pub-key", help="Ed25519 public key path (overrides pyprotect.yaml)")
@click.option("--packages", "-p", multiple=True, help="Override packages from pyprotect.yaml")
@click.option("--keep-plain", "-k", multiple=True, help="Override keep_plain from pyprotect.yaml")
@click.option("--no-license", is_flag=True, help="Do not inject license key (skip license_verify.py)")
def build(
    project_dir: str | None,
    skip_cython: bool,
    pub_key: str | None,
    packages: tuple[str, ...],
    keep_plain: tuple[str, ...],
    no_license: bool,
):
    """Build protected distribution: Cython compile + NaCl encrypt + cleanup."""

    result = _find_config(Path(project_dir) if project_dir else None)
    if result is None:
        click.echo("Error: pyprotect.yaml not found. Run 'pyprotect init' first.", err=True)
        sys.exit(1)
    root, cfg = result

    if packages:
        cfg.packages = list(packages)
    if keep_plain:
        cfg.keep_plain = list(keep_plain)

    if not cfg.packages:
        click.echo("Error: no packages configured in pyprotect.yaml.", err=True)
        sys.exit(1)

    click.echo(f"Project: {root}")
    click.echo(f"Packages: {', '.join(cfg.packages)}")

    # ── 1. Inject Ed25519 public key ──
    if not no_license:
        click.echo("\n[1/5] Injecting license public key...")
        pub_key_path = pub_key or cfg.ed25519_public_key
        pub_key_file = Path(pub_key_path)
        if not pub_key_file.is_absolute():
            pub_key_file = root / pub_key_file
        verify_file = root / "license_verify.py"
        if pub_key_file.exists() and verify_file.exists():
            inject_hex(verify_file, PLACEHOLDER_ED25519, pub_key_file.read_bytes())
            click.echo(f"  Key injected into license_verify.py")
        else:
            click.echo(f"  Skipped: public key or license_verify.py not found")
    else:
        click.echo("\n[1/5] Skipped: --no-license")

    # ── 2. Generate NaCl key + inject into bootstrap ──
    click.echo("\n[2/5] Injecting NaCl encryption key...")
    nacl_key = generate_key()
    bootstrap_file = root / "_bootstrap.py"
    if not bootstrap_file.exists():
        click.echo("  Warning: _bootstrap.py not found, creating from template", err=True)
        shutil.copy2(str(_TEMPLATES_DIR / "_bootstrap.py"), str(bootstrap_file))
    inject_hex(bootstrap_file, PLACEHOLDER_NACL, nacl_key)
    click.echo("  NaCl key injected into _bootstrap.py")

    # ── 3. Compile bootstrap ──
    if not skip_cython:
        click.echo("\n[3/5] Compiling _bootstrap.so...")
        from pyprotect.compiler import compile_file

        so_path = compile_file(bootstrap_file, module_name="_bootstrap")
        if so_path is None:
            click.echo("  Error: _bootstrap.so compilation failed!", err=True)
            sys.exit(1)
        click.echo(f"  {so_path.name}")
        bootstrap_file.unlink(missing_ok=True)
    else:
        click.echo("\n[3/5] Skipped Cython (--skip-cython)")

    # ── 4. Compile / encrypt core packages ──
    py_files = _collect_py_files(root, cfg)
    verify_file = root / "license_verify.py"
    if verify_file.exists():
        py_files.append(verify_file)
    click.echo(f"\n[4/5] Protecting {len(py_files)} files...")

    if not skip_cython:
        compiled, failed = compile_batch(py_files, root)
        click.echo(f"  Cython compiled: {len(compiled)}, fallback encrypt: {len(failed)}")
        for p in compiled:
            p.unlink(missing_ok=True)
    else:
        failed = py_files
        compiled = []

    for p in failed:
        encrypt_file(p, nacl_key)
        p.unlink(missing_ok=True)
        rel = p.relative_to(root)
        click.echo(f"  Encrypted: {rel}")

    # ── 5. Cleanup ──
    click.echo("\n[5/5] Cleaning up source files...")
    _cleanup(root, cfg)
    click.echo("  Done.")

    # ── Stats ──
    so_count = sum(1 for _ in root.rglob("*.so") if ".venv" not in str(_) and "site-packages" not in str(_))
    enc_count = sum(1 for _ in root.rglob("*.enc"))
    click.echo(f"\n  .so files: {so_count}")
    click.echo(f"  .enc files: {enc_count}")
    click.echo("Build complete.")


# ── license ───────────────────────────────────────────────────


@main.group()
def license():
    """Manage Ed25519 license keys and .lic files."""


@license.command("init")
@click.option("--output-dir", "-o", default="keys", help="Output directory for keys")
def license_init(output_dir: str):
    """Generate a new Ed25519 key pair."""

    priv_path, pub_path = generate_keys(output_dir)
    click.echo(f"Private key: {priv_path}")
    click.echo(f"Public key:  {pub_path}")
    click.echo("Keep the private key secure — it is needed to generate licenses.")


@license.command("generate")
@click.option("--machine-id", required=True, help="Target machine identifier")
@click.option("--expire-days", type=int, default=365, help="Validity in days (default: 365)")
@click.option("--private-key", required=True, type=click.Path(exists=True), help="Path to Ed25519 private key")
@click.option("--output", "-o", default="license.lic", help="Output path for .lic file")
@click.option("--max-users", type=int, help="Optional: max user limit")
def license_generate(machine_id: str, expire_days: int, private_key: str, output: str, max_users: int | None):
    """Generate a .lic license file for a target machine."""

    priv_bytes = Path(private_key).read_bytes()
    features = {}
    if max_users:
        features["max_users"] = max_users
    lic = gen_lic(machine_id, expire_days, priv_bytes, features or None)
    Path(output).write_text(lic)
    click.echo(f"License saved: {output}")
    click.echo(f"  Machine ID: {machine_id}")
    click.echo(f"  Valid for: {expire_days} days")
    if features:
        click.echo(f"  Features: {features}")


@license.command("verify")
@click.option("--license-file", required=True, type=click.Path(exists=True), help="Path to .lic file")
@click.option("--machine-id", required=True, help="Machine identifier to check")
@click.option("--public-key", required=True, type=click.Path(exists=True), help="Path to Ed25519 public key")
def license_verify(license_file: str, machine_id: str, public_key: str):
    """Verify a .lic file (developer-side testing)."""

    pub_bytes = Path(public_key).read_bytes()
    info = get_license_info(license_file, machine_id, pub_bytes)
    if info["valid"]:
        click.echo("License VALID")
    else:
        click.echo("License INVALID")
    for k, v in info.items():
        click.echo(f"  {k}: {v}")
    if not info["valid"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
