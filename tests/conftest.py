"""Shared fixtures for the pyprotect test suite."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Make the pyprotect-protected runtime package importable (it is a separate
# distribution that is not installed into the dev venv).
sys.path.insert(0, str(ROOT / "pyprotect-protected" / "src"))

from click.testing import CliRunner  # noqa: E402

from pyprotect.cli import main as cli_main  # noqa: E402
from pyprotect.license_gen import generate_keys, generate_license  # noqa: E402

DEFAULT_MACHINE_ID = "test-machine-0001"

ENV_VARS = ("LICENSE_FILE", "LICENSE_MACHINE_ID", "PYPROTECT_ALLOW_DEV")

DEMO_MAIN = """\
import sys

import _bootstrap
from license_verify import verify_license

if not verify_license():
    print("LICENSE INVALID")
    sys.exit(1)

print("license OK")
from mypkg import hello

print(hello.greet())
"""


@pytest.fixture(autouse=True)
def _isolated_license_env(monkeypatch):
    """Ensure tests never see ambient license environment variables."""
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(scope="session")
def keypair(tmp_path_factory):
    keys_dir = tmp_path_factory.mktemp("keys")
    priv, pub = generate_keys(keys_dir)
    return {"private": priv, "public": pub}


@pytest.fixture
def machine_id():
    return DEFAULT_MACHINE_ID


@pytest.fixture
def license_factory(keypair):
    """Factory: license_factory(machine_id=..., expire_days=..., out=...) -> Path."""

    def _make(
        machine_id: str = DEFAULT_MACHINE_ID,
        expire_days: int = 365,
        out: Path | None = None,
    ) -> Path:
        out = out or Path(keypair["private"]).parent / f"lic-{machine_id}-{expire_days}.lic"
        out.write_text(
            generate_license(machine_id, expire_days, Path(keypair["private"]).read_bytes())
        )
        return out

    return _make


@pytest.fixture
def demo_project(tmp_path):
    root = tmp_path / "demo"
    (root / "mypkg").mkdir(parents=True)
    (root / "main.py").write_text(DEMO_MAIN)
    (root / "mypkg" / "__init__.py").write_text("from .hello import greet\n")
    (root / "mypkg" / "hello.py").write_text('def greet():\n    return "hello from mypkg"\n')
    return root


@pytest.fixture
def protected_project(demo_project, runner, keypair):
    """Demo project after `pyprotect init` + `build --skip-cython`."""
    r = runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg", "-k", "main.py"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(
        cli_main,
        ["build", str(demo_project), "--skip-cython", "--pub-key", str(keypair["public"])],
    )
    assert r.exit_code == 0, r.output
    return demo_project


def run_demo_main(project: Path, **env_overrides: str) -> subprocess.CompletedProcess:
    """Run the protected demo main.py in a subprocess with a clean env."""
    env = {k: v for k, v in os.environ.items() if k not in ENV_VARS}
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "main.py"],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
