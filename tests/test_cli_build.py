"""CLI integration tests for `pyprotect init` / `build --skip-cython` + runtime behavior.

The subprocess cases replicate the full customer flow: build a protected
project, then run its main.py under different license environments.
"""

from __future__ import annotations

from conftest import run_demo_main
from pyprotect.cli import main as cli_main


# ── init ──────────────────────────────────────────────────────


def test_init_creates_config_and_templates(demo_project, runner):
    r = runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg", "-k", "main.py"])
    assert r.exit_code == 0, r.output
    assert (demo_project / "pyprotect.yaml").is_file()
    assert (demo_project / "_bootstrap.py").is_file()
    assert (demo_project / "license_verify.py").is_file()


def test_init_preserves_existing_templates(demo_project, runner):
    runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg"])
    bootstrap = demo_project / "_bootstrap.py"
    bootstrap.write_text("# marker\n")
    runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg"])
    assert bootstrap.read_text() == "# marker\n"


# ── build (skip-cython, fast) ─────────────────────────────────


def test_build_without_config_fails(runner, tmp_path):
    (tmp_path / "empty").mkdir()
    r = runner.invoke(cli_main, ["build", str(tmp_path / "empty")])
    assert r.exit_code == 1
    assert "pyprotect.yaml not found" in r.output


def test_build_warns_for_missing_package_dir(demo_project, runner):
    runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg", "-p", "ghost"])
    r = runner.invoke(cli_main, ["build", str(demo_project), "--skip-cython"])
    assert r.exit_code == 0, r.output
    assert "Warning" in r.output


def test_skip_cython_artifacts(protected_project):
    mypkg = protected_project / "mypkg"
    assert sorted(p.name for p in mypkg.iterdir()) == ["__init__.enc", "hello.enc"]
    assert (protected_project / "_bootstrap.py").is_file()
    assert (protected_project / "license_verify.enc").is_file()
    assert (protected_project / "main.py").is_file()
    assert not list(protected_project.rglob("*.pyc"))


# ── runtime behavior of the protected project ─────────────────


def test_run_with_valid_license(protected_project, license_factory, machine_id):
    lic = license_factory(machine_id=machine_id)
    r = run_demo_main(protected_project, LICENSE_FILE=str(lic), LICENSE_MACHINE_ID=machine_id)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "license OK" in r.stdout
    assert "hello from mypkg" in r.stdout


def test_run_without_license_is_blocked(protected_project):
    r = run_demo_main(protected_project)
    assert r.returncode == 1
    assert "LICENSE INVALID" in r.stdout


def test_run_dev_opt_in_allows_without_license(protected_project):
    r = run_demo_main(protected_project, PYPROTECT_ALLOW_DEV="1")
    assert r.returncode == 0
    assert "license OK" in r.stdout


def test_run_with_wrong_machine_is_blocked(protected_project, license_factory):
    lic = license_factory(machine_id="machine-a")
    r = run_demo_main(protected_project, LICENSE_FILE=str(lic), LICENSE_MACHINE_ID="machine-b")
    assert r.returncode == 1


def test_run_with_expired_license_is_blocked(protected_project, license_factory, machine_id):
    lic = license_factory(machine_id=machine_id, expire_days=-1)
    r = run_demo_main(protected_project, LICENSE_FILE=str(lic), LICENSE_MACHINE_ID=machine_id)
    assert r.returncode == 1
