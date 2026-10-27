"""Full Cython build path (marked `slow`: compiles extensions, needs a C compiler)."""

from __future__ import annotations

import shutil

import pytest

from conftest import run_demo_main
from pyprotect.cli import main as cli_main

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(shutil.which("cc") is None, reason="C compiler not available"),
]


@pytest.fixture
def cython_project(demo_project, runner, keypair):
    r = runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg", "-k", "main.py"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(
        cli_main,
        ["build", str(demo_project), "--pub-key", str(keypair["public"])],
    )
    assert r.exit_code == 0, r.output
    return demo_project


def test_cython_build_artifacts(cython_project):
    so_names = {p.name for p in cython_project.rglob("*.so")}
    assert len(so_names) == 4
    assert any(n.startswith("_bootstrap.") for n in so_names)
    assert any(n.startswith("license_verify.") for n in so_names)

    remaining_py = sorted(
        str(p.relative_to(cython_project)) for p in cython_project.rglob("*.py")
    )
    assert remaining_py == ["main.py"]

    assert list(cython_project.rglob("*.c")) == []


def test_cython_build_runs_with_valid_license(cython_project, license_factory, machine_id):
    lic = license_factory(machine_id=machine_id)
    r = run_demo_main(cython_project, LICENSE_FILE=str(lic), LICENSE_MACHINE_ID=machine_id)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "hello from mypkg" in r.stdout


def test_cython_build_blocks_without_license(cython_project):
    r = run_demo_main(cython_project)
    assert r.returncode == 1
    assert "LICENSE INVALID" in r.stdout
