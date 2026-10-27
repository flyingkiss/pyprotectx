"""CLI integration tests for the `pyprotect license` command group."""

from __future__ import annotations

from pyprotect.cli import main as cli_main


def test_license_init_creates_keypair(runner, tmp_path):
    keys = tmp_path / "keys"
    r = runner.invoke(cli_main, ["license", "init", "-o", str(keys)])
    assert r.exit_code == 0, r.output
    assert (keys / "license_ed25519.key").is_file()
    assert (keys / "license_ed25519.pub").is_file()


def test_generate_writes_license_file(runner, keypair, machine_id, tmp_path):
    out = tmp_path / "gen.lic"
    r = runner.invoke(
        cli_main,
        [
            "license", "generate",
            "--machine-id", machine_id,
            "--expire-days", "30",
            "--private-key", str(keypair["private"]),
            "-o", str(out),
        ],
    )
    assert r.exit_code == 0, r.output
    assert out.is_file()


def test_verify_valid_license(runner, keypair, machine_id, license_factory, tmp_path):
    lic = license_factory(machine_id=machine_id, out=tmp_path / "l.lic")
    r = runner.invoke(
        cli_main,
        [
            "license", "verify",
            "--license-file", str(lic),
            "--machine-id", machine_id,
            "--public-key", str(keypair["public"]),
        ],
    )
    assert r.exit_code == 0, r.output
    assert "License VALID" in r.output


def test_verify_invalid_license_exits_nonzero(runner, keypair, license_factory, tmp_path):
    lic = license_factory(machine_id="machine-a", out=tmp_path / "l.lic")
    r = runner.invoke(
        cli_main,
        [
            "license", "verify",
            "--license-file", str(lic),
            "--machine-id", "machine-b",
            "--public-key", str(keypair["public"]),
        ],
    )
    assert r.exit_code == 1
    assert "License INVALID" in r.output


def test_verify_missing_license_file_fails(runner, keypair, tmp_path):
    r = runner.invoke(
        cli_main,
        [
            "license", "verify",
            "--license-file", str(tmp_path / "nope.lic"),
            "--machine-id", "m",
            "--public-key", str(keypair["public"]),
        ],
    )
    assert r.exit_code != 0
