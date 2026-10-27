"""Tests for the pyprotectx-protected runtime package (pyprotect_protected).

Note: the published runtime package ships with placeholder keys
(`_KEY = bytes(32)` / `_ED25519_PUBLIC_KEY = bytes(32)`). A vendor is
expected to inject their own keys before distributing it to customers;
the placeholder-key tests below document that behavior.
"""

from __future__ import annotations

import sys

from conftest import ROOT

from pyprotect.license_gen import generate_license  # noqa: F401
from pyprotect_protected import get_license_info, license_verify as runtime_verify
from pyprotect_protected._bootstrap import _EncryptedFinder


def test_import_registers_encrypted_finder():
    assert any(isinstance(f, _EncryptedFinder) for f in sys.meta_path)


def test_fail_closed_without_license_env():
    info = get_license_info()
    assert info["valid"] is False
    assert info["mode"] == "prod"


def test_dev_opt_in(monkeypatch):
    monkeypatch.setenv("PYPROTECT_ALLOW_DEV", "1")
    info = get_license_info()
    assert info["valid"] is True
    assert info["mode"] == "dev"


def test_valid_license_after_key_injection(
    keypair, machine_id, license_factory, monkeypatch, tmp_path
):
    monkeypatch.setattr(runtime_verify, "_ED25519_PUBLIC_KEY", keypair["public"].read_bytes())
    lic = license_factory(machine_id=machine_id, out=tmp_path / "l.lic")
    monkeypatch.setenv("LICENSE_FILE", str(lic))
    monkeypatch.setenv("LICENSE_MACHINE_ID", machine_id)
    assert get_license_info()["valid"] is True


def test_wrong_machine_after_key_injection(keypair, license_factory, monkeypatch, tmp_path):
    monkeypatch.setattr(runtime_verify, "_ED25519_PUBLIC_KEY", keypair["public"].read_bytes())
    lic = license_factory(machine_id="machine-a", out=tmp_path / "l.lic")
    monkeypatch.setenv("LICENSE_FILE", str(lic))
    monkeypatch.setenv("LICENSE_MACHINE_ID", "machine-b")
    assert get_license_info()["valid"] is False


def test_placeholder_key_rejects_real_license(keypair, machine_id, license_factory, monkeypatch, tmp_path):
    """Documents current behavior: without key injection, verification always fails."""
    lic = license_factory(machine_id=machine_id, out=tmp_path / "l.lic")
    monkeypatch.setenv("LICENSE_FILE", str(lic))
    monkeypatch.setenv("LICENSE_MACHINE_ID", machine_id)
    assert get_license_info()["valid"] is False


def test_license_verify_stays_in_sync_with_template():
    """The runtime package and the build template ship the same license_verify
    logic; if they intentionally diverge, update both and relax this test."""
    template = (
        ROOT / "src" / "pyprotect" / "templates" / "license_verify.py"
    ).read_text()
    runtime = (ROOT / "pyprotect-protected" / "src" / "pyprotect_protected" / "license_verify.py").read_text()
    assert template == runtime
