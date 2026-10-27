"""Tests for machine-id auto-detection and its integration with verify_license."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from pyprotect.license_gen import detect_machine_id, generate_license
from pyprotect_protected import license_verify as runtime_verify

FAKE_UUID = "01234567-89AB-CDEF-0123-456789ABCDEF"


# ── vendor-side detection ─────────────────────────────────────


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_detect_machine_id_nonempty_on_macos():
    assert detect_machine_id()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_cli_machine_id_command(runner):
    from pyprotect.cli import main as cli_main

    r = runner.invoke(cli_main, ["machine-id"])
    assert r.exit_code == 0, r.output
    assert r.output.strip()


def test_cli_machine_id_fails_closed(runner, monkeypatch):
    from pyprotect import license_gen as lg
    from pyprotect.cli import main as cli_main

    monkeypatch.setattr(lg, "detect_machine_id", lambda: "")
    r = runner.invoke(cli_main, ["machine-id"])
    assert r.exit_code == 1
    assert "LICENSE_MACHINE_ID" in r.output


# ── per-platform parsing (unit, via the identical runtime copy) ──


def test_linux_helper_reads_machine_id_file(runtime_pkg, monkeypatch, tmp_path):
    mid_file = tmp_path / "machine-id"
    mid_file.write_text("  linux-machine-123\n")
    monkeypatch.setattr(runtime_verify, "_LINUX_MACHINE_ID_PATHS", (str(mid_file),))
    assert runtime_verify._detect_linux_machine_id() == "linux-machine-123"


def test_linux_helper_falls_back_to_second_path(runtime_pkg, monkeypatch, tmp_path):
    first = tmp_path / "a"
    second = tmp_path / "b"
    second.write_text("dbus-fallback\n")
    monkeypatch.setattr(runtime_verify, "_LINUX_MACHINE_ID_PATHS", (str(first), str(second)))
    assert runtime_verify._detect_linux_machine_id() == "dbus-fallback"


def test_linux_helper_empty_file_means_not_found(runtime_pkg, monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.write_text("  \n")
    monkeypatch.setattr(runtime_verify, "_LINUX_MACHINE_ID_PATHS", (str(empty),))
    assert runtime_verify._detect_linux_machine_id() == ""


def test_macos_helper_parses_ioreg_output(runtime_pkg, monkeypatch):
    fake = types.SimpleNamespace(
        run=lambda *a, **k: types.SimpleNamespace(
            stdout=f'"IOPlatformUUID" = "{FAKE_UUID}"\n'
        )
    )
    monkeypatch.setattr("subprocess.run", fake.run)
    assert runtime_verify._detect_macos_machine_id() == FAKE_UUID


def test_macos_helper_returns_empty_without_uuid(runtime_pkg, monkeypatch):
    fake = types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(stdout="nope\n"))
    monkeypatch.setattr("subprocess.run", fake.run)
    assert runtime_verify._detect_macos_machine_id() == ""


class _FakeWinreg:
    HKEY_LOCAL_MACHINE = 0

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    @staticmethod
    def OpenKey(root, path):
        return _FakeWinreg._Key()

    @staticmethod
    def QueryValueEx(key, name):
        return ("fake-windows-guid", None)


def test_windows_helper_reads_registry(runtime_pkg, monkeypatch):
    monkeypatch.setitem(sys.modules, "winreg", _FakeWinreg)
    assert runtime_verify._detect_windows_machine_id() == "fake-windows-guid"


def test_windows_helper_missing_registry_returns_empty(runtime_pkg, monkeypatch):
    class Broken(_FakeWinreg):
        @staticmethod
        def OpenKey(root, path):
            raise OSError("nope")

    monkeypatch.setitem(sys.modules, "winreg", Broken)
    assert runtime_verify._detect_windows_machine_id() == ""


# ── integration: verify_license now auto-detects ──────────────


@pytest.fixture
def runtime_pkg():
    return runtime_verify


@pytest.mark.skipif(sys.platform != "darwin", reason="needs real macOS detection")
def test_verify_auto_binds_to_real_machine(keypair, license_factory, monkeypatch, tmp_path):
    """License issued for the auto-detected id validates with NO env var."""
    monkeypatch.delenv("LICENSE_MACHINE_ID", raising=False)
    monkeypatch.setattr(runtime_verify, "_ED25519_PUBLIC_KEY", keypair["public"].read_bytes())
    real_id = detect_machine_id()
    lic = license_factory(machine_id=real_id, out=tmp_path / "l.lic")
    monkeypatch.setenv("LICENSE_FILE", str(lic))
    assert runtime_verify.get_license_info()["valid"] is True


def test_verify_rejects_license_for_other_machine_without_env(
    keypair, license_factory, monkeypatch, tmp_path
):
    """No env var: auto-detected id (if any) won't match a foreign license."""
    monkeypatch.delenv("LICENSE_MACHINE_ID", raising=False)
    monkeypatch.setattr(runtime_verify, "_ED25519_PUBLIC_KEY", keypair["public"].read_bytes())
    lic = license_factory(machine_id="definitely-not-this-machine", out=tmp_path / "l.lic")
    monkeypatch.setenv("LICENSE_FILE", str(lic))
    info = runtime_verify.get_license_info()
    assert info["valid"] is False


def test_env_var_still_overrides_detection(keypair, machine_id, license_factory, monkeypatch, tmp_path):
    """Backward compat: explicit LICENSE_MACHINE_ID wins over detection."""
    monkeypatch.setattr(runtime_verify, "_ED25519_PUBLIC_KEY", keypair["public"].read_bytes())
    lic = license_factory(machine_id=machine_id, out=tmp_path / "l.lic")
    monkeypatch.setenv("LICENSE_FILE", str(lic))
    monkeypatch.setenv("LICENSE_MACHINE_ID", machine_id)
    assert runtime_verify.get_license_info()["valid"] is True


def test_detection_failure_fails_closed(keypair, machine_id, license_factory, monkeypatch, tmp_path):
    lic = license_factory(machine_id=machine_id, out=tmp_path / "l.lic")
    monkeypatch.setenv("LICENSE_FILE", str(lic))
    monkeypatch.delenv("LICENSE_MACHINE_ID", raising=False)
    monkeypatch.setattr(runtime_verify, "_detect_machine_id", lambda: "")
    info = runtime_verify.get_license_info()
    assert info["valid"] is False
    assert info["mode"] == "prod"
