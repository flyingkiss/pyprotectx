"""Unit tests for pyprotect.license_gen."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from pyprotect.license_gen import (
    generate_keys,
    get_license_info,
    verify_license,
)


def test_generate_keys_creates_keypair(tmp_path):
    priv, pub = generate_keys(tmp_path / "keys")
    assert priv.is_file() and pub.is_file()
    assert len(priv.read_bytes()) == 32
    assert len(pub.read_bytes()) == 32


def test_generate_and_verify_roundtrip(keypair, machine_id, license_factory):
    lic = license_factory(machine_id=machine_id)
    pub = Path(keypair["public"]).read_bytes()
    info = get_license_info(str(lic), machine_id, pub)
    assert info["valid"] is True
    assert info["mode"] == "prod"
    assert 0 < info["days_remaining"] <= 365


def test_verify_rejects_wrong_machine(keypair, license_factory):
    lic = license_factory(machine_id="machine-a")
    pub = Path(keypair["public"]).read_bytes()
    assert get_license_info(str(lic), "machine-b", pub)["valid"] is False


def test_verify_rejects_expired(keypair, machine_id, license_factory):
    lic = license_factory(machine_id=machine_id, expire_days=-1)
    pub = Path(keypair["public"]).read_bytes()
    assert get_license_info(str(lic), machine_id, pub)["valid"] is False


def test_verify_rejects_empty_machine_id(keypair, license_factory):
    lic = license_factory(machine_id="machine-a")
    pub = Path(keypair["public"]).read_bytes()
    assert get_license_info(str(lic), "", pub)["valid"] is False


def test_verify_rejects_tampered_payload(keypair, machine_id, license_factory):
    lic = license_factory(machine_id=machine_id)
    outer = json.loads(base64.b64decode(lic.read_text()))
    payload = outer["payload"]
    payload["machine_id"] = "attacker-machine"
    outer["data_b64"] = base64.b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    tampered = lic.parent / "tampered.lic"
    tampered.write_text(base64.b64encode(json.dumps(outer).encode()).decode())
    pub = Path(keypair["public"]).read_bytes()
    assert get_license_info(str(tampered), "attacker-machine", pub)["valid"] is False


def test_missing_license_file_fails_closed(keypair):
    pub = Path(keypair["public"]).read_bytes()
    info = get_license_info("/nonexistent/license.lic", "any-machine", pub)
    assert info["valid"] is False
    assert info["mode"] == "prod"


def test_verify_helper_returns_bool(keypair, machine_id, license_factory):
    lic = license_factory(machine_id=machine_id)
    pub = Path(keypair["public"]).read_bytes()
    assert verify_license(str(lic), machine_id, pub) is True
    assert verify_license(str(lic), "other", pub) is False
