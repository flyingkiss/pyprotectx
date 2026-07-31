from __future__ import annotations

import base64
import json
import time
from pathlib import Path

from nacl.signing import SigningKey

__all__ = [
    "generate_keys",
    "generate_license",
    "verify_license",
    "get_license_info",
]


def generate_keys(output_dir: str | Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    signing_key = SigningKey.generate()
    priv_path = output_dir / "license_ed25519.key"
    pub_path = output_dir / "license_ed25519.pub"
    priv_path.write_bytes(bytes(signing_key))
    pub_path.write_bytes(bytes(signing_key.verify_key))
    return priv_path, pub_path


def generate_license(
    machine_id: str,
    expire_days: int,
    private_key: bytes,
    features: dict | None = None,
) -> str:
    signing_key = SigningKey(private_key)
    payload: dict = {
        "machine_id": machine_id,
        "expire_at": int(time.time()) + expire_days * 86400,
        "issued_at": int(time.time()),
    }
    if features:
        payload["features"] = features
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signed = signing_key.sign(data)
    result = {
        "payload": payload,
        "sig": base64.b64encode(signed.signature).decode(),
        "data_b64": base64.b64encode(data).decode(),
    }
    return base64.b64encode(json.dumps(result, separators=(",", ":")).encode()).decode()


def get_license_info(
    license_file: str,
    machine_id: str,
    public_key: bytes,
) -> dict:
    lic_path = Path(license_file)

    if not lic_path.is_file():
        return {
            "mode": "dev",
            "valid": True,
            "days_remaining": None,
            "expire_at": None,
            "issued_at": None,
            "machine_id": None,
        }

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    try:
        lic_content = lic_path.read_text().strip()
        outer = json.loads(base64.b64decode(lic_content).decode())
        payload = outer["payload"]
        sig = base64.b64decode(outer["sig"])
        data_b64 = outer.get("data_b64")
        if data_b64:
            signed_data = base64.b64decode(data_b64)
        else:
            signed_data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

        verify_key = VerifyKey(public_key)
        verify_key.verify(signed_data, sig)
    except BadSignatureError:
        return {
            "mode": "prod",
            "valid": False,
            "days_remaining": 0,
            "expire_at": None,
            "issued_at": None,
            "machine_id": None,
        }
    except Exception:
        return {
            "mode": "prod",
            "valid": False,
            "days_remaining": 0,
            "expire_at": None,
            "issued_at": None,
            "machine_id": None,
        }

    if not machine_id or payload.get("machine_id") != machine_id:
        return {
            "mode": "prod",
            "valid": False,
            "days_remaining": 0,
            "expire_at": None,
            "issued_at": None,
            "machine_id": None,
        }

    expire_at = payload.get("expire_at", 0)
    now = time.time()
    valid = now <= expire_at
    days_remaining = max(0, int((expire_at - now) / 86400))

    return {
        "mode": "prod",
        "valid": valid,
        "days_remaining": days_remaining,
        "expire_at": expire_at,
        "issued_at": payload.get("issued_at"),
        "machine_id": machine_id[:4] + "****" + machine_id[-4:] if len(machine_id) > 8 else machine_id,
    }


def verify_license(
    license_file: str,
    machine_id: str,
    public_key: bytes,
) -> bool:
    return get_license_info(license_file, machine_id, public_key)["valid"]
