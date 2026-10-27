"""
License verification module — client-side runtime.

This file is injected with an Ed25519 public key at build time and
should be Cython-compiled to .so before distribution.

Env vars:
  LICENSE_FILE         Path to the .lic license file
  LICENSE_MACHINE_ID   Machine identifier for binding
  PYPROTECT_ALLOW_DEV  Set to "1" to allow running without a license
                       (development only; default is to fail closed)

Integration:
  from license_verify import verify_license

  if not verify_license():
      print("License invalid or expired")
      sys.exit(1)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

logger = logging.getLogger(__name__)

_ED25519_PUBLIC_KEY = bytes(32)


def _mask_machine_id(mid: str) -> str:
    if len(mid) <= 8:
        return mid[:2] + "****"
    return mid[:4] + "****" + mid[-4:]


def get_license_info() -> dict:
    lic_path = os.environ.get("LICENSE_FILE", "")
    machine_id = os.environ.get("LICENSE_MACHINE_ID", "")

    if not lic_path or not os.path.isfile(lic_path):
        if os.environ.get("PYPROTECT_ALLOW_DEV") == "1":
            return {
                "mode": "dev",
                "valid": True,
                "days_remaining": None,
                "expire_at": None,
                "issued_at": None,
                "machine_id": None,
            }
        logger.error(
            "License file not found or unreadable: set LICENSE_FILE "
            "(or PYPROTECT_ALLOW_DEV=1 to explicitly allow development mode)"
        )
        return {
            "mode": "prod",
            "valid": False,
            "days_remaining": 0,
            "expire_at": None,
            "issued_at": None,
            "machine_id": None,
        }

    try:
        lic_content = open(lic_path).read().strip()
        outer = json.loads(base64.b64decode(lic_content).decode())
        payload = outer["payload"]
        sig = base64.b64decode(outer["sig"])
        data_b64 = outer.get("data_b64")
        if data_b64:
            signed_data = base64.b64decode(data_b64)
        else:
            signed_data = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode()

        verify_key = VerifyKey(_ED25519_PUBLIC_KEY)
        verify_key.verify(signed_data, sig)
    except BadSignatureError:
        logger.error("License signature verification failed")
        return {
            "mode": "prod",
            "valid": False,
            "days_remaining": 0,
            "expire_at": None,
            "issued_at": None,
            "machine_id": None,
        }
    except Exception as e:
        logger.error("License parse error: %s", e)
        return {
            "mode": "prod",
            "valid": False,
            "days_remaining": 0,
            "expire_at": None,
            "issued_at": None,
            "machine_id": None,
        }

    if not machine_id or payload.get("machine_id") != machine_id:
        logger.error("License machine ID mismatch")
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

    logger.info(
        "License verified (expires: %s)",
        time.strftime("%Y-%m-%d", time.localtime(expire_at)),
    )
    return {
        "mode": "prod",
        "valid": valid,
        "days_remaining": days_remaining,
        "expire_at": expire_at,
        "issued_at": payload.get("issued_at"),
        "machine_id": _mask_machine_id(machine_id),
    }


def verify_license() -> bool:
    return get_license_info()["valid"]
