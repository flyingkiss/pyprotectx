"""
pyprotect-protected — runtime support for pyprotect-protected Python projects.

Provides:
  - _bootstrap: encrypted .enc module import hook (auto-registered on import)
  - license_verify: Ed25519 license verification

Usage:
  import pyprotect_protected   # auto-registers .enc import hook
  from pyprotect_protected import verify_license
"""

from pyprotect_protected._bootstrap import _EncryptedFinder  # noqa: F401
from pyprotect_protected.license_verify import verify_license, get_license_info  # noqa: F401
