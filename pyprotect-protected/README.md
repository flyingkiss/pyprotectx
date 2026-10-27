# pyprotectx-protected

Runtime support package for [pyprotectx](https://pypi.org/project/pyprotectx/) —
encrypted module loader (`.enc` import hook) + Ed25519 license verification.

This is the **client-side** dependency: lightweight, only requires `pynacl`.

## ⚠️ Vendor patch required

The wheel on PyPI ships with **placeholder keys** — out of the box it cannot
decrypt `.enc` files or verify real licenses. Vendors must inject their own
keys with `pyprotect runtime-patch` (see the pyprotectx documentation) and
distribute the patched build to their customers via a private channel.

```bash
pyprotect runtime-patch --pub-key keys/license_ed25519.pub --nacl-key <hex> --out patched/
```

```python
import pyprotect_protected              # registers the .enc import hook
from pyprotect_protected import verify_license

if not verify_license():
    sys.exit(1)
```

Environment variables:

| Variable | Description |
|----------|-------------|
| `LICENSE_FILE` | Path to the `.lic` license file (required in production) |
| `LICENSE_MACHINE_ID` | Machine identifier for license binding |
| `PYPROTECT_ALLOW_DEV` | Set to `1` to allow running without a license (development only) |

Verification is **fail-closed** by default: a missing, invalid, expired, or
wrong-machine license blocks execution.

See the [pyprotectx](https://pypi.org/project/pyprotectx/) documentation for
the full workflow (build tool, key management, license generation).

## License

MIT
