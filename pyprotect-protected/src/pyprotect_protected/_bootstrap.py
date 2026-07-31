"""
Import hook for encrypted .enc modules — runtime bootstrap.

This file is injected with a NaCl symmetric key at build time and
should be Cython-compiled to .so before distribution.

Build flow:
  .py -> try Cython -> .so (success)
                     -> encrypt -> .enc (fallback, handled by this hook)

Runtime flow:
  import myapp.foo -> Python finds myapp/foo.so -> normal import
                   -> not found -> this hook finds myapp/foo.enc
                                 -> decrypt -> exec -> done
"""

import importlib
import importlib.abc
import importlib.machinery
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.resolve()
_NONCE_LEN = 24


def _decrypt(ciphertext):
    import nacl.bindings

    _KEY = bytes(32)
    _n = ciphertext[:_NONCE_LEN]
    _c = ciphertext[_NONCE_LEN:]
    return nacl.bindings.crypto_secretbox_open(_c, _n, _KEY)


class _EncryptedLoader(importlib.abc.Loader):
    def __init__(self, enc_path, is_package=False):
        self.enc_path = enc_path
        self.is_package = is_package

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        plaintext = _decrypt(self.enc_path.read_bytes())
        code = compile(plaintext, str(self.enc_path), "exec")
        exec(code, module.__dict__)


class _EncryptedFinder(importlib.abc.MetaPathFinder):

    def __init__(self, project_root: str | Path | None = None):
        if project_root is None:
            project_root = Path(sys.argv[0]).parent.resolve() if sys.argv and sys.argv[0] else Path.cwd()
        self.project_root = Path(project_root)

    def find_spec(self, fullname, path=None, target=None):
        parts = fullname.split(".")

        pkg_dir = self.project_root.joinpath(*parts)
        enc_path = pkg_dir / "__init__.enc"
        if enc_path.is_file():
            loader = _EncryptedLoader(enc_path, is_package=True)
            spec = importlib.machinery.ModuleSpec(
                fullname, loader, is_package=True, origin=str(enc_path)
            )
            spec.submodule_search_locations = [str(pkg_dir)]
            return spec

        if len(parts) > 1:
            parent_dir = self.project_root.joinpath(*parts[:-1])
        else:
            parent_dir = self.project_root
        enc_path = parent_dir / (parts[-1] + ".enc")
        if enc_path.is_file():
            loader = _EncryptedLoader(enc_path)
            return importlib.machinery.ModuleSpec(
                fullname, loader, is_package=False, origin=str(enc_path)
            )

        return None


sys.meta_path.append(_EncryptedFinder())
