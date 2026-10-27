"""Unit tests for pyprotect.encryptor."""

from __future__ import annotations

import pytest
from nacl.exceptions import CryptoError

from pyprotect.encryptor import KEY_LEN, NONCE_LEN, decrypt_file, encrypt_file, generate_key


def test_generate_key_length():
    assert KEY_LEN == 32
    assert len(generate_key()) == KEY_LEN


def test_encrypt_creates_enc_file_with_nonce_prefix(tmp_path):
    src = tmp_path / "mod.py"
    src.write_bytes(b"print('secret')\n")
    enc = encrypt_file(src, generate_key())
    assert enc == tmp_path / "mod.enc"
    assert len(enc.read_bytes()) > NONCE_LEN == 24


def test_roundtrip(tmp_path):
    src = tmp_path / "mod.py"
    original = b"VALUE = 42\n"
    src.write_bytes(original)
    key = generate_key()
    enc = encrypt_file(src, key)
    assert decrypt_file(enc, key) == original


def test_decrypt_with_wrong_key_raises(tmp_path):
    src = tmp_path / "mod.py"
    src.write_bytes(b"VALUE = 42\n")
    enc = encrypt_file(src, generate_key())
    with pytest.raises(CryptoError):
        decrypt_file(enc, generate_key())
