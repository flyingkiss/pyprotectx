from __future__ import annotations

from pathlib import Path

from nacl.bindings import crypto_secretbox, crypto_secretbox_open
from nacl.utils import random as nacl_random

NONCE_LEN = 24
KEY_LEN = 32


def generate_key() -> bytes:
    return nacl_random(KEY_LEN)


def encrypt_file(py_path: Path, key: bytes) -> Path:
    plaintext = py_path.read_bytes()
    nonce = nacl_random(NONCE_LEN)
    ciphertext = nonce + crypto_secretbox(plaintext, nonce, key)
    enc_path = py_path.with_suffix(".enc")
    enc_path.write_bytes(ciphertext)
    return enc_path


def decrypt_file(enc_path: Path, key: bytes) -> bytes:
    ciphertext = enc_path.read_bytes()
    nonce = ciphertext[:NONCE_LEN]
    enc_data = ciphertext[NONCE_LEN:]
    return crypto_secretbox_open(enc_data, nonce, key)
