"""Unit tests for pyprotect.key_inject."""

from __future__ import annotations

import pytest

from pyprotect.key_inject import inject_hex

PLACEHOLDER = "_KEY = bytes(32)"


def test_inject_replaces_placeholder(tmp_path):
    f = tmp_path / "mod.py"
    f.write_text(f"{PLACEHOLDER}\n")
    key = bytes(range(32))
    assert inject_hex(f, PLACEHOLDER, key) is True
    content = f.read_text()
    assert f'bytes.fromhex("{key.hex()}")' in content
    assert PLACEHOLDER not in content


def test_inject_is_idempotent(tmp_path):
    f = tmp_path / "mod.py"
    f.write_text(f"{PLACEHOLDER}\n")
    assert inject_hex(f, PLACEHOLDER, b"\x01" * 32) is True
    assert inject_hex(f, PLACEHOLDER, b"\x02" * 32) is False


def test_missing_placeholder_raises(tmp_path):
    f = tmp_path / "mod.py"
    f.write_text("x = 1\n")
    with pytest.raises(ValueError):
        inject_hex(f, PLACEHOLDER, b"\x00" * 32)
