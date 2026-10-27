"""Tests for `pyprotect runtime-patch` and `build --nacl-key` key alignment."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from conftest import ROOT
from pyprotect.cli import main as cli_main
from pyprotect.encryptor import decrypt_file

RUNTIME_SRC = ROOT / "pyprotect-protected" / "src" / "pyprotect_protected"
HEX64 = re.compile(r'bytes\.fromhex\("([0-9a-f]{64})"\)')


def _patched_target(tmp_path: Path) -> Path:
    dst = tmp_path / "pyprotect_protected"
    shutil.copytree(RUNTIME_SRC, dst)
    return dst


def _extract_hex(text: str) -> str:
    m = HEX64.search(text)
    assert m, "no injected 64-hex key found"
    return m.group(1)


# ── runtime-patch ─────────────────────────────────────────────


def test_patch_copy_with_explicit_keys(runner, keypair, tmp_path):
    target = _patched_target(tmp_path)
    out = tmp_path / "patched"
    nacl_hex = "ab" * 32
    r = runner.invoke(
        cli_main,
        [
            "runtime-patch",
            "--pub-key", str(keypair["public"]),
            "--nacl-key", nacl_hex,
            "--target", str(target),
            "--out", str(out),
        ],
    )
    assert r.exit_code == 0, r.output
    assert _extract_hex((out / "_bootstrap.py").read_text()) == nacl_hex
    assert _extract_hex((out / "license_verify.py").read_text()) == keypair["public"].read_bytes().hex()
    # original copy untouched
    assert "bytes(32)" in (target / "_bootstrap.py").read_text()


def test_patch_generates_random_key_when_omitted(runner, keypair, tmp_path):
    target = _patched_target(tmp_path)
    r = runner.invoke(
        cli_main,
        ["runtime-patch", "--pub-key", str(keypair["public"]), "--target", str(target)],
    )
    assert r.exit_code == 0, r.output
    key_hex = _extract_hex((target / "_bootstrap.py").read_text())
    assert key_hex != "00" * 32


def test_patch_in_place_and_idempotent_second_run(runner, keypair, tmp_path):
    target = _patched_target(tmp_path)
    nacl_hex = "cd" * 32
    args = [
        "runtime-patch",
        "--pub-key", str(keypair["public"]),
        "--nacl-key", nacl_hex,
        "--target", str(target),
    ]
    assert runner.invoke(cli_main, args).exit_code == 0
    r2 = runner.invoke(cli_main, args)
    assert r2.exit_code == 0, r2.output
    assert "already patched" in r2.output
    # original key preserved (not overwritten)
    assert _extract_hex((target / "_bootstrap.py").read_text()) == nacl_hex


def test_patch_rejects_bad_hex(runner, keypair, tmp_path):
    target = _patched_target(tmp_path)
    r = runner.invoke(
        cli_main,
        [
            "runtime-patch",
            "--pub-key", str(keypair["public"]),
            "--nacl-key", "xyz",
            "--target", str(target),
        ],
    )
    assert r.exit_code != 0


def test_patch_rejects_missing_target(runner, keypair, tmp_path):
    r = runner.invoke(
        cli_main,
        [
            "runtime-patch",
            "--pub-key", str(keypair["public"]),
            "--target", str(tmp_path / "nowhere"),
        ],
    )
    assert r.exit_code != 0


# ── build --nacl-key alignment ────────────────────────────────


def test_build_with_fixed_key_produces_decryptable_enc(demo_project, runner, keypair):
    nacl_hex = "ef" * 32
    runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg", "-k", "main.py"])
    r = runner.invoke(
        cli_main,
        [
            "build", str(demo_project),
            "--skip-cython",
            "--pub-key", str(keypair["public"]),
            "--nacl-key", nacl_hex,
        ],
    )
    assert r.exit_code == 0, r.output

    enc = demo_project / "mypkg" / "hello.enc"
    assert enc.is_file()
    plaintext = decrypt_file(enc, bytes.fromhex(nacl_hex))
    assert b"hello from mypkg" in plaintext


def test_build_rejects_bad_nacl_key(demo_project, runner):
    runner.invoke(cli_main, ["init", str(demo_project), "-p", "mypkg"])
    r = runner.invoke(cli_main, ["build", str(demo_project), "--skip-cython", "--nacl-key", "nothex"])
    assert r.exit_code == 1
    assert "64 hex chars" in r.output
