"""Unit tests for pyprotect.config."""

from __future__ import annotations

from pyprotect.config import ProjectConfig, resolve_value


def test_from_file_missing_returns_defaults(tmp_path):
    cfg = ProjectConfig.from_file(tmp_path / "nope.yaml")
    assert cfg.packages == []
    assert cfg.keep_plain == []
    assert cfg.ed25519_public_key == "license_ed25519.pub"


def test_yaml_roundtrip(tmp_path):
    cfg = ProjectConfig(
        packages=["a", "b"],
        keep_plain=["main.py"],
        ed25519_public_key="keys/pub",
    )
    p = tmp_path / "pyprotect.yaml"
    p.write_text(cfg.to_yaml())
    assert ProjectConfig.from_file(p) == cfg


def test_from_file_empty_yaml(tmp_path):
    p = tmp_path / "pyprotect.yaml"
    p.write_text("")
    assert ProjectConfig.from_file(p).packages == []


def test_resolve_value_passthrough():
    assert resolve_value("plain") == "plain"


def test_resolve_value_env(monkeypatch):
    monkeypatch.setenv("MY_VAR", "hello")
    assert resolve_value("${MY_VAR}") == "hello"


def test_resolve_value_unset_env_returns_literal():
    assert resolve_value("${DEFINITELY_NOT_SET_XYZ_123}") == "${DEFINITELY_NOT_SET_XYZ_123}"
