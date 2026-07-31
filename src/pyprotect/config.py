from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ProjectConfig:
    packages: list[str] = field(default_factory=list)
    keep_plain: list[str] = field(default_factory=list)
    ed25519_public_key: str = "license_ed25519.pub"

    @classmethod
    def from_file(cls, path: Path) -> ProjectConfig:
        if not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text()) or {}
        return cls(
            packages=data.get("packages", []),
            keep_plain=data.get("keep_plain", []),
            ed25519_public_key=data.get("ed25519_public_key", "license_ed25519.pub"),
        )

    def to_yaml(self) -> str:
        return yaml.dump(
            {
                "packages": self.packages,
                "keep_plain": self.keep_plain,
                "ed25519_public_key": self.ed25519_public_key,
            },
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )


def resolve_value(value: str) -> str:
    if value.startswith("${") and value.endswith("}"):
        env_var = value[2:-1]
        return os.environ.get(env_var, value)
    return value
