from __future__ import annotations

from pathlib import Path


def inject_hex(filepath: Path, placeholder: str, key_bytes: bytes) -> bool:
    src = filepath.read_text()
    if placeholder not in src:
        var_name = placeholder.split("=")[0].strip()
        if f'{var_name} = bytes.fromhex(' in src:
            return False
        raise ValueError(f"Placeholder '{placeholder}' not found in {filepath}")
    var_name = placeholder.split("=")[0].strip()
    src = src.replace(placeholder, f'{var_name} = bytes.fromhex("{key_bytes.hex()}")')
    filepath.write_text(src)
    return True
