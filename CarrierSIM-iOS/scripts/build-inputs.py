#!/usr/bin/env python3
"""Detect source edits during a native build so an IPA cannot be labeled final early."""
import hashlib
import json
import sys
from pathlib import Path


def capture(root: Path) -> dict[str, str]:
    generated = {
        "rust-core/vendor/idevice-ffi/idevice.h",
        "rust-core/vendor/cpp/include/idevice.h",
    }
    inputs = [root / "rust-core/Cargo.toml", root / "rust-core/Cargo.lock"]
    for relative in ("App", "Tunnel", "Resources", "Licenses", "scripts", "rust-core/src", "rust-core/include", "rust-core/vendor"):
        directory = root / relative
        if directory.is_dir():
            inputs.extend(path for path in directory.rglob("*") if path.is_file())
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(set(inputs))
        if path.is_file()
        and path.relative_to(root).as_posix() not in generated
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }


mode, root_name, record_name = sys.argv[1:]
root = Path(root_name).resolve()
record = Path(record_name)
current = capture(root)
if mode == "record":
    record.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
elif mode == "verify":
    previous = json.loads(record.read_text())
    changed = sorted(name for name in set(previous) | set(current) if previous.get(name) != current.get(name))
    if changed:
        raise SystemExit("Sources changed while building; rebuild before delivery:\n" + "\n".join(changed))
    print(f"Verified unchanged build inputs: {len(current)} files")
else:
    raise SystemExit("Expected record or verify")
