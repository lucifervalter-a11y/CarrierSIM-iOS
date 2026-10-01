#!/usr/bin/env python3
"""Collect exact license texts for the Cargo graph resolved for the iOS target.

Usage:
  cargo metadata --locked --offline --filter-platform aarch64-apple-ios \
    --format-version 1 > /tmp/carriersim-cargo-metadata.json
  python3 scripts/collect-licenses.py /tmp/carriersim-cargo-metadata.json

Includes source/build dependencies as a conservative superset of shipped code.
No network access is performed. Standard SPDX declarations without a packaged
license file are identified explicitly; they are not presented as copied files.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__)
    project = Path(__file__).resolve().parents[1]
    metadata = json.loads(Path(sys.argv[1]).read_text())
    output = Path(sys.argv[2]) if len(sys.argv) == 3 else project / "Licenses/THIRD-PARTY-RUST.txt"
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    pending = [metadata["resolve"]["root"]]
    reached: set[str] = set()
    while pending:
        key = pending.pop()
        if key in reached:
            continue
        reached.add(key)
        pending.extend(item["pkg"] for item in nodes[key]["deps"])
    packages = sorted(
        (item for item in metadata["packages"] if item["id"] in reached and item["name"] != "airlift_ffi"),
        key=lambda item: (item["name"], item["version"]),
    )
    documents: dict[str, str] = {}
    mapping = []
    missing = []
    standard_mit = project / "Licenses/SPDX-MIT.txt"
    idevice_notice = project / "Licenses/idevice-license-notice.txt"

    def add_document(path: Path) -> str | None:
        if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            return None
        raw = path.read_bytes()
        if b"\0" in raw[:4096]:
            return None
        text = raw.decode("utf-8", errors="replace")
        digest = hashlib.sha256(raw).hexdigest()[:16]
        documents.setdefault(digest, text)
        return digest

    for package in packages:
        directory = Path(package["manifest_path"]).parent
        docs = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or not re.match(r"^(LICEN[CS]E|COPYING|NOTICE)(?:$|[-_.])", path.name, re.I):
                continue
            if path.suffix.lower() in {".c", ".cc", ".cpp", ".h", ".rs", ".py", ".js", ".toml", ".json"}:
                continue
            digest = add_document(path)
            if digest:
                docs.append((str(path.relative_to(directory)), digest))
        explicit = package.get("license_file")
        if explicit:
            path = Path(explicit)
            if not path.is_absolute():
                path = directory / path
            digest = add_document(path)
            if digest and not any(item[1] == digest for item in docs):
                docs.append(("Cargo license-file: " + path.name, digest))
        license_name = package.get("license") or "See the upstream project declaration below."
        notice = None
        if package["name"] in {"idevice", "idevice-ffi"}:
            digest = add_document(idevice_notice)
            if digest:
                docs.append(("Upstream README/Cargo license declaration and attribution", digest))
            license_name = "MIT (upstream project README; idevice Cargo metadata)"
        if not docs:
            missing.append(package["name"] + " " + package["version"])
            notice = "The published package supplies an SPDX license declaration but no standalone license text."
            for readme in (directory / "README.md", directory / "Readme.md"):
                if not readme.exists():
                    continue
                text = readme.read_text(errors="replace")
                match = re.search(r"(?im)^#{1,4}\s+Licen[cs](?:e|ing)\s*\n", text)
                if match:
                    section = text[match.start():].split("\n## ", 1)[0].strip()
                    digest = hashlib.sha256(section.encode()).hexdigest()[:16]
                    documents.setdefault(digest, section)
                    docs.append(("Upstream README license section", digest))
            if "MIT" in license_name:
                digest = add_document(standard_mit)
                if digest:
                    docs.append(("Standard SPDX MIT terms, selected by the upstream declaration", digest))
        mapping.append({
            "name": package["name"], "version": package["version"],
            "license": license_name, "repository": package.get("repository"),
            "authors": package.get("authors", []), "documents": docs, "note": notice,
        })

    intro = [
        "CarrierSIM iOS — third-party Rust notices", "",
        "Generated from cargo metadata --locked --offline --filter-platform aarch64-apple-ios.",
        "This is the resolved source/build dependency graph; it conservatively includes build-time tools.",
        "Package versions and SPDX declarations come from their Cargo metadata.",
        "License document bodies below are copied from the actual package source unless explicitly marked as a declaration or standard license terms.",
        "Repeated identical license texts are stored once and referenced by document ID.",
        "CarrierSIM changes and the AirCard/AirLift and LocalDevVPN notices are supplied separately.",
        "The source distribution retains original license headers in source files.",
        "", "PACKAGE INDEX", "=" * 72, "",
    ]
    for package in mapping:
        intro += [f"{package['name']} {package['version']}", "License: " + package["license"]]
        if package["authors"]:
            intro.append("Authors: " + "; ".join(package["authors"]))
        if package["repository"]:
            intro.append("Source: " + package["repository"])
        if package["note"]:
            intro.append(package["note"])
        for name, digest in package["documents"]:
            intro.append(f"  Document {digest}: {name}")
        intro.append("")
    intro += ["LICENSE DOCUMENTS", "=" * 72, ""]
    for digest, body in sorted(documents.items()):
        intro.extend([f"Document {digest}", "-" * 72, body.rstrip(), ""])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(intro), encoding="utf-8")
    print(f"Saved {output.name}: {len(mapping)} packages, {len(documents)} distinct license documents, {output.stat().st_size} bytes")
    if missing:
        print("Explicit declaration-only packages: " + ", ".join(missing))


if __name__ == "__main__":
    main()
