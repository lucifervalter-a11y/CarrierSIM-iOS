#!/usr/bin/env python3
"""Verify the actual IPA structure and native code; does not run an iPhone."""
from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import stat
import struct
import zipfile
from pathlib import Path

ASSET_HASH = "6de1ea0be81a29c145ef414f24bc21d1dcb8a4eb737b22b1f956e9a6f0c2098b"
APP = "Payload/CarrierSIM.app/"
EXT = APP + "PlugIns/CarrierSIMTunnel.appex/"
VPN_KEY = "com.apple.developer.networking.networkextension"


def macho(data: bytes, expect_vpn: bool) -> dict:
    magic, cpu, subtype, filetype, count, command_size, flags, reserved = struct.unpack_from("<8I", data)
    assert magic == 0xFEEDFACF and cpu == 0x0100000C and filetype == 2, "Native arm64 executable required"
    assert 0 < count < 1000 and command_size + 32 <= len(data), "Invalid load commands"
    offset, dependencies, platform, signature, section_names = 32, [], None, None, []
    for _ in range(count):
        command, size = struct.unpack_from("<2I", data, offset)
        assert size >= 8 and offset + size <= 32 + command_size
        if command in (0xC, 0x18, 0x80000018, 0x8000001F):
            start = offset + struct.unpack_from("<I", data, offset + 8)[0]
            end = data.index(0, start, offset + size)
            name = data[start:end].decode()
            assert name.startswith(("/System/Library/", "/usr/lib/")), f"Unbundled host dependency: {name}"
            dependencies.append(name)
        elif command == 0x32:
            platform = struct.unpack_from("<I", data, offset + 8)[0]
        elif command == 0x25:
            platform = 2
        elif command == 0x1D:
            start, length = struct.unpack_from("<2I", data, offset + 8)
            signature = data[start:start + length]
        elif command == 0x19:
            nsections = struct.unpack_from("<I", data, offset + 64)[0]
            for index in range(nsections):
                section_names.append(data[offset + 72 + 80 * index:offset + 88 + 80 * index].split(b"\0")[0].decode())
        offset += size
    assert offset == 32 + command_size and platform == 2, "Must target an iOS device, not simulator/macOS"
    assert "__objc_classlist" in section_names, "Objective-C runtime class registration missing"
    assert signature, "Ad-hoc signature/entitlement template missing"
    sig_magic, total, entries = struct.unpack_from(">3I", signature)
    assert sig_magic == 0xFADE0CC0 and total <= len(signature)
    entitlements = {}
    for index in range(entries):
        kind, start = struct.unpack_from(">2I", signature, 12 + index * 8)
        if kind == 5:
            entry_magic, length = struct.unpack_from(">2I", signature, start)
            assert entry_magic == 0xFADE7171
            entitlements = plistlib.loads(signature[start + 8:start + length])
    if expect_vpn:
        assert entitlements.get(VPN_KEY) == ["packet-tunnel-provider"], "VPN entitlement template missing"
    else:
        assert VPN_KEY not in entitlements, "External-VPN variant must not request Network Extension"
    assert not entitlements.get("get-task-allow"), "Unexpected debugger entitlement"
    return {"architecture": "arm64", "platform": "iOS device", "bytes": len(data), "dependencies": dependencies, "entitlements": entitlements}


def verify(path: Path, external: bool) -> dict:
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        entries = archive.infolist()
        assert len({item.filename for item in entries}) == len(entries), "Duplicate IPA entries"
        assert all(item.filename.startswith(APP) and "/../" not in item.filename for item in entries)
        names = set(archive.namelist())
        info = plistlib.loads(archive.read(APP + "Info.plist"))
        assert info["CFBundleExecutable"] == "CarrierSIM"
        assert info["CFBundleIdentifier"] == "com.tema.CarrierSIM"
        assert info["MinimumOSVersion"] == "26.0"
        assert info["CFBundleShortVersionString"] == "1.1.0"
        assert {"_remoted._tcp", "_remotepairing._tcp"}.issubset(info["NSBonjourServices"])
        assert not info.get("UIFileSharingEnabled"), "Private recovery data must not appear in Documents sharing"
        assert "_remotepairing-pairable-host._tcp" in info["NSBonjourServices"]
        assert "audio" in info.get("UIBackgroundModes", []), "Pairing keep-alive declaration missing"
        assert any("carriersim" in item.get("CFBundleURLSchemes", []) for item in info["CFBundleURLTypes"])
        assert hashlib.sha256(archive.read(APP + "assets.zip")).hexdigest() == ASSET_HASH
        for filename, size in (("AppIcon60x60@2x.png", 120), ("AppIcon60x60@3x.png", 180)):
            image = archive.read(APP + filename)
            assert image[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack_from(">2I", image, 16) == (size, size)
        assert any(name.startswith(APP + "Licenses/") for name in names)
        binary = archive.read(APP + "CarrierSIM")
        assert b"cs_install_ipa" in binary, "LAN installation export missing"
        assert b"CSLANBrowserViewController" in binary, "LAN browser missing"
        executable = archive.read(APP + "CarrierSIM")
        assert archive.getinfo(APP + "CarrierSIM").external_attr >> 16 & stat.S_IXUSR
        assert b"cs_execute" in executable and b"al_pairing_cancel_host" in executable, "Carrier or cancellation implementation missing"
        result = {"app": macho(executable, not external)}
        if external:
            assert not any(name.startswith(APP + "PlugIns/") for name in names)
        else:
            extinfo = plistlib.loads(archive.read(EXT + "Info.plist"))
            assert extinfo["CFBundleIdentifier"] == info["CFBundleIdentifier"] + ".Tunnel"
            assert extinfo["CFBundleVersion"] == info["CFBundleVersion"]
            assert extinfo["CFBundleShortVersionString"] == info["CFBundleShortVersionString"]
            assert extinfo["NSExtension"]["NSExtensionPrincipalClass"] == "PacketTunnelProvider"
            assert extinfo["NSExtension"]["NSExtensionPointIdentifier"] == "com.apple.networkextension.packet-tunnel"
            extension = archive.read(EXT + "CarrierSIMTunnel")
            assert b"PacketTunnelProvider" in extension
            result["extension"] = macho(extension, True)
        result.update(filename=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                      ipa_bytes=path.stat().st_size, external_vpn=external,
                      physical_device_tested=False)
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--external-vpn", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify(args.ipa, args.external_vpn), ensure_ascii=False, indent=2))
