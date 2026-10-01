#!/usr/bin/env bash
# Native macOS build: full Xcode, Rust (rustup), and Python 3 are required.
# Run: ./scripts/build-macos.sh
# Set CARRIERSIM_EXTERNAL_VPN=0 to omit the separate external-VPN IPA.
# Output is ad-hoc signed; Apple identities/profiles are still needed to install.
set -euo pipefail

[[ "$(uname -s)" == Darwin ]] || { printf 'This script requires macOS and full Xcode.\n' >&2; exit 1; }
for command_name in xcrun codesign python3 cargo rustc rustup; do
  command -v "$command_name" >/dev/null || { printf 'Missing build tool: %s\n' "$command_name" >&2; exit 1; }
done

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${CARRIERSIM_BUILD_ROOT:-$PROJECT_ROOT/build}"
export SDKROOT="${SDKROOT:-$(xcrun --sdk iphoneos --show-sdk-path)}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"
export CARGO_TARGET_DIR="$BUILD_ROOT/rust-target"
export CARGO_PROFILE_RELEASE_LTO=false
IOS_CLANG="$(xcrun --sdk iphoneos --find clang)"
IOS_NM="$(xcrun --sdk iphoneos --find nm)"
export CC_aarch64_apple_ios="$IOS_CLANG"
export CXX_aarch64_apple_ios="$(xcrun --sdk iphoneos --find clang++)"
export AR_aarch64_apple_ios="$(xcrun --sdk iphoneos --find ar)"
export CARGO_TARGET_AARCH64_APPLE_IOS_LINKER="$IOS_CLANG"
[[ -d "$SDKROOT/System/Library/Frameworks/UIKit.framework" ]] || {
  printf 'SDKROOT must be an iPhoneOS SDK. Select full Xcode with xcode-select.\n' >&2; exit 1;
}

mkdir -p "$BUILD_ROOT"
python3 "$PROJECT_ROOT/scripts/build-inputs.py" record "$PROJECT_ROOT" "$BUILD_ROOT/build-inputs.json"
if [[ "${CARRIERSIM_SKIP_RUST:-0}" != 1 ]]; then
  rustup target add aarch64-apple-ios
  cargo build --manifest-path "$PROJECT_ROOT/rust-core/Cargo.toml" --locked --release --target aarch64-apple-ios
fi
RUST_LIBRARY="$CARGO_TARGET_DIR/aarch64-apple-ios/release/libairlift_ffi.a"
[[ -s "$RUST_LIBRARY" ]] || { printf 'Rust static library is missing.\n' >&2; exit 1; }

STAGE_ROOT="$(mktemp -d "$BUILD_ROOT/package-macos.XXXXXX")"
trap 'rm -rf -- "$STAGE_ROOT"' EXIT
APP_BUNDLE="$STAGE_ROOT/Payload/CarrierSIM.app"
EXTENSION_BUNDLE="$APP_BUNDLE/PlugIns/CarrierSIMTunnel.appex"
mkdir -p "$APP_BUNDLE" "$EXTENSION_BUNDLE"
COMMON_FLAGS=(
  -target "arm64-apple-ios$IPHONEOS_DEPLOYMENT_TARGET" -isysroot "$SDKROOT"
  -fobjc-arc -fblocks -Os -g0 -Wno-deprecated-declarations
  -I "$PROJECT_ROOT/rust-core/include" -I "$PROJECT_ROOT/App" -Wl,-dead_strip
)
shopt -s nullglob
APP_SOURCES=("$PROJECT_ROOT"/App/*.m)
TUNNEL_SOURCES=("$PROJECT_ROOT"/Tunnel/*.m)
[[ ${#APP_SOURCES[@]} -gt 0 && ${#TUNNEL_SOURCES[@]} -gt 0 ]] || {
  printf 'Application or VPN extension sources are missing.\n' >&2; exit 1;
}

"$IOS_CLANG" "${COMMON_FLAGS[@]}" "${APP_SOURCES[@]}" "$RUST_LIBRARY" \
  -framework Foundation -framework UIKit -framework Security -framework CoreFoundation \
  -framework Network -framework NetworkExtension -framework UserNotifications \
  -framework AVFoundation -framework UniformTypeIdentifiers -framework SystemConfiguration \
  -lc++ -lz -lsqlite3 -lresolv -liconv \
  -Wl,-u,_ALGetGrappaToken -Wl,-exported_symbol,_ALGetGrappaToken \
  -Wl,-exported_symbol,_cs_execute -Wl,-exported_symbol,_cs_install_ipa -Wl,-exported_symbol,_al_pairing_cancel_host \
  -o "$APP_BUNDLE/CarrierSIM"
"$IOS_CLANG" "${COMMON_FLAGS[@]}" -fapplication-extension "${TUNNEL_SOURCES[@]}" \
  -framework Foundation -framework NetworkExtension -framework Network \
  -Wl,-e,_NSExtensionMain -o "$EXTENSION_BUNDLE/CarrierSIMTunnel"

cp "$PROJECT_ROOT/App/Info.plist" "$APP_BUNDLE/Info.plist"
cp "$PROJECT_ROOT/Tunnel/Info.plist" "$EXTENSION_BUNDLE/Info.plist"
if [[ -d "$PROJECT_ROOT/Resources" ]]; then cp -R "$PROJECT_ROOT/Resources/." "$APP_BUNDLE/"; fi
if [[ -d "$PROJECT_ROOT/Licenses" ]]; then cp -R "$PROJECT_ROOT/Licenses" "$APP_BUNDLE/Licenses"; fi
export PROJECT_ROOT BUILD_ROOT STAGE_ROOT APP_BUNDLE EXTENSION_BUNDLE
python3 - <<'PY'
import os, plistlib, struct
from pathlib import Path

app = Path(os.environ['APP_BUNDLE'])
extension = Path(os.environ['EXTENSION_BUNDLE'])
app_metadata = plistlib.loads((app / 'Info.plist').read_bytes())
for bundle, identifier, executable, kind in (
    (app, 'com.tema.CarrierSIM', 'CarrierSIM', 'APPL'),
    (extension, 'com.tema.CarrierSIM.Tunnel', 'CarrierSIMTunnel', 'XPC!'),
):
    path = bundle / 'Info.plist'
    data = plistlib.loads(path.read_bytes())
    data.update(CFBundleIdentifier=identifier, CFBundleExecutable=executable,
                CFBundlePackageType=kind, CFBundleSupportedPlatforms=['iPhoneOS'],
                CFBundleInfoDictionaryVersion='6.0',
                CFBundleVersion=app_metadata.get('CFBundleVersion', '1'),
                CFBundleShortVersionString=app_metadata.get('CFBundleShortVersionString', '1.0.0'),
                UIDeviceFamily=app_metadata.get('UIDeviceFamily', [1]))
    data.setdefault('MinimumOSVersion', '26.0')
    if bundle == extension:
        data['NSExtension']['NSExtensionPrincipalClass'] = 'PacketTunnelProvider'
    path.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_BINARY))
    binary = bundle / executable
    magic, cpu, subtype, filetype = struct.unpack_from('<4I', binary.read_bytes())
    assert (magic, cpu, filetype) == (0xFEEDFACF, 0x0100000C, 2), f'{executable}: expected arm64 MH_EXECUTE'
    binary.chmod(0o755)
PY
"$IOS_NM" -gU "$APP_BUNDLE/CarrierSIM" | python3 -c '
import sys
symbols = {line.split()[-1] for line in sys.stdin if line.split()}
required = {"_ALGetGrappaToken", "_cs_execute", "_cs_install_ipa", "_al_pairing_cancel_host"}
assert required <= symbols, "Missing bridge exports: " + ", ".join(sorted(required - symbols))
'

# Sign nested code first, then seal the complete containing app and its resources.
codesign --force --sign - --timestamp=none --generate-entitlement-der \
  --entitlements "$PROJECT_ROOT/Tunnel/CarrierSIMTunnel.entitlements" "$EXTENSION_BUNDLE"
codesign --force --sign - --timestamp=none --generate-entitlement-der \
  --entitlements "$PROJECT_ROOT/App/CarrierSIM.entitlements" "$APP_BUNDLE"
codesign --verify --strict --deep "$APP_BUNDLE"
python3 "$PROJECT_ROOT/scripts/build-inputs.py" verify "$PROJECT_ROOT" "$BUILD_ROOT/build-inputs.json"

export CARRIERSIM_EXTERNAL_VPN="${CARRIERSIM_EXTERNAL_VPN:-1}"
python3 - <<'PY'
import hashlib, json, os, plistlib, shutil, stat, subprocess, zipfile
from pathlib import Path

stage = Path(os.environ['STAGE_ROOT'])
build = Path(os.environ['BUILD_ROOT'])
app = Path(os.environ['APP_BUNDLE'])
artifacts = {}

def package(source, filename, with_extension):
    destination = build / filename
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for item in sorted((source / 'Payload').rglob('*')):
            if item.is_file():
                archive.write(item, item.relative_to(source).as_posix())
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None, 'IPA ZIP integrity check failed'
        names = archive.namelist()
        executables = ['Payload/CarrierSIM.app/CarrierSIM']
        if with_extension:
            executables.append('Payload/CarrierSIM.app/PlugIns/CarrierSIMTunnel.appex/CarrierSIMTunnel')
        else:
            assert not any('/PlugIns/' in name for name in names), 'Unexpected embedded VPN extension'
        for name in executables:
            assert (archive.getinfo(name).external_attr >> 16) & stat.S_IXUSR, 'Missing executable permission'
    artifacts[filename] = hashlib.sha256(destination.read_bytes()).hexdigest()
    print(f'IPA: {destination}\nSHA256: {artifacts[filename]}')

package(stage, 'CarrierSIM-iOS-unsigned.ipa', True)
if os.environ['CARRIERSIM_EXTERNAL_VPN'] != '0':
    fallback_stage = stage / 'external-vpn'
    fallback_app = fallback_stage / 'Payload' / 'CarrierSIM.app'
    shutil.copytree(app, fallback_app)
    shutil.rmtree(fallback_app / 'PlugIns')
    shutil.rmtree(fallback_app / '_CodeSignature', ignore_errors=True)
    entitlements = stage / 'empty.entitlements'
    entitlements.write_bytes(plistlib.dumps({}))
    subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none',
                    '--generate-entitlement-der', '--entitlements', str(entitlements), str(fallback_app)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(fallback_app)], check=True)
    embedded = subprocess.check_output(['codesign', '--display', '--entitlements', ':-', str(fallback_app)], stderr=subprocess.DEVNULL)
    assert not plistlib.loads(embedded), 'External-VPN app must have empty entitlements'
    package(fallback_stage, 'CarrierSIM-iOS-external-vpn.ipa', False)

manifest = {
    'platform': 'iOS', 'architecture': 'arm64', 'apple_signed': False,
    'compiler': subprocess.check_output(['xcrun', '--sdk', 'iphoneos', 'clang', '--version'], text=True).splitlines()[0],
    'rust': subprocess.check_output(['rustc', '--version'], text=True).strip(),
    'sources': json.loads((build / 'build-inputs.json').read_text()), 'artifacts': artifacts,
}
(build / 'CarrierSIM-build-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
print('Ad-hoc build only: re-sign with an Apple identity and provisioning profiles before installation.')
print('The integrated-VPN IPA needs Network Extension support for both the app and its extension.')
PY
