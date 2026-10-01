#!/usr/bin/env bash
# Build native arm64 iOS executables with LLVM on Linux, then package an IPA.
# The resulting archive still needs an Apple signing identity/provisioning profile
# before installation. Embedded ad-hoc entitlements are a re-signing template.
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_ROOT="${CARRIERSIM_TOOLCHAIN:-$PROJECT_ROOT/../toolchain}"
LLVM_ROOT="${LLVM_ROOT:-$TOOLCHAIN_ROOT/llvm/usr/lib/llvm-20}"
LLVM_BIN="${LLVM_BIN:-$LLVM_ROOT/bin}"
export SDKROOT="${SDKROOT:-$TOOLCHAIN_ROOT/sdks/iPhoneOS16.5.sdk}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"
BUILD_ROOT="${CARRIERSIM_BUILD_ROOT:-$PROJECT_ROOT/build}"
export CARGO_TARGET_DIR="$BUILD_ROOT/rust-target"
# LLVM ThinLTO cross-codegen can produce empty Mach-O objects in recent Rust
# releases. Ordinary release optimization plus ld64 dead stripping is reliable.
export CARGO_PROFILE_RELEASE_LTO=false

if [[ -d "$TOOLCHAIN_ROOT/cargo" && -d "$TOOLCHAIN_ROOT/rustup" ]]; then
  export CARGO_HOME="${CARGO_HOME:-$TOOLCHAIN_ROOT/cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$TOOLCHAIN_ROOT/rustup}"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
export PATH="$LLVM_BIN:$TOOLCHAIN_ROOT/bin:$PATH"
if [[ -d "$TOOLCHAIN_ROOT/llvm/usr/lib/x86_64-linux-gnu" ]]; then
  export LD_LIBRARY_PATH="$TOOLCHAIN_ROOT/llvm/usr/lib/x86_64-linux-gnu:$LLVM_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

for command_name in clang ld64.lld llvm-ar llvm-nm python3 cargo ldid; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing build tool: %s. Configure LLVM_BIN and Rust PATH.\n' "$command_name" >&2
    exit 1
  }
done
[[ -f "$SDKROOT/SDKSettings.json" || -f "$SDKROOT/SDKSettings.plist" ]] || {
  printf 'Set SDKROOT to an extracted iPhoneOS SDK.\n' >&2
  exit 1
}

export CC_aarch64_apple_ios="$(command -v clang)"
export CXX_aarch64_apple_ios="$(command -v clang++)"
export AR_aarch64_apple_ios="$(command -v llvm-ar)"
export CARGO_TARGET_AARCH64_APPLE_IOS_LINKER="$PROJECT_ROOT/scripts/ios-linker.sh"

mkdir -p "$BUILD_ROOT"
python3 "$PROJECT_ROOT/scripts/build-inputs.py" record "$PROJECT_ROOT" "$BUILD_ROOT/build-inputs.json"
RUST_LIBRARY="$CARGO_TARGET_DIR/aarch64-apple-ios/release/libairlift_ffi.a"
if [[ "${CARRIERSIM_SKIP_RUST:-0}" != 1 ]]; then
  cargo build --manifest-path "$PROJECT_ROOT/rust-core/Cargo.toml" \
    --locked --release --target aarch64-apple-ios
fi
[[ -f "$RUST_LIBRARY" ]] || { printf 'Rust static library is missing.\n' >&2; exit 1; }

STAGE_ROOT="$(mktemp -d "$BUILD_ROOT/package.XXXXXX")"
trap 'rm -rf -- "$STAGE_ROOT"' EXIT
APP_BUNDLE="$STAGE_ROOT/Payload/CarrierSIM.app"
EXTENSION_BUNDLE="$APP_BUNDLE/PlugIns/CarrierSIMTunnel.appex"
mkdir -p "$APP_BUNDLE" "$EXTENSION_BUNDLE"

COMMON_FLAGS=(
  -target "arm64-apple-ios$IPHONEOS_DEPLOYMENT_TARGET"
  -isysroot "$SDKROOT"
  -fobjc-arc -fblocks -Os -g0
  -fuse-ld="$(command -v ld64.lld)" -mlinker-version=1000
  -Wno-deprecated-declarations
  -I "$PROJECT_ROOT/rust-core/include" -I "$PROJECT_ROOT/App"
  -Wl,-dead_strip -Wl,-no_adhoc_codesign
)
APP_FRAMEWORKS=(
  -framework Foundation -framework UIKit -framework Security
  -framework CoreFoundation -framework Network -framework NetworkExtension
  -framework UserNotifications -framework AVFoundation
  -framework UniformTypeIdentifiers -framework SystemConfiguration
)
shopt -s nullglob
APP_SOURCES=("$PROJECT_ROOT"/App/*.m)
TUNNEL_SOURCES=("$PROJECT_ROOT"/Tunnel/*.m)
[[ ${#APP_SOURCES[@]} -gt 0 && ${#TUNNEL_SOURCES[@]} -gt 0 ]] || {
  printf 'Application or VPN extension sources are missing.\n' >&2
  exit 1
}

clang "${COMMON_FLAGS[@]}" "${APP_SOURCES[@]}" "$RUST_LIBRARY" \
  "${APP_FRAMEWORKS[@]}" -lc++ -lz -lsqlite3 -lresolv -liconv \
  -Wl,-u,_ALGetGrappaToken -Wl,-exported_symbol,_ALGetGrappaToken \
  -Wl,-exported_symbol,_cs_execute -Wl,-exported_symbol,_cs_install_ipa -Wl,-exported_symbol,_cs_developer_mode -Wl,-exported_symbol,_cs_sign_self -Wl,-exported_symbol,_al_pairing_cancel_host \
  -o "$APP_BUNDLE/CarrierSIM"

# Foundation supplies the extension entry point. No UIApplicationMain is used.
clang "${COMMON_FLAGS[@]}" -fapplication-extension \
  "${TUNNEL_SOURCES[@]}" \
  -framework Foundation -framework NetworkExtension -framework Network \
  -Wl,-e,_NSExtensionMain \
  -o "$EXTENSION_BUNDLE/CarrierSIMTunnel"

cp "$PROJECT_ROOT/App/Info.plist" "$APP_BUNDLE/Info.plist"
cp "$PROJECT_ROOT/Tunnel/Info.plist" "$EXTENSION_BUNDLE/Info.plist"
if [[ -d "$PROJECT_ROOT/Resources" ]]; then
  cp -a "$PROJECT_ROOT/Resources/." "$APP_BUNDLE/"
fi
if [[ -d "$PROJECT_ROOT/Licenses" ]]; then
  cp -a "$PROJECT_ROOT/Licenses" "$APP_BUNDLE/Licenses"
fi

export APP_BUNDLE EXTENSION_BUNDLE
python3 - <<'PY'
import os, plistlib
from pathlib import Path

app = Path(os.environ['APP_BUNDLE'])
extension = Path(os.environ['EXTENSION_BUNDLE'])
with (app / 'Info.plist').open('rb') as handle:
    app_metadata = plistlib.load(handle)
for bundle, identifier, executable in (
    (app, 'com.tema.CarrierSIM', 'CarrierSIM'),
    (extension, 'com.tema.CarrierSIM.Tunnel', 'CarrierSIMTunnel'),
):
    path = bundle / 'Info.plist'
    with path.open('rb') as handle:
        data = plistlib.load(handle)
    data['CFBundleIdentifier'] = identifier
    data['CFBundleExecutable'] = executable
    data['CFBundleSupportedPlatforms'] = ['iPhoneOS']
    data['CFBundleInfoDictionaryVersion'] = '6.0'
    data.setdefault('CFBundleVersion', '1')
    data.setdefault('CFBundleShortVersionString', '1.0')
    data.setdefault('MinimumOSVersion', '26.0')
    if bundle == extension:
        data['NSExtension']['NSExtensionPrincipalClass'] = 'PacketTunnelProvider'
        data['CFBundleVersion'] = app_metadata['CFBundleVersion']
        data['CFBundleShortVersionString'] = app_metadata['CFBundleShortVersionString']
        data['UIDeviceFamily'] = app_metadata.get('UIDeviceFamily', [1])
    with path.open('wb') as handle:
        plistlib.dump(data, handle, fmt=plistlib.FMT_BINARY)
PY

# Preserve intended entitlements inside both Mach-O signatures so capable
# sideloading tools can re-sign them. This is not an Apple installation signature.
for spec in \
    "$PROJECT_ROOT/App/CarrierSIM.entitlements|$APP_BUNDLE/CarrierSIM" \
    "$PROJECT_ROOT/Tunnel/CarrierSIMTunnel.entitlements|$EXTENSION_BUNDLE/CarrierSIMTunnel"; do
    entitlement_path="${spec%%|*}"
    executable_path="${spec#*|}"
    if [[ -f "$entitlement_path" ]]; then
      ldid -S"$entitlement_path" "$executable_path"
    else
      printf 'Entitlement template missing: %s\n' "$entitlement_path" >&2
      exit 1
    fi
done

python3 "$PROJECT_ROOT/scripts/build-inputs.py" verify "$PROJECT_ROOT" "$BUILD_ROOT/build-inputs.json"

# Keep this symbol dynamically discoverable for the paired service authorization.
llvm-nm --extern-only --defined-only "$APP_BUNDLE/CarrierSIM" | \
  python3 -c 'import sys; s=sys.stdin.read(); required=["_ALGetGrappaToken", "_cs_execute", "_cs_install_ipa", "_cs_developer_mode", "_cs_sign_self", "_al_pairing_cancel_host"]; missing=[name for name in required if name not in s]; assert not missing, "Required bridge exports are missing: " + ", ".join(missing)'

export PROJECT_ROOT BUILD_ROOT STAGE_ROOT
python3 - <<'PY'
import hashlib, json, os, plistlib, shutil, stat, struct, subprocess, zipfile
from pathlib import Path

stage = Path(os.environ['STAGE_ROOT'])
build = Path(os.environ['BUILD_ROOT'])
app = Path(os.environ['APP_BUNDLE'])
extension = Path(os.environ['EXTENSION_BUNDLE'])
for executable, expected_type in ((app / 'CarrierSIM', 2), (extension / 'CarrierSIMTunnel', 2)):
    data = executable.read_bytes()
    magic, cpu, subtype, filetype = struct.unpack_from('<4I', data)
    assert magic == 0xFEEDFACF, f'{executable.name}: not a 64-bit Mach-O'
    assert cpu == 0x0100000C, f'{executable.name}: not arm64'
    assert filetype == expected_type, f'{executable.name}: unexpected Mach-O file type'
    executable.chmod(0o755)
    print(f'Verified {executable.name}: native Mach-O arm64, {len(data):,} bytes')

def package(source, destination, with_extension):
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for item in sorted((source / 'Payload').rglob('*')):
            if item.is_file():
                archive.write(item, item.relative_to(source).as_posix())
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None, 'IPA ZIP integrity verification failed'
        executables = ['Payload/CarrierSIM.app/CarrierSIM']
        if with_extension:
            executables.append('Payload/CarrierSIM.app/PlugIns/CarrierSIMTunnel.appex/CarrierSIMTunnel')
        else:
            assert not any('/PlugIns/' in name for name in archive.namelist())
        for name in executables:
            assert archive.getinfo(name).external_attr >> 16 & stat.S_IXUSR, 'Executable bit is missing'
    print(f'IPA: {destination}')
    print(f'SHA256: {hashlib.sha256(destination.read_bytes()).hexdigest()}')

package(stage, build / 'CarrierSIM-iOS-unsigned.ipa', with_extension=True)

# Optional signing fallback. The identical app detects the missing embedded
# extension and uses its existing external-local-VPN flow.
fallback_stage = stage / 'external-vpn'
fallback_app = fallback_stage / 'Payload' / 'CarrierSIM.app'
shutil.copytree(app, fallback_app)
shutil.rmtree(fallback_app / 'PlugIns')
empty_entitlements = stage / 'external-vpn.entitlements'
empty_entitlements.write_bytes(plistlib.dumps({}))
subprocess.run(['ldid', '-S' + str(empty_entitlements), str(fallback_app / 'CarrierSIM')], check=True)
fallback_entitlements = subprocess.check_output(['ldid', '-e', str(fallback_app / 'CarrierSIM')])
assert 'com.apple.developer.networking.networkextension' not in plistlib.loads(fallback_entitlements)
package(fallback_stage, build / 'CarrierSIM-iOS-external-vpn.ipa', with_extension=False)
manifest = {
    'platform': 'iOS',
    'architecture': 'arm64',
    'apple_signed': False,
    'compiler': subprocess.check_output(['clang', '--version'], text=True).splitlines()[0],
    'rust': subprocess.check_output(['rustc', '--version'], text=True).strip(),
    'sources': json.loads((build / 'build-inputs.json').read_text()),
    'artifacts': {
        name: hashlib.sha256((build / name).read_bytes()).hexdigest()
        for name in ('CarrierSIM-iOS-unsigned.ipa', 'CarrierSIM-iOS-external-vpn.ipa')
    },
}
(build / 'CarrierSIM-build-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
print('Re-sign both the app and its VPN extension using an Apple identity/profile before installation.')
PY
