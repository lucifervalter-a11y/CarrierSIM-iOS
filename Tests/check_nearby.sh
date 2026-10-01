#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(uname -s)" == Darwin ]] || { echo 'Requires macOS with Xcode'; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
python3 - "$ROOT" "$TMP" <<'PY'
from pathlib import Path
import sys
root, out=map(Path,sys.argv[1:])
source=(root/'App/CSNearbyViewController.m').read_text()
parser=source[source.index('static NSString *const'):source.index('@interface CSNearbyViewController')]
(out/'test.m').write_text('#import <Foundation/Foundation.h>\n'+parser+(root/'Tests/nearby_protocol_test.m').read_text())
PY
xcrun clang -fobjc-arc -fblocks -framework Foundation "$TMP/test.m" -o "$TMP/protocol-test"
"$TMP/protocol-test"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
xcrun --sdk iphoneos clang -target arm64-apple-ios18.0 -isysroot "$SDK" -fobjc-arc -fblocks -fsyntax-only -Wno-deprecated-declarations -I "$ROOT/App" "$ROOT/App/CSNearbyViewController.m"
echo 'Nearby UIKit/MultipeerConnectivity source syntax checked for iPhoneOS.'
