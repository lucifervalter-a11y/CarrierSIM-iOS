#!/usr/bin/env bash
# Cargo also builds helper dylibs for some FFI dependencies. Route those through
# the same Darwin linker and SDK as the final app, never the Linux ELF linker.
set -euo pipefail
: "${SDKROOT:?SDKROOT must point to an iPhoneOS SDK}"
IOS_CLANG="${CC_aarch64_apple_ios:-$(command -v clang)}"
IOS_LINKER="$(command -v ld64.lld)"
exec "$IOS_CLANG" -isysroot "$SDKROOT" \
  -fuse-ld="$IOS_LINKER" -mlinker-version=1000 "$@"
