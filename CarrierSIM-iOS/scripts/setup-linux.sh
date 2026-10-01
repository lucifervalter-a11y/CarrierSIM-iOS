#!/usr/bin/env bash
# Ubuntu 24.04 x86_64: download a pinned task-local toolchain and optionally build.
set -euo pipefail
SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIRECTORY/setup-linux.py" "$@"
