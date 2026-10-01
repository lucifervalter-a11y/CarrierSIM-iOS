#!/usr/bin/env python3
"""Reproduce the Linux toolchain without changing system packages or shell profiles."""
import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path


def run(arguments, **kwargs):
    return subprocess.run([str(value) for value in arguments], check=True, **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build", action="store_true", help="Build both IPA variants after setup")
args = parser.parse_args()
if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
    raise SystemExit("This recipe targets Ubuntu 24.04 x86_64. Use build-macos.sh on macOS.")
required = ("curl", "git", "dpkg-deb", "cc", "make", "ar")
missing = [name for name in required if not shutil.which(name)]
if missing:
    raise SystemExit("Missing prerequisites: " + ", ".join(missing) + ". See scripts/BUILDING.md.")

project = Path(__file__).resolve().parent.parent
metadata = json.loads((project / "scripts/linux-toolchain.json").read_text())
toolchain = Path(os.environ.get("CARRIERSIM_TOOLCHAIN", str(project.parent / "toolchain"))).resolve()
downloads = toolchain / "downloads"
downloads.mkdir(parents=True, exist_ok=True)


def download(url, destination, expected):
    if destination.is_file() and digest(destination) == expected:
        return destination
    partial = destination.with_name(destination.name + ".part")
    run(["curl", "-fsSL", "--retry", "2", "--connect-timeout", "25", "--max-time", "300", url, "-o", partial])
    if digest(partial) != expected:
        raise SystemExit("Checksum mismatch: " + destination.name)
    partial.replace(destination)
    return destination


def fetch_llvm(package):
    destination = downloads / Path(package["Filename"]).name
    download(metadata["llvm_base_url"] + package["Filename"], destination, package["SHA256"])
    return package["Package"], destination


llvm_install = toolchain / "llvm"
llvm_install.mkdir(exist_ok=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    for name, archive in executor.map(fetch_llvm, metadata["llvm_packages"]):
        run(["dpkg-deb", "-x", archive, llvm_install])
        print("Verified LLVM package:", name, flush=True)

sdks = toolchain / "sdks"
revision = metadata["sdk_revision"]
if not sdks.exists():
    sdks.mkdir()
    run(["git", "init", "-q", sdks])
    run(["git", "-C", sdks, "remote", "add", "origin", metadata["sdk_repository"]])
    run(["git", "-C", sdks, "sparse-checkout", "init", "--cone"])
    run(["git", "-C", sdks, "sparse-checkout", "set", metadata["sdk_directory"]])
    run(["git", "-C", sdks, "fetch", "--depth", "1", "--filter=blob:none", "origin", revision])
    run(["git", "-C", sdks, "checkout", "--detach", "FETCH_HEAD"])
else:
    existing = subprocess.check_output(["git", "-C", str(sdks), "rev-parse", "HEAD"], text=True).strip()
    if existing != revision:
        raise SystemExit("Existing SDK checkout differs from the pinned revision. Choose a new CARRIERSIM_TOOLCHAIN directory.")
sdk = sdks / metadata["sdk_directory"]
if not (sdk / "SDKSettings.json").is_file():
    raise SystemExit("The expected iPhoneOS SDK is missing from the checkout.")

(toolchain / "bin").mkdir(exist_ok=True)
ldid = download(metadata["ldid_url"], toolchain / "bin/ldid", metadata["ldid_sha256"])
ldid.chmod(0o755)
environment = os.environ.copy()
environment.update({"RUSTUP_HOME": str(toolchain / "rustup"), "CARGO_HOME": str(toolchain / "cargo")})
environment["PATH"] = str(toolchain / "cargo/bin") + os.pathsep + environment["PATH"]
rustc = toolchain / "cargo/bin/rustc"
version = ""
if rustc.exists():
    version = subprocess.check_output([str(rustc), "--version"], env=environment, text=True).strip()
if not version.startswith("rustc " + metadata["rust_version"] + " "):
    installer_url = "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
    checksum_text = subprocess.check_output(["curl", "-fsSL", "--retry", "2", "--connect-timeout", "25", "--max-time", "90", installer_url + ".sha256"], text=True)
    expected = checksum_text.split()[0]
    if len(expected) != 64 or any(value not in "0123456789abcdef" for value in expected):
        raise SystemExit("Invalid Rust installer checksum response.")
    installer = download(installer_url, downloads / "rustup-init", expected)
    installer.chmod(0o755)
    run([installer, "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", metadata["rust_version"], "--target", "aarch64-apple-ios"], env=environment)
run([toolchain / "cargo/bin/rustup", "target", "add", "aarch64-apple-ios"], env=environment)

llvm_root = toolchain / "llvm/usr/lib/llvm-20"
environment["PATH"] = str(llvm_root / "bin") + os.pathsep + str(toolchain / "bin") + os.pathsep + environment["PATH"]
environment["LD_LIBRARY_PATH"] = str(toolchain / "llvm/usr/lib/x86_64-linux-gnu") + os.pathsep + str(llvm_root / "lib") + (os.pathsep + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else "")
environment["CARRIERSIM_TOOLCHAIN"] = str(toolchain)
environment["SDKROOT"] = str(sdk)
run([llvm_root / "bin/clang", "--version"], env=environment)
run([llvm_root / "bin/ld64.lld", "--version"], env=environment)
run([rustc, "--version"], env=environment)
print("Toolchain ready:", toolchain, flush=True)
if args.build:
    run([project / "scripts/build-linux.sh"], env=environment)
