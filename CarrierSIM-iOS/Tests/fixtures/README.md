# Fixture for signature tests

`unsigned-arm64.macho` is built from `signature-test.c`, contains only a main function returning zero, and is never packaged in CarrierSIM. It targets an iOS arm64 device and has no code signature.

Reproduce with the configured LLVM/iPhoneOS toolchain:

```sh
clang -target arm64-apple-ios18.0 -isysroot "$SDKROOT" \
  -fuse-ld=ld64.lld -mlinker-version=1000 -Wl,-no_adhoc_codesign \
  Tests/fixtures/signature-test.c -o Tests/fixtures/unsigned-arm64.macho
```

The integration test creates a temporary self-signed test certificate and P12 using OpenSSL, imports it, signs this bundle, verifies its CMS signature and code hashes, and detects modified bytes. It also verifies that a provisioning profile signed by this test certificate is rejected. Temporary private keys are removed; no usable Apple certificate is supplied.
