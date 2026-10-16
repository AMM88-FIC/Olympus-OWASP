MASTG-TEST-0044
masvs_v1_id	MSTG-CODE-9
masvs_v2_id	MASVS-CODE-4
platform	android
title	Make Sure That Free Security Features Are Activated
masvs_v1_levels	L1, L2

Overview
This test evaluates whether every native library shipped in the APK was built with the two free compiler security features that the Android NDK toolchain provides by default: position-independent code (PIE/PIC) and stack canary protection.

Static Analysis
Inspect every `lib/<abi>/*.so` under the APK. For each, examine the ELF metadata:

- `pic` — must be `true`. PIE/PIC is required for ASLR; without it, the loader places the library at a fixed address.
- `canary` — must be `true`. The canary symbol indicates the binary was compiled with `-fstack-protector-strong` (or stronger), which inserts checks against stack-buffer overflows.

Tools such as `rabin2 -I <lib>.so` surface both flags. Both must be `true`; either flag set to `false` is a violation for that library.

Description
Compiler security features shall be enabled.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0044.

Verification
The analysis shall demonstrate that all native libraries packaged in the APK are compiled with PIE/PIC and stack canary protections enabled. A third-party native library missing these flags may still pass if the developer provides justification that the library does not build or work as expected with these flags enabled.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every native library packaged in the APK that is missing one or both compiler security features. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `.so` under `lib/<abi>/` whose ELF metadata reports `pic` = `false`
- Each `.so` under `lib/<abi>/` whose ELF metadata reports `canary` = `false`

A single library missing both flags produces two rows. The same library at the same version present under multiple ABI directories (`lib/arm64-v8a/foo.so` and `lib/armeabi-v7a/foo.so`) counts as one row when both copies have the same flag profile, two rows when the profiles differ. The rationale should group findings by library, with one row per (library, missing flag) pair.
