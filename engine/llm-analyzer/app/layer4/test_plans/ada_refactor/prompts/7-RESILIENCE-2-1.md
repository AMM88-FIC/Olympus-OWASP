MASTG-TEST-0040
masvs_v1_id	MSTG-CODE-3
masvs_v2_id	MASVS-RESILIENCE-3
platform	android
title	Testing for Debugging Symbols
masvs_v1_levels	R

Overview
This test evaluates whether each native library packaged in the APK has had its debug symbols stripped for the release build. Debug symbols (function names, source line mappings, type information) significantly aid reverse engineering of native code; release builds should strip them.

Static Analysis
Inspect every `lib/<abi>/*.so` under the APK. For each, examine the symbol tables:

- The full symbol table (visible with `nm -a <lib>.so`) — release builds should be empty or contain only essential exports. The presence of `.debug_info`, `.debug_str`, `.debug_line`, or other `.debug_*` ELF sections indicates the library was built with `-g` and not stripped.
- The dynamic symbol table (visible with `nm -D <lib>.so`) — should contain only the JNI entry points (functions declared `JNIEXPORT` or registered via `RegisterNatives`). Internal helper functions exposed in the dynamic table indicate the library was not built with `-fvisibility=hidden`.

Description
The app shall disable all debugging symbols in the production version.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0040.

Verification
The analysis shall demonstrate that all native libraries packaged in the APK have had their debug symbols stripped, and that the dynamic symbol table exposes only JNI entry points.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every native library that ships with debug symbols or with internal symbols left in the dynamic table. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `.so` under `lib/<abi>/` whose ELF metadata reports the presence of `.debug_*` sections or a non-empty full symbol table containing internal symbols
- Each `.so` under `lib/<abi>/` whose dynamic symbol table exposes non-JNI internal functions (i.e. the library was not compiled with `-fvisibility=hidden` or equivalent)

A single library failing both checks produces two rows. The same library at the same version present under multiple ABI directories counts as one row when the symbol profiles match, two rows when they differ. The rationale should group findings by library, with one row per (library, symbol-table issue) pair.
