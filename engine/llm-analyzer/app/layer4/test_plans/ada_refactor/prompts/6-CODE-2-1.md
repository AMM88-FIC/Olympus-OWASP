MASTG-TEST-0042
masvs_v1_id	MSTG-CODE-5
masvs_v2_id	MASVS-CODE-3
platform	android
title	Checking for Weaknesses in Third Party Libraries
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app ships any third-party library at a version with known CVEs of severity ≥ CVSS 7.0. Three dependency categories are in scope: Java/Kotlin libraries (DEX classes from JAR/AAR coordinates), native libraries (`.so` files under `lib/<abi>/`), and JavaScript dependencies bundled into hybrid apps.

The Verification permits two justifications that can excuse a vulnerable library: (a) the app does not invoke the vulnerable code path; (b) the library has no patched version available yet and follows a regular patch process. Both justifications require evidence the static pipeline cannot supply on its own; the typical achievable verdict is `partial_static_only`.

Static Analysis
L1 evidence is expected to surface dependencies via:

- Maven/Gradle coordinates (when build metadata is present)
- Class-file fingerprinting of `classes*.dex` against known library signatures
- Native library identification under `lib/<abi>/*.so` by name, ELF metadata, exported symbols, content hash
- JavaScript bundle scanning (RetireJS-style) of `assets/`, `res/raw/`, WebView-bundled HTML/JS

Each identified `(library, version)` pair is checked against a CVE feed for the highest-severity CVE affecting that version. Findings are limited to CVSS ≥ 7.0.

Description
The app only uses software components without known vulnerabilities.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0042.

Verification
The app shall not use any third-party library at a version vulnerable to a CVE with severity ≥ CVSS 7.0.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every third-party library shipped at a version vulnerable to one or more CVEs with severity ≥ CVSS 7.0. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each Java/Kotlin third-party library at a version affected by one or more CVEs of severity ≥ CVSS 7.0
- Each native library (`.so`) at a version affected by one or more CVEs of severity ≥ CVSS 7.0
- Each JavaScript dependency in bundled webroot assets at a version affected by one or more CVEs of severity ≥ CVSS 7.0

Two records describing the same `(library, version)` pair are duplicates and count as one. The same library shaded under two distinct internal module paths at the same version is one row (one upgrade fixes it); the same library at two distinct versions is two rows. The rationale should group findings by language/artifact category (Java/Kotlin, native, JavaScript) and cite the relevant CVE IDs and CVSS scores per row.
