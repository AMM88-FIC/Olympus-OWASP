MASTG-TEST-0038
masvs_v1_id	MSTG-CODE-1
masvs_v2_id	MASVS-RESILIENCE-2
platform	android
title	Making Sure that the App is Properly Signed
masvs_v1_levels	R

Overview
This test evaluates whether the APK is signed with the APK Signature Scheme v2 or higher. Apps signed only with the legacy JAR (v1) scheme are vulnerable to the Janus attack (CVE-2017-13156), which permits arbitrary code injection without invalidating the signature.

Static Analysis
Inspect the APK's signing block. Tools such as `apksigner verify --verbose <apk>` report which schemes were used:

- v1 (JAR signing) — legacy, vulnerable to Janus on its own.
- v2 (APK Signature Scheme v2) — required for Android 7.0+ (API 24+).
- v3 (APK Signature Scheme v3) — recommended for Android 9+ (API 28+); supports key rotation.
- v4 (APK Signature Scheme v4) — adjacent, used with incremental installation; not required for security baseline.

Also inspect the signing certificate. Debug certificates are recognizable by their default `CN=Android Debug, O=Android, C=US` subject and must not appear in release-built APKs.

Description
The app shall be properly signed.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0038.

Verification
The APK shall be signed using APK Signature Scheme v2 or higher, and the signing certificate shall not be a debug certificate.

Verdict scope
This test is binary. The verdict is a yes/no on whether the APK is signed with v2 or higher and signed with a non-debug certificate. The evidence_table cites the signature-scheme record from the L1 evidence (typically the signing-information section) and any supporting certificate-subject context. There is no enumeration to do beyond that.
