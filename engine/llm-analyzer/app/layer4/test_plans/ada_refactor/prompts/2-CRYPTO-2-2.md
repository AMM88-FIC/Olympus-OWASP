MASTG-TEST-0062
masvs_v1_id	MSTG-CRYPTO-1
masvs_v2_id	MASVS-CRYPTO-2
platform	android
title	Testing Key Management
masvs_v1_levels	L1, L2

Overview
This test evaluates how cryptographic keys are stored, derived, imported, and protected against backup. Algorithm choice and purpose binding are scoped to CRYPTO-1-2/CRYPTO-1-3/CRYPTO-2-1; this test covers management failures.

Static Analysis
For each key, inspect its provenance and storage:

- KeyStore-backed vs. raw bytes in `SharedPreferences`/files/resources/build configs/manifest
- Backup exposure: `android:allowBackup="true"` combined with absence of `BackupAgent`/`fullBackupContent`/`dataExtractionRules` exclusion of the key's path
- Hardcoded keys (literals, constants, static fields)
- Derivation from stable device features (`Build.SERIAL`, `ANDROID_ID`, IMEI, MAC, advertising ID, package name, install ID) without additional per-user secret
- Provenance crossing into native (JNI/`.so`)
- Import from untrusted sources (external storage, network, intent extras, content providers, clipboard)

Description
Cryptographic keys shall be managed securely.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0062, applied to the Android codebase.

Verification
The analysis shall demonstrate that all cryptographic keys protecting data covered by the threat model are managed in accordance with the listed requirements.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every cryptographic key managed against the requirements. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each key whose persisted storage is not Keystore-protected (raw bytes in `SharedPreferences`, files under `getFilesDir()`, `res/raw/`, `assets/`, build configs, manifest meta-data) when protecting threat-model-covered data
- Each key exposed to cloud backup channels: `android:allowBackup="true"` without exclusion of the key's storage path via `BackupAgent`, `fullBackupContent`, or `dataExtractionRules`
- Each hardcoded key (`byte[]` literal, `String` constant, static field) used in a long-lived or cross-install context
- Each key derived from a stable device-identifying feature without an additional per-user secret or Keystore-backed entropy
- Each key whose generation, storage, or retrieval path crosses into native code (JNI/`.so`)
- Each key imported from an untrusted source (external storage, network response, intent extra, content provider, clipboard)

Two records describing the same key managed at the same site are duplicates and count as one. The same key with two distinct management failures (e.g. hardcoded AND exposed to backup) produces two rows. The rationale should group findings by surface (unprotected storage, backup exposure, hardcoded, device-derived, native-concealed, imported-from-untrusted).
