MASTG-TEST-XXXX

masvs_v1_id    MSTG-CRYPTO-1 (and MSTG-CRYPTO-2)
masvs_v2_id    MASVS-CRYPTO-2
platform       android
title          Cryptographic key management implemented correctly across the key lifecycle (1.2.1.5, static)

What this test looks for
Keys must follow lifecycle best practices. A key fails if ANY of these criteria is violated:
- KM1 - Sync: a key protecting high-risk data must not be synchronized/backed up across devices.
- KM2 - Storage: a key must not be persisted without additional protection (raw key bytes in prefs/files/DB/resources).
- KM3 - Hardcoded: a key must not be embedded in the app (literal bytes/String, constant field, BuildConfig, resource/asset).
- KM4 - Device derivation: a key must not be derived from stable device characteristics (non-secret, predictable).
- KM5 - Obscurity: a key must not be protected solely by hiding it in low-level/native code (security through obscurity).
- KM6 - Insecure import: a key must not be imported from an insecure location (public/external storage, cleartext network, world-readable file, unprotected IPC).
This is a fully static, inventory-style evaluation: enumerate every key, then check each against KM1-KM6. Verdict: `pass` (all keys meet all criteria), `fail` (>=1 key violates >=1 criterion, in proprietary reachable code), `n/a` (the app manages no cryptographic keys), or `inconclusive`.

Source is ground truth. A crypto/key evidence index is a candidate list only - it does not track a key's storage, provenance, or import path across methods and aliases. Confirm every conclusion by reading the key's materialization, storage, and load path in `jadx/sources/`, the manifest, and resources. The `find_callers`/`find_callees` call graph gives *candidate* chains, not confirmed flow - confirm in source.

The good pattern (do not flag)
A key generated in and confined to **AndroidKeyStore** (`KeyGenParameterSpec` -> `KeyStore.getKey`, never exported) is non-exportable and device-bound: it inherently satisfies KM1 (not syncable), KM2 (hardware/TEE-protected, not raw-persisted), and KM6 (not imported). Do not flag such a key for storage/sync. A session key derived fresh from a user secret via a strong KDF (PBKDF2 adequate iterations + random salt / scrypt / Argon2) and never persisted is also acceptable provenance. A raw key wrapped (encrypted) by a KeyStore key before persistence satisfies KM2.

Per-criterion detection signals
- KM2/KM3: trace each key's bytes to their origin. Literal/constant/BuildConfig/resource -> KM3. Persisted raw to `SharedPreferences`, a file, SQLite, or `DataStore` without wrapping/KeyStore -> KM2. (Cross-references test 1.2.1.2's hardcoded-key check for KM3.)
- KM1: a key (or the store holding it) exposed to backup/sync - e.g. `android:allowBackup="true"` with key material in backed-up storage, inclusion in an Auto Backup set / `BackupAgent`, or storage in a cloud/account-synced location - while the data it protects is high-risk (credentials, payment, health, precise location, etc.).
- KM4: key material or KDF input sourced from `TelephonyManager.getImei`/`getDeviceId`/`getSubscriberId`, `Build.SERIAL`/`getSerial`, `Settings.Secure.ANDROID_ID`, Wi-Fi/Bluetooth MAC, `Build.FINGERPRINT`, or account name - any stable, non-secret device property.
- KM5: key bytes produced by a `native` method / loaded from a `.so` with no real KeyStore/KMS protection, where obfuscation is the only barrier.
- KM6: key bytes read from `Environment.getExternalStoragePublicDirectory`/`getExternalStorageDirectory`/a world-readable path, downloaded over cleartext or unpinned HTTP, or received via an unprotected `Intent`/`ContentProvider`, then used/imported as a key.

Key materialization & storage APIs to enumerate
`SecretKeySpec`, `KeyGenerator.generateKey`, `KeyPairGenerator.generateKeyPair`, `SecretKeyFactory.generateSecret` (PBKDF2), `KeyGenParameterSpec`, `KeyStore.getKey`/`getEntry`/`setEntry`/`setKeyEntry`, key bytes via `getBytes`/`decode`; storage sinks `SharedPreferences.put*`, file/`FileOutputStream` writes, SQLite/`DataStore`; sources `TelephonyManager`/`Settings.Secure`/`Build`/network/external storage; manifest `allowBackup`/backup rules.

Procedure
1. Enumerate every key materialization from the evidence index if present, then confirm with grep, e.g. `grep -rEn "SecretKeySpec|KeyGenerator|KeyPairGenerator|SecretKeyFactory|KeyGenParameterSpec|KeyStore\.getInstance|\.getKey\(|setKeyEntry|setEntry" jadx/sources/`. If there are zero key materializations of any kind, the verdict is `n/a`.
2. For each key, identify storage location, byte provenance, any KDF and its inputs, any import/load path, and backup/sync exposure (read the manifest for `allowBackup`/backup rules). Determine the sensitivity of the data the key protects (needed for KM1).
3. **Read the surrounding context** to confirm what the key does and what it protects - do not infer from a variable name alone. If the purpose/sensitivity is indeterminate, prefer `unverified` over assuming.
4. Check the key against KM1-KM6. Skip criteria neutralized by the good pattern (KeyStore-confined, KDF-derived-not-persisted, wrapped-before-persist).
5. **Ownership + reachability (mandatory for any finding).** Classify the owning class proprietary vs third-party from evidence (package prefix is a hint only; in OEM/ROM apps platform-looking or vendor-looking prefixes are often first-party; an undecidable/obfuscated owner defaults to **proprietary, in scope** - never silently out-of-scope it). Run `find_callers` to confirm proprietary code materializes/uses the key, and cite the chain in an L2 row. A finding without an evidenced ownership decision AND a cited `find_callers` chain is invalid -> downgrade to `unverified`.
6. Conclude per key: Finding (violates >=1 of KM1-KM6, in security-relevant context, proprietary & reachable - name the criterion); Compliant (meets all criteria / good pattern); Unreachable (violation only in dead/test/independent-SDK-internal code); documented candidate (see rules).
7. Budget ~2-4 reads per key (materialization, storage, provenance/import, manifest) plus 1-2 call-graph hops. If storage, provenance, import path, owner, or reachability can't be resolved within the bytecode within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Key handling fully inside native code or a no-source third-party SDK can't be traced statically: record an `unverified` row (name the entry point). KM5 (native obscurity) is inherently hard to confirm statically - flag the pattern and, where the key's true protection can't be seen, use `unverified`. The static verdict is made on what was determinable and is not deferred to runtime.

Output
List **all** key uses - one L1 row per key with its lifecycle disposition. <=20 keys -> one L1 row each. >20 keys -> group Compliant keys by functionality (e.g. "KeyStore-backed field keys - 8 keys") as one L1 row per group, but always break out every Finding (with its KM criterion), documented-candidate, and unverified key as its own individual L1 row regardless of count. Never sample findings.
- Finding: L1 row plus L2 rows for the violated criterion (the storage line / literal / device-property source / import path / native source), for the protected-asset context (esp. KM1 high-risk), AND for ownership+`find_callers` reachability.
- Compliant: L1 row plus L2 for the good pattern that satisfies the criteria.
- Group: L1 summary plus an L2 naming the keys/references and why they are compliant.

```
{
  "id": "key-001",
  "description": "Finding (KM3 hardcoded + KM2 unprotected storage): The AES key for the local credential vault is a hardcoded literal and the wrapped blob is the only thing the app relies on - the key itself ships in the APK.",
  "reference": "jadx/sources/com/example/app/Vault.java",
  "level": 1
},
{
  "id": "L2-Vault-criterion",
  "description": "KM3: SecretKeySpec(\"S3cr3tKey0123456\".getBytes(), \"AES\") at line 19 - key bytes are a String literal embedded in the app. No KeyStore, no derivation. (KM2 also: the key is not protected by any keystore/wrapping.)",
  "reference": "jadx/sources/com/example/app/Vault.java:16-22",
  "level": 2
},
{
  "id": "L2-Vault-context",
  "description": "Protected asset: Vault.encrypt is used by CredentialStore to encrypt the user's saved passwords - high-risk data. A hardcoded key means anyone with the APK can decrypt them.",
  "reference": "jadx/sources/com/example/app/CredentialStore.java:40-52",
  "level": 2
},
{
  "id": "L2-Vault-reachability",
  "description": "Ownership + reachability: Vault is first-party (app application-id namespace) -> proprietary (an obfuscated/undecidable owner would also default to proprietary). find_callers: Vault.encrypt <- CredentialStore.save <- SettingsActivity.onSave. Live in proprietary code.",
  "reference": "jadx/sources/com/example/app/SettingsActivity.java:88-95",
  "level": 2
},
{
  "id": "key-ks-group",
  "description": "Compliant group: 8 AndroidKeyStore AES keys (KeyGenParameterSpec, non-exportable) for local field encryption - device-bound, hardware-protected; satisfy KM1/KM2/KM6.",
  "reference": "jadx/sources/com/example/app/store/",
  "level": 1
},
{
  "id": "L2-ks-coverage",
  "description": "Good pattern: keys generated via KeyGenParameterSpec(alias, ENCRYPT|DECRYPT) and only retrieved through KeyStore.getKey; never exported, never written to prefs/files, not derived from device props, not imported. References FieldVault.java:30-140 (and 7 more).",
  "reference": "jadx/sources/com/example/app/store/FieldVault.java:30-140",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K keys enumerated, N findings (by criterion: KM1.. KM6), C compliant, D unreachable, U unverified. <one or two sentences naming the keys, the violated criteria and the contexts>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only to mark native/no-source-SDK key handling recorded as `unverified`. It does not change `pass`/`fail`.
- `fail`: >=1 key with (a) an L2 row showing a KM1-KM6 violation (naming the criterion), (b) an L2 row establishing the security-relevant context/protected asset read from code, AND (c) an L2 row giving an evidenced ownership verdict plus a `find_callers` chain from proprietary code.
- **Enforcement - no finding without the three L2 rows.** A candidate finding missing the context row OR the ownership+reachability row is invalid -> downgrade to `unverified` (name what was unresolved). Ownership and reachability may NOT be asserted from a package/obfuscated name or the rationale prose; they come from an actual `find_callers` result and an evidenced ownership decision. If `find_callers` was not run for a site, it cannot be a finding.
- **Ownership default (OEM-aware).** Decide owner from evidence, not prefix. Platform-looking or vendor-looking prefixes can be first-party in OEM/ROM apps - do not out-of-scope on prefix. Undecidable/obfuscated owner -> proprietary (in scope); never silently drop a site.
- **No sampling.** Every finding is its own L1 row; the rationale finding count MUST equal the number of finding L1 rows (grouping is only for Compliant keys). Claiming more violations than rows is `inconclusive`.
- Do not flag the good pattern: KeyStore-confined keys (KM1/KM2/KM6 satisfied), KDF-derived-not-persisted session keys, raw keys wrapped by a KeyStore key before persistence.
- `pass`: keys are managed and every key meets all applicable criteria (good pattern or evidenced compliance), with L2 coverage.
- `n/a`: no key materialization of any kind exists (enumeration performed and empty).
- Documented exception: an external-system requirement justifying e.g. a shared/imported key is a documentation fact outside the APK - record the key as a Finding "documented candidate" with a matching `false_positive_risks` entry; it counts toward `fail` unless the assessor downgrades it.
- `unverified` rows name the deepest unresolved point (or the native/SDK entry point). Such keys are neither findings nor cleans.
- `false_positive_risks` is for factors **outside the static artifact only** (documented exceptions, key path resolved at runtime by server config, OEM framework behavior). Statements about what in-APK code does or might be for must be resolved by reading the code (steps 3-4) and recorded as Compliant/Finding/`unverified`; they are INVALID as `false_positive_risks` entries.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if any candidate finding was dropped/out-of-scoped without an evidenced ownership decision, or if any `fail` lacks its three L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the violated KM criterion is named and evidenced from code; (2) the protected-asset context was read (not inferred from a name); (3) an evidenced proprietary-vs-third-party ownership decision was made (OEM-aware, obfuscated->proprietary) AND `find_callers` was actually run and its chain cited. If any is missing, downgrade to `unverified`. Then confirm the rationale finding count equals the finding rows (no sampling) and no `false_positive_risks` entry describes in-APK code. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.