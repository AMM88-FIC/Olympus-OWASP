MASTG-TEST-0328

maswe_id       MASWE-0046
masvs_v2_id    MASVS-AUTH-2
platform       android
title          References to APIs Detecting Biometric Enrollment Changes - setInvalidatedByBiometricEnrollment(false) (static)

What this test looks for
A biometric-gated key that protects sensitive data should be invalidated when a NEW biometric is enrolled - otherwise an attacker who knows the device passcode can enroll their own fingerprint/face and then authenticate in the app. Android invalidates such keys by default; `KeyGenParameterSpec.Builder.setInvalidatedByBiometricEnrollment(true)` is the safe default, and explicitly setting it to `false` keeps the key usable after new enrollment. This is a static evaluation of every auth-bound key generation. Verdict: `pass` (auth-bound keys protecting sensitive data are invalidated on enrollment - default or `true`), `fail` (>=1 key protecting sensitive data is generated with `setInvalidatedByBiometricEnrollment(false)`), `n/a` (the app generates no biometric/auth-bound keys), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `setInvalidatedByBiometricEnrollment`/`setUserAuthenticationRequired`/`KeyGenParameterSpec`. If no auth-bound key generation appears -> `n/a` (state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `setInvalidatedByBiometricEnrollment(false)` call on the key spec AND the sensitive data the key protects. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual builder call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) `setInvalidatedByBiometricEnrollment(false)` and (b) the sensitive data the key guards. "probably not invalidated" with no quoted call is NOT evidence -> `unverified`. The default (no call) is `true` -> Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the boolean argument or the key's purpose can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Scope note
This concern applies to keys that are biometric/auth-bound (`setUserAuthenticationRequired(true)`) and protect sensitive data - those are the keys whose post-enrollment usability matters. A key with `setInvalidatedByBiometricEnrollment(false)` that is NOT auth-bound, or guards nothing sensitive, is a weaker concern (note it; primary finding is on auth-bound sensitive-data keys).

Procedure
1. Enumerate auth-bound key generations: `grep -rEn "KeyGenParameterSpec|setInvalidatedByBiometricEnrollment|setUserAuthenticationRequired|setUserAuthenticationParameters" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each key spec, read the `setInvalidatedByBiometricEnrollment` argument: `false` (candidate finding), `true` or absent/default (Compliant). Quote it. Confirm the key is auth-bound (`setUserAuthenticationRequired(true)`).
3. For each `false` on an auth-bound key, trace what sensitive data the key protects (token/credential/PII decryption). Quote the protected data. Non-sensitive -> note as Compliant/lower-severity.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per key: Finding (`setInvalidatedByBiometricEnrollment(false)` on an auth-bound sensitive-data key, quoted); Compliant (default/`true`, or non-sensitive/non-auth-bound); Unverified (argument/purpose unresolved).
6. Budget ~2-4 reads per key (the builder, the auth-required flag, the protected data). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Key generation inside native code or a no-source SDK -> `unverified` (name the entry point). DEVICE_CREDENTIAL fallback is MASTG-TEST-0326; CryptoObject binding is MASTG-TEST-0327; validity duration is MASTG-TEST-0330. This test is the enrollment-invalidation flag.

Output
List **all** auth-bound key generations - one L1 row per key with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant invalidated keys by area, but always break out every Finding and unverified key individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting `setInvalidatedByBiometricEnrollment(false)` (on an auth-bound key) and the sensitive data it protects, plus owner.
- Compliant: L1 row plus an L2 showing default/`true`, or a non-sensitive/non-auth-bound key.
- Group: L1 summary plus an L2 naming references and the shared invalidate-on-enrollment pattern.

```
{
  "id": "be-001",
  "description": "Finding (key not invalidated on new biometric enrollment): The key protecting the user's vault is auth-bound but generated with setInvalidatedByBiometricEnrollment(false), so a newly enrolled biometric can unlock it.",
  "reference": "jadx/sources/com/example/app/vault/VaultKey.java",
  "level": 1
},
{
  "id": "L2-be-flag",
  "description": "Unsafe flag (quoted): new KeyGenParameterSpec.Builder(\"vault_key\", PURPOSE_DECRYPT).setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(false)... at VaultKey.java:30-36 - auth-bound key NOT invalidated on enrollment change.",
  "reference": "jadx/sources/com/example/app/vault/VaultKey.java:30-36",
  "level": 2
},
{
  "id": "L2-be-data",
  "description": "Protected data (quoted): this key decrypts the vault contents (PII + stored passwords) at VaultRepo.java:60-66. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/vault/VaultRepo.java:60-66",
  "level": 2
},
{
  "id": "be-ok-001",
  "description": "Compliant: auth-bound key uses the default (invalidated on enrollment).",
  "reference": "jadx/sources/com/example/app/auth/AuthKey.java",
  "level": 1
},
{
  "id": "L2-be-ok",
  "description": "Default invalidation (quoted): the spec calls setUserAuthenticationRequired(true) and does NOT call setInvalidatedByBiometricEnrollment(false) at AuthKey.java:20-25 - default true; key invalidated on new enrollment.",
  "reference": "jadx/sources/com/example/app/auth/AuthKey.java:20-25",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0328",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K auth-bound key generations enumerated, S protecting sensitive data, N findings (setInvalidatedByBiometricEnrollment(false) on a sensitive auth-bound key), C compliant (default/true or non-sensitive), U unverified. Any auth-bound key generation? <no -> n/a / yes>. <one or two sentences naming each non-invalidated key and the data it protects>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 auth-bound key protecting sensitive data with (a) an L2 quoting `setInvalidatedByBiometricEnrollment(false)` AND (b) an L2 quoting the sensitive data it protects. A finding stated with "likely"/"may" instead of the quoted call is INVALID -> `unverified`.
- **Default is safe.** Absence of the call means `true` (invalidated) -> Compliant. Only an explicit `false` is the concern.
- **Auth-bound + sensitive.** The primary finding is on `setUserAuthenticationRequired(true)` keys protecting sensitive data; a `false` on a non-auth-bound or non-sensitive key is a noted lower-severity observation, not the core fail.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the flag false? is the key auth-bound and sensitive?) resolved by reading, unresolved -> `unverified`.
- `pass`: every auth-bound key protecting sensitive data is invalidated on enrollment (default/`true`), with L2 coverage.
- `n/a`: no auth-bound key generation appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its flag + protected-data L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) `setInvalidatedByBiometricEnrollment(false)` is quoted on the key spec; (2) the key is auth-bound (`setUserAuthenticationRequired(true)`) and the sensitive data it protects is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the key-spec search was performed (n/a / pass state it), every key's invalidation flag and protected data were read and quoted (unread -> `unverified`), no default/true key was miscounted as a Finding, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
