MASTG-TEST-0307

maswe_id       MASWE-0012
masvs_v2_id    MASVS-CRYPTO-2
platform       android
title          References to Asymmetric Key Pairs Used For Multiple Purposes - over-broad KeyGenParameterSpec purposes (static)

What this test looks for
Per NIST SP 800-57, a cryptographic key should serve ONE purpose. On Android, asymmetric keys are generated with `KeyPairGenerator` configured by `KeyGenParameterSpec.Builder(alias, purposes)`, where `purposes` is a bitmask of `KeyProperties.PURPOSE_*`. A key pair authorized for multiple distinct roles (e.g. both encryption AND signing) violates key separation. This is a static evaluation of every `KeyGenParameterSpec` purpose bitmask. Verdict: `pass` (every asymmetric key pair is restricted to exactly one role group), `fail` (>=1 key pair authorizes purposes spanning more than one role group), `n/a` (the app generates no AndroidKeyStore asymmetric keys via `KeyGenParameterSpec`), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `KeyGenParameterSpec`. If NONE appear -> `n/a` (no keystore key generation to assess; state the search).

PURPOSE constants and the allowed role groups
Bit values: `PURPOSE_ENCRYPT = 1`, `PURPOSE_DECRYPT = 2`, `PURPOSE_SIGN = 4`, `PURPOSE_VERIFY = 8`, `PURPOSE_WRAP_KEY = 32`. In decompiled code these appear as the combined INTEGER (the `setPurposes`/constructor argument). A key is COMPLIANT only if its purposes fall within exactly ONE of these role groups:
- Encryption/Decryption: `ENCRYPT` and/or `DECRYPT` -> allowed values 1, 2, 3 (1|2).
- Signing/Verification: `SIGN` and/or `VERIFY` -> allowed values 4, 8, 12 (4|8).
- Key wrapping: `WRAP_KEY` -> allowed value 32.
A finding is any bitmask mixing groups, e.g. `15` (1|2|4|8 = encrypt+decrypt+sign+verify), `5` (1|4 = encrypt+sign), `7`, `13`, `33` (1|32), etc. Decode the integer to the constituent purposes and name the groups it spans.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `KeyGenParameterSpec.Builder(alias, purposes)` / `setPurposes(...)` with the purpose integer or `PURPOSE_*` constants, and the key alias/algorithm. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual Builder call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the purpose bitmask spanning >1 role group. "might allow signing too" is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the purposes argument is computed and can't be decoded, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Sinks
`new KeyGenParameterSpec.Builder(keystoreAlias, purposes)`, chained `.setPurposes(int)`, the resulting spec passed to `KeyPairGenerator.initialize(spec)` for an asymmetric algorithm (RSA/EC). (Symmetric `KeyGenerator` keys are not the focus of this OWASP test; concentrate on asymmetric key pairs.)

Procedure
1. Enumerate generation sites: `grep -rEn "KeyGenParameterSpec|setPurposes|PURPOSE_(ENCRYPT|DECRYPT|SIGN|VERIFY|WRAP_KEY)" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each `KeyGenParameterSpec` that configures an ASYMMETRIC key pair (RSA/EC), resolve the purpose bitmask (decode the integer or OR the named constants). Resolve finals; computed/obfuscated -> `unverified`.
3. Decide: purposes within one role group -> Compliant; purposes spanning two or more groups -> finding. Decode the integer and name the spanned groups. Quote the bitmask + alias.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A multi-purpose key created inside a third-party SDK is attributed but reported.
5. Conclude per key: Finding (multi-group bitmask quoted + decoded); Compliant (single-group purposes quoted); Unverified (purposes not decodable / algorithm unclear).
6. Budget ~2-3 reads per key (the Builder, the purposes constant, the initialize). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Key generation inside native code or a no-source SDK -> `unverified` (name the entry point). The DYNAMIC counterpart - keys actually USED across multiple operations at runtime - is MASTG-TEST-0308. This static test judges the authorized PURPOSES bitmask at generation only.

Output
List **all** asymmetric `KeyGenParameterSpec` sites - one L1 row per key with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant single-purpose keys by area as one L1 row per group, but always break out every Finding and unverified key individually. Never sample findings.
- Finding: L1 row plus an L2 quoting the purposes bitmask, its decoded purposes, the spanned role groups, and the alias/algorithm, plus owner.
- Compliant: L1 row plus an L2 quoting the single-group purposes.
- Group: L1 summary plus an L2 naming references and the shared single-purpose pattern.

```
{
  "id": "kp-001",
  "description": "Finding (multi-purpose asymmetric key): A keystore RSA key pair is authorized for encryption, decryption, signing and verification (purposes = 15), mixing the Encryption and Signing role groups.",
  "reference": "jadx/sources/com/example/app/KeyFactoryX.java",
  "level": 1
},
{
  "id": "L2-kp-purposes",
  "description": "Over-broad purposes (quoted): new KeyGenParameterSpec.Builder(\"app_rsa\", 15) ... at KeyFactoryX.java:40-46 - 15 = PURPOSE_ENCRYPT(1)|PURPOSE_DECRYPT(2)|PURPOSE_SIGN(4)|PURPOSE_VERIFY(8); spans Encryption/Decryption AND Signing/Verification groups. Key alias \"app_rsa\", RSA 2048 (initialize at line 48). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/KeyFactoryX.java:40-48",
  "level": 2
},
{
  "id": "kp-ok-001",
  "description": "Compliant: signing key pair restricted to SIGN|VERIFY only.",
  "reference": "jadx/sources/com/example/app/SignKey.java",
  "level": 1
},
{
  "id": "L2-kp-ok",
  "description": "Single-group purposes (quoted): new KeyGenParameterSpec.Builder(\"sign_key\", KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY) at SignKey.java:20-22 - 4|8 = 12, Signing/Verification group only.",
  "reference": "jadx/sources/com/example/app/SignKey.java:20-22",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0307",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K asymmetric KeyGenParameterSpec keys enumerated, N findings (purposes spanning >1 role group), C compliant (single group), U unverified. Any keystore key generation present? <no -> n/a / yes>. <one or two sentences naming each multi-purpose key, its decoded bitmask and spanned groups>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 asymmetric key pair whose quoted purposes bitmask spans more than one role group (Encryption/Decryption vs Signing/Verification vs Key-wrapping). The bitmask MUST be decoded to its constituent purposes in the L2. A finding stated with "likely"/"may" instead of the quoted+decoded bitmask is INVALID -> `unverified`.
- **Decode the integer.** Decompiled code shows the combined integer (e.g. 15); the L2 must show the OR-decomposition and the groups it crosses. Acceptable single-group values: 1, 2, 3, 4, 8, 12, 32.
- **Static authorization only.** Runtime cross-use is MASTG-TEST-0308. Symmetric keys are out of scope.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (what is the bitmask? is the key asymmetric?) resolved by reading, unresolved -> `unverified`.
- `pass`: every asymmetric key pair is restricted to exactly one role group, with L2 coverage.
- `n/a`: no `KeyGenParameterSpec` sites appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if a bitmask was flagged without being decoded, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its quoted+decoded purposes L2 row.

Self-check before emitting (per finding)
For every Finding confirm: (1) the purposes bitmask is quoted; (2) it is decoded to its constituent `PURPOSE_*` and shown to span >1 role group; (3) the key is asymmetric (RSA/EC) and the alias/algorithm named; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the KeyGenParameterSpec search was performed (n/a / pass state it), every key's purposes were read and decoded (undecoded -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
