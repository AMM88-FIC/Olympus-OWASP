MASTG-TEST-0308

maswe_id       MASWE-0012
masvs_v2_id    MASVS-CRYPTO-2
platform       android
title          Runtime Use of Asymmetric Key Pairs Used For Multiple Purposes - cross-purpose key use (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0308 is a dynamic test (hook `Cipher.init`, `Signature.initSign`/`initVerify` at runtime and observe each key used across encryption, signing, and key-wrapping operations). This static engine cannot intercept runtime crypto calls, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0307 (KeyGenParameterSpec authorized-purposes), EXTENDED to also trace, where statically visible, the actual operations each key reaches (`Cipher.init` ENCRYPT/DECRYPT/WRAP/UNWRAP vs `Signature.initSign`/`initVerify`). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the static verdict is indicative only and must be confirmed at runtime (a key may be reused across purposes only on a path not statically resolved).

What this test looks for
A single asymmetric key (or key pair) must be used for exactly ONE role: Encryption/Decryption (`Cipher` ENCRYPT_MODE/DECRYPT_MODE), Signing/Verification (`Signature`), or Key-wrapping (`Cipher` WRAP_MODE/UNWRAP_MODE). This static approximation traces each key from generation/import to every USE SITE and flags any key reaching operations in more than one role group, plus any over-broad `KeyGenParameterSpec` purposes (as in 0307). Verdict: `pass` (each key reaches only one role group, and purposes are single-group), `fail` (>=1 key is used across - or authorized for - multiple role groups), `n/a` (the app performs no asymmetric key operations), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for asymmetric key generation/use APIs (below). If NONE appear -> `n/a` (no asymmetric key operations to assess; state the search).

Role groups (a key must stay within one)
- Encryption/Decryption: `Cipher.init(ENCRYPT_MODE|DECRYPT_MODE, key, ...)`.
- Signing/Verification: `Signature.initSign(privateKey)` / `Signature.initVerify(publicKey)`.
- Key wrapping: `Cipher.init(WRAP_MODE|UNWRAP_MODE, key, ...)`.
Also: an over-broad `KeyGenParameterSpec` purposes bitmask spanning groups (1|2|4|8 etc.) is itself a finding even before a runtime use is seen (decode the integer; see MASTG-TEST-0307 for values).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the key (alias/variable, where generated/imported) AND each distinct-group operation it reaches (or the multi-group purposes bitmask). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual key and each use site, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the SAME key reaching two distinct role groups, OR a multi-group purposes bitmask. "the key might also be used to sign" is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If a key's identity across use sites or an operation's mode can't be resolved within budget, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Sinks (key use sites)
`Cipher.init(int opmode, Key key, ...)` with `opmode` = ENCRYPT_MODE(1)/DECRYPT_MODE(2)/WRAP_MODE(3)/UNWRAP_MODE(4); `Signature.initSign(PrivateKey)` / `Signature.initVerify(PublicKey)`. Plus `KeyGenParameterSpec` purposes as in 0307. Trace key identity by alias (`KeyStore.getEntry("alias")`) or by the variable/field holding the `Key`/`KeyPair`/`PrivateKey`/`PublicKey`.

Procedure
1. Enumerate: `grep -rEn "KeyPairGenerator|KeyGenParameterSpec|getEntry|getKey\(|PrivateKey|PublicKey|Signature\.getInstance|initSign|initVerify|Cipher\.init" jadx/sources/`. If no asymmetric key operations -> short-circuit `n/a` (state the search).
2. For each asymmetric key (by alias or holding variable/field), collect every use site and classify the operation's role group (Cipher opmode vs Signature). Quote each use.
3. Decide: a key reaching only one role group -> Compliant; a key reaching two or more groups -> finding (cross-purpose use). Independently, decode each `KeyGenParameterSpec` purposes bitmask - multi-group authorization -> finding (as 0307). Quote the key + the spanning operations/bitmask.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per key: Finding (same key across >1 role group, or multi-group purposes); Compliant (single role group + single-group purposes); Unverified (key identity / opmode unresolved).
6. Budget ~3-5 reads per key (generation, each use site, 1-2 call-graph hops to confirm same key). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Key use inside native code or a no-source SDK -> `unverified` (name the entry point). Static reachability cannot prove a key is NEVER reused on an unobserved path - hence the forced `needs_dynamic_testing`. Symmetric keys are out of scope.

Output
List **all** asymmetric keys - one L1 row per key with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant single-purpose keys by area as one L1 row per group, but always break out every Finding and unverified key individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the key and each distinct-group use site (or the decoded multi-group purposes bitmask), plus owner.
- Compliant: L1 row plus an L2 showing the key's single role group (or single-group purposes).
- Group: L1 summary plus an L2 naming references and the shared single-purpose pattern.

```
{
  "id": "xp-001",
  "description": "Finding (cross-purpose key use): The same keystore RSA key is used both to decrypt data (Cipher DECRYPT_MODE) and to sign requests (Signature.initSign) - one key spanning the Encryption and Signing role groups.",
  "reference": "jadx/sources/com/example/app/KeyOps.java",
  "level": 1
},
{
  "id": "L2-xp-key",
  "description": "Key identity (quoted): PrivateKey pk = (PrivateKey) keyStore.getKey(\"app_rsa\", null); at KeyOps.java:30 - single keystore key, alias \"app_rsa\".",
  "reference": "jadx/sources/com/example/app/KeyOps.java:30",
  "level": 2
},
{
  "id": "L2-xp-use1",
  "description": "Role group 1 - Decryption (quoted): Cipher c = Cipher.getInstance(\"RSA/ECB/OAEPPadding\"); c.init(Cipher.DECRYPT_MODE, pk); at lines 33-35.",
  "reference": "jadx/sources/com/example/app/KeyOps.java:33-35",
  "level": 2
},
{
  "id": "L2-xp-use2",
  "description": "Role group 2 - Signing (quoted): Signature s = Signature.getInstance(\"SHA256withRSA\"); s.initSign(pk); at lines 41-43 - SAME key \"app_rsa\" now signing. Cross-purpose use. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/KeyOps.java:41-43",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0308",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K asymmetric keys enumerated, N findings (same key across >1 role group, or multi-group purposes), C compliant (single group), U unverified. Any asymmetric key operations present? <no -> n/a / yes>. <one or two sentences naming each cross-purpose key and the spanning operations>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 key with either (a) L2 rows quoting the SAME key reaching two distinct role groups (Cipher enc/dec vs Signature vs Cipher wrap/unwrap), or (b) a quoted+decoded multi-group `KeyGenParameterSpec` purposes bitmask. A finding stated with "likely"/"may" instead of the quoted key+operations is INVALID -> `unverified`.
- **Same key, two groups.** The two use sites must be shown to use the SAME key (same alias / same holding variable traced). Two different keys each in one group is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (same key? which opmode?) resolved by reading, unresolved -> `unverified`.
- `pass`: every asymmetric key reaches only one role group and authorizes only one group, with L2 coverage.
- `n/a`: no asymmetric key operations appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if a cross-purpose claim does not show the two uses share one key, if a bitmask was flagged without decoding, if any false_positive_risk references in-APK code, or if any `fail` lacks its key + spanning-operation L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the key is quoted and its identity (alias/variable) fixed; (2) two distinct-group operations on that SAME key are quoted, OR the multi-group purposes bitmask is quoted+decoded; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the asymmetric-key search was performed (n/a / pass state it), every key's use sites were read and quoted (unread -> `unverified`), each cross-purpose finding shows one shared key, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
