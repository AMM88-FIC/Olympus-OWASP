MASTG-TEST-0350

maswe_id       MASWE-0020
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Runtime Use of Broken Symmetric Encryption Modes - ECB at runtime (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0350 is a dynamic test (hook cipher-configuration APIs at runtime, capture the transformation string actually passed to `Cipher.getInstance`, and inspect backtraces to confirm the data is sensitive). This static engine cannot hook the running app, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0232 (symmetric block-cipher mode, ECB / implicit-ECB default, excluding the RSA `ECB` placeholder). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the static verdict is indicative only and must be confirmed at runtime (the transformation string may be assembled at runtime on a path not statically resolved).

What this test looks for
The running app must not configure symmetric block ciphers in a broken mode (chiefly ECB) for security-relevant operations. This static approximation evaluates every symmetric `Cipher` transformation string for ECB / an implicit-ECB default, INCLUDING transforms assembled from constants/config where the value can be resolved statically. Verdict: `pass` (symmetric ciphers use a secure mode), `fail` (>=1 symmetric cipher uses ECB / implicit-ECB in a security-relevant context), `n/a` (the app performs no symmetric block-cipher encryption), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `Cipher.getInstance`. If NONE appear -> `n/a` (no cipher configuration to assess; state the search).

Broken modes (deny-list)
- **ECB** explicitly: `"AES/ECB/..."`, `"<symmetric>/ECB/..."`.
- **Implicit ECB**: a bare algorithm transform with no mode (`Cipher.getInstance("AES")`) defaults to ECB - treat as ECB.
Secure modes (allow): GCM (AEAD, preferred), CBC/CTR/CFB/OFB (mode-wise acceptable here; IV uniqueness is MASTG-TEST-0309).

IMPORTANT - avoid the RSA false positive
`"RSA/ECB/OAEPPadding"` / `"RSA/ECB/PKCS1Padding"` - the `ECB` token is a JCA placeholder; RSA does NOT use block ECB. RSA transforms are NOT a finding. Flag ECB only on SYMMETRIC block ciphers (AES, DES, DESede, Blowfish, ...).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the transformation string (or the resolved assembled value) showing the broken mode, plus a symmetric block cipher in a security-relevant use. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual `getInstance(...)`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the ECB/implicit-ECB transform and its use to encrypt/decrypt sensitive data. "probably ECB at runtime" with no resolved string is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the transform is assembled at runtime from values that cannot be resolved statically, the row is `unverified` (and the forced `needs_dynamic_testing` flags it for hooking). `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate cipher sites: `grep -rEn "Cipher\.getInstance" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each, resolve the transformation string - including transforms built from `String` constants/config where resolvable. Identify cipher + mode. Unresolvable runtime-assembled transform -> `unverified`.
3. Flag a finding only when the cipher is SYMMETRIC AND the mode is ECB or an implicit default, AND it protects sensitive data. Skip RSA/EC transforms. Quote the transform + the data.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (symmetric ECB / implicit-ECB quoted + security-relevant use); Compliant (secure mode, or RSA placeholder-ECB, quoted); Unverified (transform unresolved / use not security-relevant).
6. Budget ~2-3 reads per site (the getInstance, the key/cipher object, the data). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Crypto inside native code or a no-source SDK -> `unverified` (name the entry point). Algorithm brokenness (DES/RC4) is MASTG-TEST-0221; IV reuse is MASTG-TEST-0309; key size is MASTG-TEST-0208. This test judges the MODE of symmetric block ciphers only and excludes the RSA `ECB` placeholder. Runtime-only transform assembly is the dynamic test's domain - flagged via the forced `needs_dynamic_testing`.

Output
List **all** symmetric `Cipher` sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant secure-mode sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the ECB/implicit-ECB transform and the security-relevant use, plus owner.
- Compliant: L1 row plus an L2 quoting the secure mode (or noting an RSA placeholder-ECB that is not a finding).
- Group: L1 summary plus an L2 naming references and the shared secure mode.

```
{
  "id": "rm-001",
  "description": "Finding (broken mode - ECB): The app encrypts cardholder data with AES/ECB, leaking plaintext block patterns.",
  "reference": "jadx/sources/com/example/app/PayCrypto.java",
  "level": 1
},
{
  "id": "L2-rm-mode",
  "description": "Broken mode (quoted): String t = \"AES/ECB/\" + PAD; Cipher c = Cipher.getInstance(t); with PAD = \"PKCS5Padding\" (constant at line 12) -> \"AES/ECB/PKCS5Padding\" at PayCrypto.java:40-43 - AES/ECB resolved statically.",
  "reference": "jadx/sources/com/example/app/PayCrypto.java:40-43",
  "level": 2
},
{
  "id": "L2-rm-use",
  "description": "Security-relevant use (quoted): c.init(ENCRYPT_MODE, key); byte[] out = c.doFinal(pan.getBytes()) at lines 45-47 - encrypts the card PAN. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/PayCrypto.java:45-47",
  "level": 2
},
{
  "id": "rm-ok-001",
  "description": "Not a finding (RSA placeholder ECB): Cipher.getInstance(\"RSA/ECB/OAEPPadding\") - RSA does not use block ECB.",
  "reference": "jadx/sources/com/example/app/RsaWrap.java:22",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0350",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "C Cipher sites enumerated, B symmetric block-cipher sites, N findings (explicit/implicit ECB), K compliant (secure mode), X RSA placeholder-ECB excluded, U unverified (incl. runtime-assembled transforms). Any cipher present? <no -> n/a / yes>. <one or two sentences naming each ECB site and the data it protects>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 SYMMETRIC block cipher quoted (or statically resolved) in ECB / implicit-ECB used to encrypt/decrypt sensitive data. A finding stated with "likely"/"may" and no resolved transform is INVALID -> `unverified`.
- **RSA `ECB` is NOT a finding.** Excluding it correctly is required; counting it makes the verdict `inconclusive`-worthy.
- **Mode only.** Algorithm (DES/RC4) is 0221; IV reuse is 0309; key size is 0208.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (what mode? symmetric? sensitive data?) resolved by reading, unresolved -> `unverified`.
- `pass`: every symmetric block cipher uses a secure mode, with L2 coverage (RSA placeholder-ECB noted, not counted).
- `n/a`: no `Cipher.getInstance` sites appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point, or a runtime-assembled transform). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if an RSA placeholder-ECB was counted as a finding, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its transform + security-relevant-use L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the transformation string showing ECB / implicit-ECB is quoted (or its statically resolved value shown); (2) the cipher is SYMMETRIC (NOT RSA/EC); (3) the security-relevant use (sensitive data) is quoted; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`. RSA-placeholder scan: confirm no `"RSA/ECB/..."` site was counted as a finding.
Before any `pass`/`fail`/`n/a`: confirm the Cipher search was performed (n/a / pass state it), every symmetric block-cipher mode was read and resolved (unresolved runtime-assembled -> `unverified`), RSA placeholder-ECB excluded, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
