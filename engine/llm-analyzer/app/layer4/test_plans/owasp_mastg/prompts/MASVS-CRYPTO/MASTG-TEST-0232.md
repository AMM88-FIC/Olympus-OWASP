MASTG-TEST-0232

maswe_id       MASWE-0020
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Broken Symmetric Encryption Modes - ECB and other insecure block modes (static)

What this test looks for
The app must not configure symmetric block ciphers in a broken mode of operation - chiefly ECB, which is deterministic and leaks plaintext patterns. This is a static evaluation of every symmetric `Cipher` transformation string for a broken mode. Verdict: `pass` (symmetric ciphers use a secure mode - AEAD like GCM, or CBC/CTR with proper IV handling), `fail` (>=1 symmetric cipher uses ECB / an implicit-ECB default in a security-relevant context), `n/a` (the app performs no symmetric block-cipher encryption), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `Cipher.getInstance`. If NONE appear -> `n/a` (no cipher configuration to assess; state the search).

Broken modes (deny-list)
- **ECB** explicitly: `"AES/ECB/..."`, `"<cipher>/ECB/NoPadding"`, `"AES/ECB/PKCS5Padding"`, `"AES/ECB/ISO10126Padding"`.
- **Implicit ECB (default)**: a bare algorithm transform with no mode - `Cipher.getInstance("AES")`, `Cipher.getInstance("DES")` - defaults to ECB. Treat as ECB.
- Secure modes (allow): GCM (AEAD, preferred), CBC / CTR / CFB / OFB (acceptable mode-wise here; IV uniqueness is MASTG-TEST-0309's scope, MAC pairing is broader CRYPTO-1).

IMPORTANT - avoid the RSA false positive
In `"RSA/ECB/OAEPPadding"` / `"RSA/ECB/PKCS1Padding"`, the `ECB` token is a JCA placeholder - **RSA does not use block modes like ECB**. RSA transforms are NOT a finding for this test (asymmetric is out of scope). Only flag ECB on SYMMETRIC block ciphers (AES, DES, DESede, Blowfish, etc.).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the transformation string showing the broken mode (or the bare-algorithm default), and confirm a symmetric block cipher in a security-relevant use. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual `getInstance(...)`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the ECB/implicit-ECB transform and its use for encryption/decryption of sensitive data. "probably ECB" is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the transform is computed/obfuscated and can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate cipher sites: `grep -rEn "Cipher\.getInstance" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each, resolve the transformation string (resolve constants/finals; obfuscated/runtime-computed -> `unverified`). Identify the cipher and the mode.
3. Flag a finding only when the cipher is a SYMMETRIC block cipher AND the mode is ECB or an implicit default (bare algorithm). Skip RSA/EC transforms (placeholder ECB - not a finding). Confirm the cipher protects sensitive data. Quote the transform + the data.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (symmetric ECB / implicit-ECB quoted + security-relevant use); Compliant (secure mode, or RSA placeholder-ECB, quoted); Unverified (transform unresolved / use not security-relevant).
6. Budget ~2-3 reads per site (the getInstance, the key/cipher object, the data). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Crypto inside native code or a no-source SDK -> `unverified` (name the entry point). The symmetric algorithm itself (DES/RC4) is MASTG-TEST-0221; IV reuse is MASTG-TEST-0309; key size is MASTG-TEST-0208. This test judges the MODE of symmetric block ciphers only, and explicitly excludes the RSA `ECB` placeholder.

Output
List **all** symmetric `Cipher` sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant secure-mode sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the ECB/implicit-ECB transform and the security-relevant use (the data it protects), plus owner.
- Compliant: L1 row plus an L2 quoting the secure mode (or noting an RSA placeholder-ECB that is not a finding).
- Group: L1 summary plus an L2 naming references and the shared secure mode.

```
{
  "id": "bm-001",
  "description": "Finding (broken mode - ECB): The app encrypts session data with AES in ECB mode, which leaks plaintext patterns across blocks.",
  "reference": "jadx/sources/com/example/app/SessionCrypto.java",
  "level": 1
},
{
  "id": "L2-bm-mode",
  "description": "Broken mode (quoted): Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\"); at SessionCrypto.java:28 - AES/ECB, deterministic block mode.",
  "reference": "jadx/sources/com/example/app/SessionCrypto.java:28",
  "level": 2
},
{
  "id": "L2-bm-use",
  "description": "Security-relevant use (quoted): c.init(ENCRYPT_MODE, key); byte[] out = c.doFinal(session.toBytes()) at lines 30-32 - encrypts session material. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/SessionCrypto.java:30-32",
  "level": 2
},
{
  "id": "bm-002",
  "description": "Finding (implicit ECB default): Cipher.getInstance(\"AES\") with no mode defaults to AES/ECB.",
  "reference": "jadx/sources/com/example/app/Quick.java",
  "level": 1
},
{
  "id": "L2-bm-default",
  "description": "Implicit ECB (quoted): Cipher.getInstance(\"AES\") at Quick.java:15 - bare algorithm defaults to ECB; used to encrypt the stored auth token at lines 17-19. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Quick.java:15-19",
  "level": 2
},
{
  "id": "bm-ok-001",
  "description": "Not a finding (RSA placeholder ECB): Cipher.getInstance(\"RSA/ECB/OAEPPadding\") - RSA does not use block ECB; the token is a JCA placeholder.",
  "reference": "jadx/sources/com/example/app/RsaWrap.java:22",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0232",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "C Cipher sites enumerated, B symmetric block-cipher sites, N findings (explicit ECB / implicit-ECB default), K compliant (secure mode), X RSA placeholder-ECB excluded, U unverified. Any cipher present? <no -> n/a / yes>. <one or two sentences naming each ECB site and the data it protects>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 SYMMETRIC block cipher quoted in ECB mode (explicit `"…/ECB/…"` or a bare-algorithm implicit default) used to encrypt/decrypt sensitive data. A finding stated with "likely"/"may" instead of the quoted transform is INVALID -> `unverified`.
- **RSA `ECB` is NOT a finding.** `"RSA/ECB/…"` is a JCA placeholder; asymmetric ciphers are out of scope. Excluding it correctly is required - flagging it makes the verdict `inconclusive`-worthy.
- **Mode only.** Broken algorithm (DES/RC4) is MASTG-TEST-0221; IV reuse is MASTG-TEST-0309; key size is MASTG-TEST-0208.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (what mode? symmetric or RSA? sensitive data?) resolved by reading, unresolved -> `unverified`.
- `pass`: every symmetric block cipher uses a secure mode, with L2 coverage (RSA placeholder-ECB noted but not counted as a finding).
- `n/a`: no `Cipher.getInstance` sites appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if an RSA placeholder-ECB was counted as a finding, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its transform + security-relevant-use L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the transformation string showing ECB / implicit-ECB is quoted; (2) the cipher is a SYMMETRIC block cipher (NOT RSA/EC); (3) the security-relevant use (sensitive data) is quoted; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`. RSA-placeholder scan: confirm no `"RSA/ECB/..."` site was counted as a finding.
Before any `pass`/`fail`/`n/a`: confirm the Cipher search was performed (n/a / pass state it), every symmetric block-cipher mode was read and quoted (unread -> `unverified`), RSA placeholder-ECB excluded, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
