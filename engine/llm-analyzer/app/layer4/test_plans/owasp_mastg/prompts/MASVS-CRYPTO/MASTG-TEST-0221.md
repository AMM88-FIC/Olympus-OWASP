MASTG-TEST-0221

maswe_id       MASWE-0020
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Broken Symmetric Encryption Algorithms - deprecated/insecure ciphers (static)

What this test looks for
The app must not use broken or deprecated symmetric encryption algorithms to protect data. This is a static evaluation of every symmetric cipher/key-factory/key-generator transformation string for a broken primitive. Verdict: `pass` (only strong symmetric primitives - AES, ChaCha20 - are used), `fail` (>=1 broken primitive is used in a security-relevant context), `n/a` (the app performs no symmetric cryptography), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the cipher APIs below. If NONE appear -> `n/a` (no symmetric crypto to assess; state the search).

Broken symmetric primitives (deny-list)
- **DES** (`"DES"`, `DESKeySpec`) - 56-bit, withdrawn by NIST (2005).
- **3DES / DESede / TripleDES** - 64-bit block, Sweet32, withdrawn by NIST (2024).
- **RC4 / ARCFOUR** - predictable keystream, prohibited (IETF RFC 7465).
- **Blowfish** - 64-bit block, Sweet32, never FIPS-approved.
- **RC2**, and any other primitive not on the strong list when used for confidentiality of sensitive data.
Strong (allow): **AES** (any approved mode - mode brokenness like ECB is MASTG-TEST-0232's scope, NOT this test), **ChaCha20** / ChaCha20-Poly1305.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the transformation string / algorithm argument naming the broken primitive, and confirm a security-relevant use. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual `getInstance(...)` call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the broken-algorithm string and its use for encryption/decryption of sensitive data. "might use DES" is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the algorithm argument is computed/obfuscated and can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Cipher/algorithm sinks
`Cipher.getInstance(transform)`, `SecretKeyFactory.getInstance(alg)`, `KeyGenerator.getInstance(alg)`, `SecretKeySpec(bytes, alg)`, `DESKeySpec`/`DESedeKeySpec`. The algorithm is the first token of the transformation (`"DES/CBC/PKCS5Padding"` -> DES; `"AES/ECB/..."` -> AES, strong primitive but see 0232 for the mode).

Procedure
1. Enumerate cipher sites: `grep -rEn "Cipher\.getInstance|SecretKeyFactory\.getInstance|KeyGenerator\.getInstance|SecretKeySpec|DESKeySpec|DESedeKeySpec|getInstance\(\"(DES|DESede|TripleDES|RC4|ARCFOUR|RC2|Blowfish)" jadx/sources/`. If no symmetric crypto -> short-circuit `n/a` (state the search).
2. For each site, resolve the algorithm token (resolve constants/finals; obfuscated/runtime-computed -> `unverified`). Match against the deny-list.
3. For each broken-primitive site, confirm it performs encryption/decryption of sensitive data (a security-relevant context). Quote the transform + the data. Strong primitive -> Compliant (mode issues belong to 0232).
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A broken primitive inside a third-party SDK protecting app data is reported.
5. Conclude per site: Finding (broken primitive quoted + security-relevant use); Compliant (strong primitive, quoted); Unverified (algorithm unresolved / use not security-relevant).
6. Budget ~2-3 reads per site (the getInstance, the key, the data it protects). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Crypto inside native code or a no-source SDK -> `unverified` (name the entry point). Mode/padding brokenness (ECB) is MASTG-TEST-0232; key SIZE is MASTG-TEST-0208; this test judges the symmetric ALGORITHM only. Asymmetric algorithms (RSA/EC) are out of scope here.

Output
List **all** symmetric cipher/key sites - one L1 row per site (or per primitive) with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant AES/ChaCha20 sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the broken-algorithm transform and the security-relevant use (the data it protects), plus owner.
- Compliant: L1 row plus an L2 quoting the strong primitive.
- Group: L1 summary plus an L2 naming references and the shared strong primitive.

```
{
  "id": "ba-001",
  "description": "Finding (broken symmetric algorithm): The app encrypts cached PII with DES, a 56-bit cipher withdrawn by NIST.",
  "reference": "jadx/sources/com/example/app/Cache.java",
  "level": 1
},
{
  "id": "L2-ba-algo",
  "description": "Broken algorithm (quoted): Cipher c = Cipher.getInstance(\"DES/CBC/PKCS5Padding\"); SecretKeySpec k = new SecretKeySpec(keyBytes, \"DES\"); at Cache.java:44-47 - DES (56-bit), deprecated.",
  "reference": "jadx/sources/com/example/app/Cache.java:44-47",
  "level": 2
},
{
  "id": "L2-ba-use",
  "description": "Security-relevant use (quoted): c.init(ENCRYPT_MODE, k); byte[] enc = c.doFinal(profileJson.getBytes()) at lines 49-51 - encrypts the user profile (PII). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Cache.java:49-51",
  "level": 2
},
{
  "id": "ba-ok-group",
  "description": "Compliant group: 3 Cipher sites using AES (strong primitive; mode reviewed under MASTG-TEST-0232).",
  "reference": "jadx/sources/com/example/app/crypto/",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0221",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S symmetric cipher/key sites enumerated, N findings (broken primitive: DES/3DES/RC4/Blowfish/RC2), C compliant (AES/ChaCha20), U unverified. Any symmetric crypto present? <no -> n/a / yes>. <one or two sentences naming each broken primitive and the data it protects>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 site quoting a broken symmetric primitive (DES/3DES/DESede/RC4/ARCFOUR/Blowfish/RC2) used to encrypt/decrypt sensitive data. A finding stated with "likely"/"may" instead of the quoted transform is INVALID -> `unverified`.
- **Algorithm only.** AES with a bad mode (ECB) is NOT this test's finding - that is MASTG-TEST-0232. Short key sizes are MASTG-TEST-0208. Keep scope tight.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (which algorithm? is the data sensitive?) resolved by reading, unresolved -> `unverified`. Reject "the algorithm string might differ at runtime".
- `pass`: only strong symmetric primitives (AES/ChaCha20) are used, with L2 coverage.
- `n/a`: no symmetric cipher/key APIs appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its transform + security-relevant-use L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the transformation string naming the broken primitive is quoted; (2) the security-relevant use (the sensitive data it protects) is quoted; (3) the issue is the ALGORITHM (not the mode/size, which are other tests); (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the cipher search was performed (n/a / pass state it), every broken-primitive site's algorithm and use were read and quoted (unread -> `unverified`), no AES-mode issue was miscounted here, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
