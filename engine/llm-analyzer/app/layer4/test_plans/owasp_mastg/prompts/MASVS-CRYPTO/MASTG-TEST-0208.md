MASTG-TEST-0208

maswe_id       MASWE-0009
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Insufficient Key Sizes - cryptographic keys generated below the modern minimum (static)

What this test looks for
Cryptographic keys must be generated at a length that is still considered strong. The app must not generate keys below the accepted minimums for their algorithm family. This is a static evaluation of every key-generation site and its declared/derived key length. Verdict: `pass` (all generated keys meet the minimums, or key sizes are the algorithm defaults that are adequate), `fail` (>=1 key is generated below the minimum for its algorithm in a security-relevant context), `n/a` (the app generates no cryptographic keys), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the key-generation APIs below. If NONE appear -> `n/a` (no key generation to assess; state the search).

Minimums (baseline)
- **Symmetric (AES, ChaCha20)**: AES key >= 128 bits is acceptable; AES-256 preferred. AES key < 128 (e.g. an explicit `init(64)`/`init(96)`) -> finding. Keys for broken primitives (DES 56, 3DES, RC4, Blowfish) are out of scope here (algorithm choice is covered by MASTG-TEST-0221); a too-short AES/ChaCha key IS in scope.
- **RSA / DSA / DH**: modulus >= 2048 bits. `KeyPairGenerator("RSA").initialize(1024)` (or 512) -> finding. 2048 is the floor; 3072+ preferred.
- **EC (ECDSA/ECDH)**: curve >= 224-bit (P-256 / secp256r1 and above acceptable); a named curve below 224 bits (e.g. secp192r1, secp160r1) -> finding.
- A `KeyGenerator`/`KeyPairGenerator` that relies on the platform DEFAULT size (no explicit `init`/`initialize`) is adequate unless the default for that algorithm is itself sub-baseline; state the default you assume.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the key-generation call AND the size argument (or the named curve), and enough context to confirm it is a security-relevant key. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual `init`/`initialize` call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the generation call with its sub-baseline size. "probably uses a short key" is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the size argument can't be resolved (computed at runtime, read from config) or the key's security-relevance is unclear, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Key-generation sinks
`KeyGenerator.getInstance(alg)` + `init(int keysize)` (symmetric), `KeyPairGenerator.getInstance(alg)` + `initialize(int keysize)` or `initialize(ECGenParameterSpec)` (asymmetric), `KeyGenParameterSpec.Builder(...).setKeySize(int)` (AndroidKeyStore), `SecretKeySpec(byte[] key, alg)` where the byte[] length pins the size, `ECGenParameterSpec("secpXXXr1"/"primeXXXv1")` naming a curve.

Procedure
1. Enumerate generation sites: `grep -rEn "KeyGenerator|KeyPairGenerator|KeyGenParameterSpec|setKeySize|\.initialize\(|ECGenParameterSpec|SecretKeySpec" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each site, read the algorithm and the size argument (or named curve, or the byte[] length for `SecretKeySpec`). Resolve constants/finals; a size read from config/runtime that can't be pinned -> `unverified`.
3. Compare against the minimums above. Below minimum in a security-relevant context -> finding; at/above minimum, or adequate default -> Compliant. Quote the size.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A short key generated inside a third-party SDK for its own use is attributed but reported.
5. Conclude per site: Finding (sub-baseline size quoted); Compliant (>= minimum, or adequate default, quoted); Unverified (size not resolvable / security-relevance unclear).
6. Budget ~2-3 reads per site (the generation call, the algorithm, any constant holding the size). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Key generation inside native code or a no-source SDK -> `unverified` (name the entry point). Algorithm choice/brokenness is covered by MASTG-TEST-0221; here only the SIZE is assessed. A size computed entirely at runtime that cannot be pinned -> `unverified`.

Output
List **all** key-generation sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant generations by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus an L2 quoting the generation call and the sub-baseline size/curve, plus owner.
- Compliant: L1 row plus an L2 quoting the size/curve at or above the minimum (or the adequate default).
- Group: L1 summary plus an L2 naming references and the shared adequate size.

```
{
  "id": "ks-001",
  "description": "Finding (insufficient RSA key size): The app generates a 1024-bit RSA key pair, below the 2048-bit modern minimum, in a signing context.",
  "reference": "jadx/sources/com/example/app/KeyManager.java",
  "level": 1
},
{
  "id": "L2-ks-gen",
  "description": "Sub-baseline generation (quoted): KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\"); kpg.initialize(1024); at KeyManager.java:40-42 - 1024-bit RSA < 2048-bit minimum. Key used to sign auth requests (lines 48-52). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/KeyManager.java:40-42",
  "level": 2
},
{
  "id": "ks-ok-001",
  "description": "Compliant: AES key generated at 256 bits.",
  "reference": "jadx/sources/com/example/app/CryptoBox.java",
  "level": 1
},
{
  "id": "L2-ks-ok",
  "description": "Adequate size (quoted): KeyGenerator kg = KeyGenerator.getInstance(\"AES\"); kg.init(256); at CryptoBox.java:22-24 - 256-bit AES, above the 128-bit minimum.",
  "reference": "jadx/sources/com/example/app/CryptoBox.java:22-24",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0208",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "G key-generation sites enumerated, N findings (sub-baseline size/curve), C compliant, U unverified. Any key generation present? <no -> n/a / yes>. <one or two sentences naming each undersized key, its algorithm and size>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 key-generation site quoted with a size below the minimum for its algorithm family (AES < 128, RSA/DSA/DH < 2048, EC < 224) in a security-relevant context. A finding stated with "likely"/"may" instead of the quoted size is INVALID -> `unverified`.
- **Size only.** Algorithm brokenness (DES/3DES/RC4) is MASTG-TEST-0221's scope; mode/padding is MASTG-TEST-0232's. Here only the key LENGTH/curve is judged.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (what size? which algorithm?) resolved by reading, unresolved -> `unverified`. Reject "the size might be larger at runtime".
- `pass`: all generated keys meet the minimums (or use adequate defaults), with L2 coverage.
- `n/a`: no key-generation APIs appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its quoted generation call + size.

Self-check before emitting (per finding)
For every Finding confirm: (1) the generation call is quoted; (2) the size/curve is quoted and named below the minimum for that algorithm; (3) the key is security-relevant; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the generation search was performed (n/a / pass state it), every generation site's size was read and quoted (unread -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
