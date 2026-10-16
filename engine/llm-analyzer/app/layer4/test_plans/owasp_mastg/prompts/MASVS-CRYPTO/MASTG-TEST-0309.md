MASTG-TEST-0309

maswe_id       MASWE-0022
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          References to Reused Initialization Vectors in Symmetric Encryption - static/predictable IV or nonce (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0309 as a `status: placeholder` (no procedure body). This prompt implements the best-effort STATIC detection the control describes: a symmetric IV/nonce that is hardcoded, all-zero, constant, or otherwise predictable, so it repeats across encryptions under the same key. Per NIST SP 800-38A, CBC requires a fresh, unpredictable IV per encryption; per NIST SP 800-38D, counter-based modes (GCM/CTR) require a nonce that NEVER repeats under the same key. Repeating a key+IV/nonce pair defeats confidentiality (and, for GCM, integrity). True per-message repetition is only fully observable at runtime (covered by MASTG-TEST-0310); statically, a fixed/derivable IV constant is the detectable proxy.

What this test looks for
Every symmetric encryption that requires a unique/unpredictable IV or nonce must source it from a secure RNG per operation. A static, hardcoded, all-zero, or constant IV/nonce - or one derived deterministically from a constant - is a finding because it forces IV reuse. This is a static evaluation: the IV/nonce source feeding a symmetric `Cipher.init`. Verdict: `pass` (every required IV/nonce is freshly generated per encryption from a secure RNG), `fail` (>=1 symmetric encryption uses a static/hardcoded/predictable IV or nonce), `n/a` (the app performs no symmetric encryption requiring an IV/nonce), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `IvParameterSpec`/`GCMParameterSpec`/`Cipher.init`. If NO symmetric IV-bearing encryption appears -> `n/a` (nothing to assess; state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the IV/nonce source (the byte[] / constant / RNG draw) AND the `Cipher.init` it parameterizes. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual IV construction and the cipher init, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a static/predictable IV/nonce and (b) its use in a symmetric `Cipher.init`. "the IV might be reused" with no quoted constant is NOT evidence -> `unverified`. A per-call `SecureRandom`-generated IV is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the IV's origin (fresh vs constant) can't be resolved within budget, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Static-IV indicators (finding sources)
- A literal/constant byte array passed to `IvParameterSpec(new byte[]{...})` / `IvParameterSpec(IV_CONST)` where `IV_CONST` is a `static final byte[]` or a decoded literal.
- An all-zero IV: `new IvParameterSpec(new byte[16])` (default-initialized zeros), or `new byte[12]` for GCM.
- `GCMParameterSpec(tagLen, constantNonce)` with a fixed/constant nonce.
- An IV derived deterministically from a constant (e.g. `key.getBytes()`, a fixed string, a hash of a constant) rather than from `SecureRandom`.
- The SAME IV variable generated ONCE and reused across multiple `Cipher.init(ENCRYPT_MODE, ...)` calls under the same key.

Compliant IV sources
A fresh IV/nonce generated per encryption from `SecureRandom` (e.g. `byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);` then `GCMParameterSpec`/`IvParameterSpec`), or the random IV the provider generates when `Cipher.init` is called WITHOUT an explicit IV (then read back via `cipher.getIV()` and stored/transmitted with the ciphertext).

Procedure
1. Enumerate IV-bearing encryption sites: `grep -rEn "IvParameterSpec|GCMParameterSpec|Cipher\.init|\.getIV\(" jadx/sources/`. If no symmetric IV-bearing encryption -> short-circuit `n/a` (state the search).
2. For each, resolve the IV/nonce SOURCE for ENCRYPT operations: a literal/constant/all-zero/derived-from-constant value (finding), a per-call `SecureRandom` draw (Compliant), or a provider-generated random IV (Compliant). Quote the source and the `Cipher.init`. (Decryption necessarily reuses the stored IV - judge ENCRYPT sites for IV freshness.)
3. Confirm the cipher is symmetric and in a mode requiring IV uniqueness (CBC/CTR/GCM/CFB/OFB) and protects sensitive data. ECB has no IV (its weakness is MASTG-TEST-0232). Quote the mode + data.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (static/predictable/reused IV quoted + symmetric encrypt use); Compliant (per-call SecureRandom or provider-generated IV, quoted); Unverified (IV source unresolved).
6. Budget ~2-4 reads per site (the IV construction, the Cipher.init, any constant holding the IV). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
IV handling inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a freshly-generated IV is ALSO reused across messages at runtime is only fully visible dynamically (MASTG-TEST-0310); statically, judge whether the source is fresh-per-call. ECB (no IV) is MASTG-TEST-0232.

Output
List **all** symmetric IV-bearing encrypt sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant per-call-random IV sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the static/predictable IV source and the symmetric `Cipher.init` (mode + sensitive data), plus owner.
- Compliant: L1 row plus an L2 quoting the per-call SecureRandom / provider-generated IV.
- Group: L1 summary plus an L2 naming references and the shared fresh-IV pattern.

```
{
  "id": "iv-001",
  "description": "Finding (static IV): The app encrypts stored tokens with AES/CBC using a hardcoded all-zero IV, so every ciphertext shares the same IV under the same key.",
  "reference": "jadx/sources/com/example/app/TokenStore.java",
  "level": 1
},
{
  "id": "L2-iv-source",
  "description": "Static IV (quoted): IvParameterSpec iv = new IvParameterSpec(new byte[16]); at TokenStore.java:40 - 16 zero bytes, never randomized.",
  "reference": "jadx/sources/com/example/app/TokenStore.java:40",
  "level": 2
},
{
  "id": "L2-iv-use",
  "description": "Symmetric encrypt use (quoted): Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\"); c.init(ENCRYPT_MODE, key, iv); c.doFinal(token) at lines 42-45 - CBC requires a fresh, unpredictable IV per encryption (NIST SP 800-38A). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/TokenStore.java:42-45",
  "level": 2
},
{
  "id": "iv-ok-001",
  "description": "Compliant: GCM nonce freshly generated per encryption from SecureRandom.",
  "reference": "jadx/sources/com/example/app/AeadBox.java",
  "level": 1
},
{
  "id": "L2-iv-ok",
  "description": "Fresh nonce (quoted): byte[] n = new byte[12]; new SecureRandom().nextBytes(n); GCMParameterSpec spec = new GCMParameterSpec(128, n); c.init(ENCRYPT_MODE, key, spec); at AeadBox.java:30-34 - unique per-call nonce.",
  "reference": "jadx/sources/com/example/app/AeadBox.java:30-34",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0309",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "I symmetric IV-bearing encrypt sites enumerated, N findings (static/all-zero/constant/derived/reused IV or nonce), C compliant (per-call SecureRandom / provider-generated), U unverified. Any IV-bearing symmetric encryption present? <no -> n/a / yes>. <one or two sentences naming each static IV, its mode and the data it protects>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` MAY be set true for sites where per-message uniqueness can only be confirmed at runtime; it does not change the static `pass`/`fail`.
- `fail`: >=1 symmetric encrypt site with (a) an L2 row quoting a static/all-zero/constant/derived-from-constant IV or nonce (or one IV reused across encrypt calls) AND (b) an L2 row quoting the `Cipher.init` (IV-requiring mode, sensitive data). A finding stated with "likely"/"may" instead of the quoted IV source is INVALID -> `unverified`.
- **Fresh-per-call is the bar.** A per-call `SecureRandom` IV or a provider-generated random IV is Compliant. ECB (no IV) is not this test - it is MASTG-TEST-0232.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the IV fresh? is it constant?) resolved by reading, unresolved -> `unverified`. Reject "the IV might be randomized elsewhere".
- `pass`: every IV-requiring symmetric encryption sources a fresh IV/nonce per call from a secure RNG (or provider-generated), with L2 coverage.
- `n/a`: no symmetric IV-bearing encryption appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its IV-source + Cipher.init L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the static/predictable/reused IV or nonce source is quoted; (2) the symmetric `Cipher.init` (IV-requiring mode, sensitive data) is quoted; (3) the IV is NOT freshly generated per call; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the IV search was performed (n/a / pass state it), every encrypt site's IV source was read and quoted (unread -> `unverified`), no ECB (no-IV) site was miscounted here, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
