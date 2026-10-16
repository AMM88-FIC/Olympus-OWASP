MASTG-TEST-0310

maswe_id       MASWE-0022
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Runtime Use of Reused Initialization Vectors in Symmetric Encryption - IV/nonce repetition at runtime (dynamic; static approximation)

NOTE - DYNAMIC TEST + UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC APPROXIMATION: OWASP ships MASTG-TEST-0310 as a `status: placeholder` DYNAMIC test (hook `Cipher.init` at runtime and observe whether the same IV/nonce repeats across encryptions under the same key). This static engine cannot observe runtime IV values, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0309 (static/hardcoded/constant/derived IV or nonce feeding a symmetric encryption). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the static verdict is indicative only and must be confirmed at runtime - a per-call `SecureRandom` IV that LOOKS fresh statically could still be cached and repeated on a path only observable dynamically.

What this test looks for
At runtime the same key must never encrypt two messages under the same IV/nonce. Statically, the detectable proxy is an IV/nonce that is hardcoded, all-zero, constant, deterministically derived from a constant, or generated once and reused across multiple encrypt calls - any of which forces runtime reuse. This static approximation evaluates the IV/nonce source feeding every symmetric `Cipher.init` ENCRYPT operation. Verdict: `pass` (every required IV/nonce is freshly generated per encryption from a secure RNG), `fail` (>=1 symmetric encryption uses a static/predictable/reused IV or nonce), `n/a` (the app performs no symmetric encryption requiring an IV/nonce), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `IvParameterSpec`/`GCMParameterSpec`/`Cipher.init`. If NO symmetric IV-bearing encryption appears -> `n/a` (nothing to assess; state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the IV/nonce source AND the `Cipher.init` it parameterizes. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual IV construction and the cipher init, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a static/predictable/reused IV/nonce and (b) its use in a symmetric encrypt `Cipher.init`. "the IV is probably reused" with no quoted source is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the IV's origin can't be resolved statically, the row is `unverified` (and the forced `needs_dynamic_testing` flags it for hooking). `false_positive_risks` is out-of-APK only.

Static-IV indicators (finding sources)
- Literal/constant byte array in `IvParameterSpec` / `GCMParameterSpec` (incl. a `static final byte[]` or decoded literal).
- All-zero IV (`new IvParameterSpec(new byte[16])`, `new byte[12]` for GCM).
- A fixed/constant GCM nonce.
- An IV derived deterministically from a constant (fixed string, key bytes, hash of a constant).
- A single IV variable generated once and reused across multiple `Cipher.init(ENCRYPT_MODE, ...)` calls under the same key.

Compliant IV sources
A fresh IV/nonce generated per encryption from `SecureRandom`, or the provider-generated random IV obtained when `Cipher.init` is called without an explicit IV and read back via `cipher.getIV()`.

Procedure
1. Enumerate IV-bearing encryption sites: `grep -rEn "IvParameterSpec|GCMParameterSpec|Cipher\.init|\.getIV\(" jadx/sources/`. If no symmetric IV-bearing encryption -> short-circuit `n/a` (state the search).
2. For each ENCRYPT operation, resolve the IV/nonce SOURCE: literal/constant/all-zero/derived-from-constant/once-and-reused (finding), or per-call `SecureRandom`/provider-generated (Compliant). Quote the source and `Cipher.init`. (Decryption reuses the stored IV by design - judge ENCRYPT sites.)
3. Confirm the cipher is symmetric in an IV-requiring mode (CBC/CTR/GCM/CFB/OFB) protecting sensitive data. ECB (no IV) -> MASTG-TEST-0232. Quote mode + data.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (static/predictable/reused IV quoted + symmetric encrypt use); Compliant (per-call SecureRandom / provider-generated, quoted); Unverified (IV source unresolved).
6. Budget ~2-4 reads per site (the IV construction, the Cipher.init, any constant holding the IV). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
IV handling inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a statically-fresh IV is repeated at runtime is only fully visible dynamically - hence the forced `needs_dynamic_testing`. ECB (no IV) is MASTG-TEST-0232.

Output
List **all** symmetric IV-bearing encrypt sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant per-call-random IV sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the static/predictable/reused IV source and the symmetric `Cipher.init` (mode + sensitive data), plus owner.
- Compliant: L1 row plus an L2 quoting the per-call SecureRandom / provider-generated IV.
- Group: L1 summary plus an L2 naming references and the shared fresh-IV pattern.

```
{
  "id": "ri-001",
  "description": "Finding (reused IV): A single IV is generated once in a static initializer and reused for every AES/CBC encryption under the same key, guaranteeing runtime IV reuse.",
  "reference": "jadx/sources/com/example/app/Crypter.java",
  "level": 1
},
{
  "id": "L2-ri-source",
  "description": "Reused IV (quoted): private static final IvParameterSpec IV = new IvParameterSpec(SEED_BYTES); at Crypter.java:18 - one fixed IV instance shared by all calls.",
  "reference": "jadx/sources/com/example/app/Crypter.java:18",
  "level": 2
},
{
  "id": "L2-ri-use",
  "description": "Symmetric encrypt use (quoted): c.init(Cipher.ENCRYPT_MODE, KEY, IV); c.doFinal(message) at Crypter.java:40-42 - the same KEY+IV pair across every message. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Crypter.java:40-42",
  "level": 2
},
{
  "id": "ri-ok-001",
  "description": "Compliant: IV freshly drawn from SecureRandom per encryption.",
  "reference": "jadx/sources/com/example/app/SafeBox.java",
  "level": 1
},
{
  "id": "L2-ri-ok",
  "description": "Fresh IV (quoted): byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv); c.init(ENCRYPT_MODE, key, new IvParameterSpec(iv)); at SafeBox.java:25-28 - unique per-call IV.",
  "reference": "jadx/sources/com/example/app/SafeBox.java:25-28",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0310",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "I symmetric IV-bearing encrypt sites enumerated, N findings (static/all-zero/constant/derived/once-and-reused IV or nonce), C compliant (per-call SecureRandom / provider-generated), U unverified. Any IV-bearing symmetric encryption present? <no -> n/a / yes>. <one or two sentences naming each reused/static IV, its mode and the data it protects>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 symmetric encrypt site with (a) an L2 row quoting a static/all-zero/constant/derived/once-and-reused IV or nonce AND (b) an L2 row quoting the `Cipher.init` (IV-requiring mode, sensitive data). A finding stated with "likely"/"may" instead of the quoted IV source is INVALID -> `unverified`.
- **Fresh-per-call is the bar.** A per-call `SecureRandom` IV or provider-generated IV is Compliant statically (runtime still flagged via the forced `needs_dynamic_testing`). ECB (no IV) is MASTG-TEST-0232.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the IV fresh? constant? reused?) resolved by reading, unresolved -> `unverified`.
- `pass`: every IV-requiring symmetric encryption sources a fresh IV/nonce per call from a secure RNG (or provider-generated), with L2 coverage.
- `n/a`: no symmetric IV-bearing encryption appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its IV-source + Cipher.init L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the static/predictable/reused IV or nonce source is quoted; (2) the symmetric `Cipher.init` (IV-requiring mode, sensitive data) is quoted; (3) the IV is NOT freshly generated per call; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the IV search was performed (n/a / pass state it), every encrypt site's IV source was read and quoted (unread -> `unverified`), no ECB (no-IV) site was miscounted here, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
