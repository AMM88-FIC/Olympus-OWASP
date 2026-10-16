MASTG-TEST-XXXX

masvs_v1_id    MSTG-CRYPTO-6
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Insecure random number generators used in security-sensitive contexts (1.2.1.1, static)

What this test looks for
In security contexts only a cryptographically secure PRNG (CSPRNG) may be used: `java.security.SecureRandom` (or a kernel CSPRNG in non-Java code). `java.util.Random`, `Math.random()` and other non-secure PRNGs are acceptable only for non-sensitive uses (UI, jitter, sampling, games). This is a fully static evaluation and a taint problem: an **insecure RNG source** whose output flows into a **security-sensitive consumer** is a finding. Verdict: `pass` (only CSPRNG in security contexts), `fail` (an insecure RNG reaches a security context), `n/a` (the app uses no RNG at all), or `inconclusive`.

Source is ground truth. An RNG-call evidence index is a candidate list only — extractors miss wrapper RNG utilities, fields holding a `Random` instance reused across the codebase, and time-based "randomness". Confirm every conclusion by reading the call site in `jadx/sources/` and tracing the generated value to where it is consumed.

Insecure RNG sources
`new java.util.Random(...)` and its `next*`/`nextInt`/`nextLong`/`nextBytes`/`nextDouble`/`ints`/`longs`; `Math.random()`; `java.util.concurrent.ThreadLocalRandom`; `java.util.SplittableRandom`; Kotlin `kotlin.random.Random` (`Random.Default`, `Random.nextInt/Bytes/...` — not cryptographically secure); `org.apache.commons.lang3.RandomStringUtils.random*` and `RandomUtils.*` without a SecureRandom source; `scala.util.Random`. Also non-random sources used as entropy/seed for a secret: `System.currentTimeMillis()`, `System.nanoTime()`, `new Date().getTime()`, a counter, a hardcoded seed.

Secure (compliant) sources
`java.security.SecureRandom` (incl. `SecureRandom.getInstanceStrong()`), a kernel CSPRNG (`/dev/urandom`), platform key generation that draws secure entropy internally (`javax.crypto.KeyGenerator`, `KeyPairGenerator`, `SecretKeyFactory`, AndroidKeyStore via `KeyGenParameterSpec`), `java.util.UUID.randomUUID()` (backed by SecureRandom), and `RandomStringUtils.secure()` / Apache generators explicitly given a `SecureRandom`. Insufficient even though "secure": a `SecureRandom` created from a constant seed (`new SecureRandom(constBytes)`) or whose only entropy is a fixed `setSeed(const)` before generating key material — flag as insufficient.

Security-sensitive consumers (the context that makes an insecure RNG a finding)
The random value is used to produce or seed any of: cryptographic key / IV / nonce / GCM nonce / salt; a password, passphrase, PIN, OTP/2FA code, session id, CSRF or password-reset token, API key/secret; signing/blinding/padding material; or any value assigned to a variable/field named `key|iv|nonce|salt|seed|token|otp|secret|sessionId|csrf|resetCode|apiKey|password`. Consumers via crypto APIs: bytes passed to `IvParameterSpec`, `GCMParameterSpec`, `SecretKeySpec`, `Cipher` init, `Mac`, `MessageDigest` salt.
Non-sensitive consumers (insecure RNG is fine): UI/animation/color/layout jitter, list shuffling for display, retry/backoff jitter, sampling/telemetry bucketing, A/B assignment, game logic, non-security cache keys, test code.

Procedure
1. Enumerate every RNG site (secure and insecure) from the evidence index if present, then confirm with grep, e.g. `grep -rEn "new Random|Math\.random|ThreadLocalRandom|SplittableRandom|kotlin\.random|SecureRandom|RandomStringUtils|RandomUtils|randomUUID|nanoTime|currentTimeMillis" jadx/sources/`. If there are zero RNG sites of any kind, the verdict is `n/a`.
2. For each site, classify the engine: secure or insecure (per the lists above).
3. Trace the generated value forward to its consumer(s) — through local assignment, return value, field, and wrapper RNG utilities (follow a wrapper to its body once). Decide whether any consumer is a security-sensitive context.
4. Conclude per site: Finding (insecure engine → sensitive consumer); Compliant (secure engine → sensitive consumer, with sufficient entropy); Benign (insecure engine → only non-sensitive consumers); Insufficient (secure engine but predictable/constant seed feeding a secret).
5. Budget ~1–3 reads per site whose output is not obviously confined to UI. If forward flow can't be resolved within the bytecode within budget, mark the site `unverified` naming the deepest unresolved consumer (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
RNG inside native code or a no-source third-party SDK can't be traced statically: record it as an `unverified` row (name the entry point handing off to it); it is neither a finding nor a clean. The static verdict is made on what was determinable and is not deferred to runtime.

Output
List **all** RNG uses. If there are 20 or fewer, emit one L1 row per use. If there are more than 20, group the **benign** and **compliant** uses by functionality (e.g. "UI animations — 14 java.util.Random uses", "key generation — 3 SecureRandom uses") as one L1 row per group, but always break out every Finding and every Insufficient/unverified site as its own individual L1 row regardless of count.
- Finding: L1 row plus L2 rows for the insecure source line, the sensitive-consumer line, and why the consumer is a security context.
- Compliant (secure in a sensitive context): L1 row plus L2 for the secure source and the consumer.
- Benign group: L1 summary plus an L2 row naming the references and the non-security use that makes them benign.

```
{
  "id": "rng-001",
  "description": "Finding: TokenFactory.newSessionToken builds a session token from java.util.Random output. An insecure PRNG seeds an authentication token (predictable).",
  "reference": "jadx/sources/com/example/app/TokenFactory.java",
  "level": 1
},
{
  "id": "L2-TokenFactory-source",
  "description": "Insecure source: Random rnd = new Random(); rnd.nextBytes(buf) at lines 22-24. java.util.Random is not a CSPRNG.",
  "reference": "jadx/sources/com/example/app/TokenFactory.java:20-26",
  "level": 2
},
{
  "id": "L2-TokenFactory-consumer",
  "description": "Sensitive consumer: buf is Base64-encoded into sessionToken and returned to AuthService.startSession (session identifier). Security context: an attacker who can predict the PRNG sequence can forge tokens.",
  "reference": "jadx/sources/com/example/app/TokenFactory.java:28-36",
  "level": 2
},
{
  "id": "rng-ui-group",
  "description": "Benign group: 14 java.util.Random / Math.random uses confined to UI animation and list-shuffle utilities; no security consumer.",
  "reference": "jadx/sources/com/example/app/ui/",
  "level": 1
},
{
  "id": "L2-ui-coverage",
  "description": "Non-security use: AnimUtils.jitter, ConfettiView, ShuffleHelper.shuffleForDisplay (and 11 more) consume the values only for view offsets, colors, and display ordering. References enumerated; none reaches a key/IV/salt/token consumer.",
  "reference": "jadx/sources/com/example/app/ui/AnimUtils.java:40-120",
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
  "rationale": "T RNG sites enumerated (S secure, I insecure), N findings, C compliant-in-sensitive, B benign, U unverified. <one or two sentences naming the classes, methods and consumers involved>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set it true only to mark native/no-source-SDK RNG recorded as `unverified` for optional manual follow-up. It does not change `pass`/`fail`.
- `fail`: ≥1 site with an L2 row showing an insecure engine AND an L2 row showing its output reaches a security-sensitive consumer. "Reaches" means the random value (or a direct derivation of it) is consumed by the sensitive operation — not merely that an insecure RNG exists somewhere.
- `pass`: RNG is used and every security-sensitive consumer is fed by a CSPRNG with sufficient entropy; any insecure RNG present is confirmed benign with L2 coverage.
- `n/a`: no RNG site of any kind exists (enumeration performed and empty).
- A `SecureRandom` with a constant/predictable seed feeding a secret is a finding classified Insufficient, not Compliant. `UUID.randomUUID()` is secure — do not flag it.
- `unverified` rows name the deepest unresolved consumer (or the native/SDK entry point). Such sites are neither findings nor cleans.
- `false_positive_risks` is for factors outside the static artifact only (a consumer that looks security-relevant by name but is non-security at runtime, RNG provider chosen at runtime). In-APK gaps go in `unverified` rows.
- `inconclusive` if rationale counts don't reconcile with L1 rows (counting grouped uses), if any false_positive_risk references in-APK code, or if any `fail` lacks its two L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.