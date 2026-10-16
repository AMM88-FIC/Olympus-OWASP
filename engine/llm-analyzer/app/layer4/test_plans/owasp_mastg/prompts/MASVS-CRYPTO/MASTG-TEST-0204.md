MASTG-TEST-0204

maswe_id       MASWE-0027
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Insecure Random API Usage - weak PRNG feeding a security-relevant value (static)

What this test looks for
Every security-relevant value that must be unpredictable - cryptographic keys, IVs/nonces, salts, authentication/session tokens, passwords, PINs, OTPs, CSRF/anti-replay nonces - must be produced by a cryptographically secure RNG (a default-seeded `SecureRandom` or equivalent). Insecure PRNGs are predictable and must not feed those contexts: `java.util.Random` (a linear congruential generator), `Math.random()` (which delegates to a shared static `java.util.Random`), and a `SecureRandom` constructed/seeded with a fixed, hardcoded, derived, or low-entropy value. This is a static, taint-style evaluation: insecure-RNG source -> security-relevant sink. Verdict: `pass` (insecure RNG present only in non-security contexts, or all security randomness comes from a secure RNG), `fail` (an insecure RNG produces a value used in a security-relevant context), `n/a` (no insecure-RNG APIs appear in code at all), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the insecure-RNG APIs below. If NONE appear in code -> `n/a` (there is no weak-RNG mechanism to assess; state the search). If they appear but every reachable use is non-security (UI/animation, jitter, exponential backoff, sampling, shuffling display order) -> `pass`. Only a flow into a security-relevant sink is a finding.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the RNG construction/draw site AND the security-relevant sink the value reaches. A disposition with no quoted code is an assertion -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual draw site and the sink, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the insecure-RNG draw and (b) the security-relevant use of that value. "probably used for a token", "may be a key" are NOT evidence -> `unverified`. A weak-RNG draw used only for a non-security purpose is Compliant, not a finding.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the draw's security-relevance or the secure-vs-insecure nature of the RNG can't be resolved within budget, the row is `unverified` (deepest unresolved point named). `false_positive_risks` is out-of-APK only.

Insecure-RNG sources (taint sources)
`new java.util.Random(...)` and its draws (`nextInt`/`nextLong`/`nextBytes`/`nextDouble`/`nextFloat`/`nextBoolean`), `Math.random()`, `java.util.concurrent.ThreadLocalRandom` (NOT cryptographically secure), `SecureRandom` whose seed is fixed/hardcoded/derived (`new SecureRandom(seedBytes)`, `setSeed(constant)`, `setSeed(System.currentTimeMillis())`), custom PRNGs (linear-congruential, XOR-shift, time-based), and third-party RNG classes not documented as cryptographically secure. (A default-constructed `SecureRandom` used without a forced seed is the SECURE baseline - not a source.)

Security-relevant sinks (where unpredictability is required)
The drawn value flows into: key material (`SecretKeySpec`, `KeyGenerator`/`KeyPairGenerator` seeding, raw key bytes), an IV/nonce (`IvParameterSpec`, `GCMParameterSpec`), a KDF salt, or a token / session identifier / password / PIN / OTP / nonce / anti-CSRF value (often revealed by variable/field/method names and the downstream crypto or auth API). Non-security uses (UI, animation, jitter, backoff, sampling) are out of scope.

Failure modes
- IR1 - Predictable PRNG in a security context: `java.util.Random` / `Math.random()` / `ThreadLocalRandom` / custom PRNG produces a value used in a security-relevant sink. Quote draw + sink.
- IR2 - Improperly seeded SecureRandom: a `SecureRandom` forced to a fixed/derived/low-entropy seed feeds a security-relevant sink, making its output predictable. Quote the seeding + sink.

Procedure
1. Enumerate RNG sites: `grep -rEn "new Random\(|java\.util\.Random|Math\.random\(|ThreadLocalRandom|new SecureRandom|setSeed" jadx/sources/`. If no insecure-RNG sources are present -> short-circuit `n/a` (state the search). Also note default-seeded `SecureRandom` uses as the compliant baseline.
2. For each insecure-RNG source, read the draw site and trace the drawn value: does it flow into a security-relevant sink (key/IV/nonce/salt/token/PIN/OTP)? Quote the value and the sink. Non-security uses -> Compliant.
3. For each `SecureRandom`, check whether it is forced to a fixed/derived seed (`setSeed`/seeded constructor). Default-seeded -> Compliant; seeded-with-constant feeding a security sink -> IR2. Quote the seeding.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A third-party SDK's internal non-security RNG is attributed; a weak RNG the app feeds into its own security value is in scope.
5. Conclude per site: Finding (IR1/IR2 with draw+sink quoted); Compliant (non-security use, or default-seeded SecureRandom); Unverified (security-relevance or seeding unresolved).
6. Budget ~2-4 reads per source (the draw, the downstream sink) plus 1-2 call-graph hops to reach the sink. Unresolved within budget -> `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
RNG inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a use is security-relevant is read from context; indeterminate -> `unverified`. Non-security randomness is out of scope.

Output
List **all** insecure-RNG sites carrying app data - one L1 row per site (or per data category) with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant non-security draws by area as one L1 row per group, but always break out every Finding (IR1/IR2) and unverified site individually. Never sample findings.
- Finding IR1: L1 row plus L2 rows for the insecure-RNG draw (quoted) and the security-relevant sink (quoted), plus owner.
- Finding IR2: L1 row plus L2 quoting the fixed/derived seed and the security-relevant sink.
- Compliant: L1 row plus L2 showing the draw is non-security, or a default-seeded SecureRandom (quoted).
- Group: L1 summary plus an L2 naming references and the shared non-security pattern.

```
{
  "id": "ir-001",
  "description": "Finding (IR1 predictable PRNG in security context): The app derives an authentication token from java.util.Random, so the token is predictable to an attacker who can recover or guess the seed.",
  "reference": "jadx/sources/com/example/app/TokenFactory.java",
  "level": 1
},
{
  "id": "L2-rng-draw",
  "description": "Insecure-RNG draw (quoted): Random rng = new Random(); byte[] b = new byte[16]; rng.nextBytes(b); at TokenFactory.java:21-24 - java.util.Random (LCG), not cryptographically secure.",
  "reference": "jadx/sources/com/example/app/TokenFactory.java:21-24",
  "level": 2
},
{
  "id": "L2-rng-sink",
  "description": "Security sink (quoted): String token = Base64.encodeToString(b, NO_WRAP) returned as the session token at lines 26-28 - token/session material requires unpredictability. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/TokenFactory.java:26-28",
  "level": 2
},
{
  "id": "ir-ok-group",
  "description": "Compliant group: 4 java.util.Random draws used only for UI jitter / animation delays (non-security).",
  "reference": "jadx/sources/com/example/app/ui/",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0204",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R insecure-RNG sources enumerated, S feeding a security-relevant sink, N findings (IR1 predictable PRNG / IR2 seeded SecureRandom), C compliant (non-security or default-seeded), U unverified. Any insecure RNG present? <no -> n/a / yes>. <one or two sentences naming the security-relevant draws and their sinks>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 value with (a) an L2 row quoting an insecure-RNG draw (IR1) or a fixed/derived `SecureRandom` seed (IR2) AND (b) an L2 row quoting its use in a security-relevant sink (key/IV/nonce/salt/token/PIN/OTP/session id). A finding stated with "likely"/"may"/"probably a token" instead of the quoted draw+sink is INVALID -> `unverified`.
- **Security-relevance is required.** A weak-RNG draw used only for UI/animation/jitter/backoff/sampling is Compliant, not a finding. A default-constructed `SecureRandom` (no forced seed) is the secure baseline.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is this draw security-relevant? is this RNG secure?) resolved by reading, unresolved -> `unverified`. Reject "might be a key", "could be seeded securely elsewhere".
- `pass`: insecure-RNG APIs are present but every reachable use is non-security, OR all security-relevant randomness comes from a default-seeded SecureRandom, with L2 coverage.
- `n/a`: no insecure-RNG APIs appear in code at all (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its draw + security-sink L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the insecure-RNG draw (IR1) or fixed/derived seed (IR2) is quoted; (2) the security-relevant sink is quoted and the value category named (key/IV/nonce/salt/token/PIN/OTP/session); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the RNG-source search was performed (n/a / pass state it), every security-relevant draw was read and quoted (unread -> `unverified`), no non-security draw was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
