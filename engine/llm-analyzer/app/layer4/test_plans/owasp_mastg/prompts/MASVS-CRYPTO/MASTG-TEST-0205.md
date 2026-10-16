MASTG-TEST-0205

maswe_id       MASWE-0027
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Non-random Sources Usage - guessable values from time/counters used as randomness (static)

What this test looks for
Security-relevant values that must be unpredictable (keys, IVs/nonces, salts, tokens, session IDs, passwords, PINs, OTPs) must not be derived from NON-random sources - clock readings, counters, or other low-entropy/deterministic inputs that are easily guessable or reproducible. Typical anti-patterns: `System.currentTimeMillis()`, `System.nanoTime()`, `new Date().getTime()`, `Calendar.get(Calendar.MILLISECOND)`, `SystemClock.*`, an incrementing counter, a UUID built from time, or hashing such a value and treating the digest as a secret. This is a static, taint-style evaluation: non-random source -> security-relevant sink. Verdict: `pass` (no non-random source feeds a security-relevant value), `fail` (a non-random source produces a value used in a security-relevant context), `n/a` (the app generates no security-relevant values to assess), or `inconclusive`.

SHORT-CIRCUIT (decide first): if the app derives no security-relevant secret/token/key/IV at all (no such generation sites) -> `n/a`. A time/counter read used only for non-security purposes (timestamps, cache keys, logging, jitter) is NOT a finding. Only a flow of a non-random value INTO a security-relevant sink is a finding.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the non-random source read AND the security-relevant sink the value reaches. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the source read and the sink, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the non-random source and (b) the security-relevant use of its value. "might use the timestamp as a token" is NOT evidence -> `unverified`. A timestamp used as a plain timestamp is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If security-relevance or the source's randomness can't be resolved within budget, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Non-random sources (taint sources)
`System.currentTimeMillis()`, `System.nanoTime()`, `new Date().getTime()`, `Calendar.getInstance().get(...)` (esp. `MILLISECOND`/`SECOND`), `SystemClock.elapsedRealtime()`/`uptimeMillis()`, `AtomicInteger`/`AtomicLong` or a plain incrementing counter used as "randomness", a process id / sequence number, `UUID` built from a timestamp, and any digest (`MessageDigest`) whose only entropy input is one of the above. (A value mixed into a properly-seeded `SecureRandom` as additional entropy is NOT itself the source of unpredictability and is out of scope.)

Security-relevant sinks (where unpredictability is required)
The value flows into: key material (`SecretKeySpec`, raw key bytes), an IV/nonce (`IvParameterSpec`, `GCMParameterSpec`), a KDF salt, or a token / session identifier / password / PIN / OTP / nonce (revealed by names and downstream crypto/auth APIs). Non-security uses (timestamps, cache keys, ordering, logging) are out of scope.

Failure modes
- NR1 - Time-based secret: a clock reading (`currentTimeMillis`/`nanoTime`/`Date`/`Calendar`/`SystemClock`) is used (directly or hashed) as a key/IV/nonce/salt/token/PIN/OTP. Quote source + sink.
- NR2 - Counter/deterministic secret: an incrementing counter, sequence number, or pid is used as a security-relevant "random" value. Quote source + sink.

Procedure
1. Enumerate non-random source reads: `grep -rEn "currentTimeMillis|nanoTime|getTime\(|Calendar\.|SystemClock\.|elapsedRealtime|uptimeMillis|AtomicInteger|AtomicLong" jadx/sources/`. Also locate secret/token/key/IV generation sites (`grep -rEn "SecretKeySpec|IvParameterSpec|GCMParameterSpec|generateToken|sessionId|otp|nonce|salt" jadx/sources/`). If no security-relevant generation exists -> short-circuit `n/a` (state the searches).
2. For each non-random source, trace its value: does it reach a security-relevant sink (directly, hashed, or concatenated)? Quote source + sink. Non-security uses -> Compliant.
3. For each security-relevant generation site, confirm whether its entropy comes from a non-random source (finding) or a secure RNG (Compliant). Quote the entropy input.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (NR1/NR2 with source+sink quoted); Compliant (non-security use, or secure-RNG entropy); Unverified (security-relevance or entropy source unresolved).
6. Budget ~2-4 reads per source plus 1-2 call-graph hops to reach the sink. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Value derivation inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a use is security-relevant is read from context; indeterminate -> `unverified`. Non-security time/counter reads are out of scope.

Output
List **all** non-random-source flows carrying app data - one L1 row per flow (or per data category) with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant non-security reads by area as one L1 row per group, but always break out every Finding (NR1/NR2) and unverified flow individually. Never sample findings.
- Finding NR1/NR2: L1 row plus L2 rows for the non-random source read (quoted) and the security-relevant sink (quoted), plus owner.
- Compliant: L1 row plus L2 showing the read is non-security, or the secret's entropy comes from a secure RNG (quoted).
- Group: L1 summary plus an L2 naming references and the shared non-security pattern.

```
{
  "id": "nr-001",
  "description": "Finding (NR1 time-based secret): The app builds a one-time password from System.currentTimeMillis(), so the OTP is guessable from the device clock.",
  "reference": "jadx/sources/com/example/app/OtpHelper.java",
  "level": 1
},
{
  "id": "L2-nr-source",
  "description": "Non-random source (quoted): long seed = System.currentTimeMillis(); at OtpHelper.java:30 - deterministic clock reading, low entropy.",
  "reference": "jadx/sources/com/example/app/OtpHelper.java:28-31",
  "level": 2
},
{
  "id": "L2-nr-sink",
  "description": "Security sink (quoted): String otp = String.format(\"%06d\", seed % 1000000) used as the login OTP at lines 33-35 - OTP requires unpredictability. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/OtpHelper.java:33-35",
  "level": 2
},
{
  "id": "nr-ok-group",
  "description": "Compliant group: 6 currentTimeMillis() reads used only for cache expiry / log timestamps (non-security).",
  "reference": "jadx/sources/com/example/app/cache/",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0205",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R non-random source reads enumerated, S feeding a security-relevant sink, N findings (NR1 time-based / NR2 counter), C compliant, U unverified. Any security-relevant value generated? <no -> n/a / yes>. <one or two sentences naming the non-random-sourced secrets and their sinks>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 value with (a) an L2 row quoting a non-random source (NR1 time / NR2 counter) AND (b) an L2 row quoting its use in a security-relevant sink. A finding stated with "likely"/"may"/"might be the token" is INVALID -> `unverified`.
- **Security-relevance is required.** A time/counter read used only for timestamps, cache keys, ordering, or logging is Compliant, not a finding.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is this security-relevant? is this the entropy source?) resolved by reading, unresolved -> `unverified`. Reject "might be hashed with a secret elsewhere".
- `pass`: non-random sources are present but only in non-security uses, OR every security-relevant value is seeded from a secure RNG, with L2 coverage.
- `n/a`: the app generates no security-relevant secret/token/key/IV to assess (short-circuit; state the searches).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its source + security-sink L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the non-random source read is quoted; (2) the security-relevant sink is quoted and the value category named; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the source + generation searches were performed (n/a / pass state them), every security-relevant value's entropy was read and quoted (unread -> `unverified`), no non-security read was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
