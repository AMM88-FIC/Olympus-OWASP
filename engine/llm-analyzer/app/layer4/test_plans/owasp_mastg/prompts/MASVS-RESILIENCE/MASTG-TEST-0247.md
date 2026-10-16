MASTG-TEST-0247

maswe_id       MASWE-0008
masvs_v2_id    MASVS-RESILIENCE-1
platform       android
title          References to APIs for Detecting Secure Screen Lock - device-lock check present (static)

What this test looks for
An app handling sensitive data should verify the device has a secure screen lock (PIN/pattern/password) using platform APIs, so it can adapt its security posture. This is a PRESENCE/coverage test: it FAILS if the app uses NO such API. Verdict: `pass` (>=1 genuine secure-screen-lock detection API reference), `fail` (no such API reference anywhere), `n/a` (the app handles no sensitive data / device-lock posture is genuinely irrelevant - state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the detection APIs. If >=1 genuine reference -> lean PASS (quote one). If NONE -> lean FAIL (state the search).

Secure-screen-lock detection APIs (any genuine one -> pass)
`KeyguardManager.isDeviceSecure()`, `KeyguardManager.isKeyguardSecure()`, `BiometricManager.canAuthenticate(...)` (biometrics require a secure lock as fallback, so this serves as an equivalent check). A reference used to inform behavior counts; a constant never used is weak (note it).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 real detection-API call. For FAIL, show the searches returned nothing. No quoted evidence -> `inconclusive`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual call, not an index record or line 1.
3. **No verdict by inference/hedge.** PASS requires a quoted call; FAIL requires shown-empty searches. "probably checks the lock" is NOT evidence -> `inconclusive`.
4. **Unresolved determinacy is `inconclusive`.** If the search can't be completed, say so. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "isDeviceSecure|isKeyguardSecure|KeyguardManager|BiometricManager|canAuthenticate" jadx/sources/`.
2. If >=1 genuine detection-API call exists (informing behavior), quote it -> PASS. Distinguish the app's own code from a bundled SDK (note the owner).
3. If none exist, state the search and conclude FAIL.
4. Owner: note proprietary vs library for the cited reference.
5. Budget ~1-3 reads. Unresolved -> `inconclusive`.

Out-of-scope / static limits
The runtime confirmation that the check executes is MASTG-TEST-0249. Whether the check drives an EFFECTIVE response is a deeper review; the OWASP control fails on ABSENCE of any such API. The app cannot force the user to enable a lock - it can only detect/adapt. Detection in native/no-source code -> note as a limit.

Output
One L1 row stating whether any detection reference exists, with a quoted example (pass) or the empty-search result (fail).
- Pass: L1 row plus an L2 quoting a genuine detection-API call.
- Fail: L1 row plus an L2 showing the searches returned nothing.

```
{
  "id": "lock-001",
  "description": "Pass: the app checks for a secure device lock via KeyguardManager.isDeviceSecure().",
  "reference": "jadx/sources/com/example/app/Security.java",
  "level": 1
},
{
  "id": "L2-lock-check",
  "description": "Detection (quoted): if (!keyguardManager.isDeviceSecure()) { warnUserNoLock(); restrictSensitiveFeatures(); } at Security.java:40-44 - adapts behavior to device-lock state. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Security.java:40-44",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0247",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R secure-screen-lock detection references found. Any device-lock check present? <yes -> pass / no -> fail>. <one sentence: where, or that the search was empty>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime confirmation is MASTG-TEST-0249); it does not change `pass`/`fail`.
- `pass`: >=1 genuine secure-screen-lock detection API call is quoted. Even one suffices (presence test).
- `fail`: the detection-API search returns NO reference (state the search). A FAIL asserted without the empty search is INVALID -> `inconclusive`.
- **Presence test.** Do not fail an app that has any genuine lock check; do not pass on an unrelated keyguard reference that is never used.
- **Ownership note.** Distinguish the app's own check from one only in a bundled SDK; note the owner (OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification that device-lock posture is irrelevant (the app handles no sensitive data).
- `false_positive_risks` out-of-APK only.
- `inconclusive` if the search could not be completed, or a verdict was asserted without quoted/empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS, a genuine detection-API call is quoted; (2) for FAIL, the search is shown empty; (3) an unused reference was not counted as a genuine check.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `inconclusive`.
Before emitting: confirm the search was performed, the verdict rests on quoted evidence (or a shown-empty search), and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
