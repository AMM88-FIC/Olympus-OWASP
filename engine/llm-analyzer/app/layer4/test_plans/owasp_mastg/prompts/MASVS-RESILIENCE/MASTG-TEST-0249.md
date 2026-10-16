MASTG-TEST-0249

maswe_id       MASWE-0008
masvs_v2_id    MASVS-RESILIENCE-1
platform       android
title          Runtime Use of Secure Screen Lock Detection APIs (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0249 is a dynamic test (hook `KeyguardManager.isDeviceSecure` / `BiometricManager.canAuthenticate` at runtime to confirm the app actually checks the device-lock state). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0247 (presence of secure-screen-lock detection API references). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only hooking the APIs at runtime confirms the check actually executes.

What this test looks for
At runtime the app should check whether the device has a secure screen lock. Statically, the proxy is the presence of a detection-API reference (as in MASTG-TEST-0247). This is a PRESENCE test: it FAILS if no such API is referenced. Verdict: `pass` (>=1 detection API reference), `fail` (none), `n/a` (device-lock posture genuinely irrelevant - state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the detection APIs. >=1 genuine reference -> lean PASS; none -> lean FAIL (state the search). Runtime execution is still flagged via the forced `needs_dynamic_testing`.

Detection APIs (any genuine one -> pass)
`KeyguardManager.isDeviceSecure()`, `KeyguardManager.isKeyguardSecure()`, `BiometricManager.canAuthenticate(...)`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 real detection call. For FAIL, show empty searches. No quoted evidence -> `inconclusive`/`unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No verdict by inference/hedge.** PASS needs a quoted call; FAIL needs shown-empty searches. "probably checks at runtime" is NOT static proof -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`/`inconclusive`.** `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "isDeviceSecure|isKeyguardSecure|KeyguardManager|BiometricManager|canAuthenticate" jadx/sources/`.
2. >=1 genuine call -> PASS (quote it); none -> FAIL (state the search).
3. Owner: note proprietary vs library.
4. Budget ~1-3 reads. Unresolved -> `unverified`/`inconclusive`.

Out-of-scope / static limits
Whether the check actually runs at the right moment is runtime-only - hence the forced `needs_dynamic_testing`. Static presence is MASTG-TEST-0247. Detection in native/no-source code -> note as a limit.

Output
One L1 row stating whether any detection reference exists, with a quoted example (pass) or the empty-search result (fail).
- Pass: L1 row plus an L2 quoting a genuine detection call.
- Fail: L1 row plus an L2 showing empty searches.

```
{
  "id": "lockr-001",
  "description": "Pass: the app references KeyguardManager.isDeviceSecure(); runtime hook confirms execution.",
  "reference": "jadx/sources/com/example/app/Security.java",
  "level": 1
},
{
  "id": "L2-lockr-check",
  "description": "Detection (quoted): boolean secure = keyguardManager.isDeviceSecure(); used to gate sensitive features at Security.java:40-44. Owner: com.example.app (proprietary). Runtime hook confirms the call fires.",
  "reference": "jadx/sources/com/example/app/Security.java:40-44",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0249",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R secure-screen-lock detection references found. Any device-lock check present? <yes -> pass / no -> fail>. <one sentence>; runtime hook confirms execution.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `pass`: >=1 genuine detection API call is quoted (presence test).
- `fail`: the detection-API search returns NO reference (state the search). A FAIL asserted without the empty search is INVALID -> `unverified`.
- **Presence test / ownership note** as in MASTG-TEST-0247 (OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification.
- `false_positive_risks` out-of-APK only.
- `unverified`/`inconclusive` if the search could not be completed or the verdict lacks quoted/empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS a genuine detection call is quoted; (2) for FAIL the search is shown empty; (3) an unused reference was not counted.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `unverified`.
Before emitting: confirm the search was performed, the verdict rests on quoted/empty-search evidence, and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
