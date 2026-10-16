MASTG-TEST-0263

maswe_id       MASWE-0094
masvs_v2_id    MASVS-RESILIENCE-2
platform       android
title          Logging of StrictMode Violations - StrictMode logs in production (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0263 is a dynamic test (run the production build and watch logcat for StrictMode policy-violation log entries). This static engine cannot run the app or read logcat, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0265 (StrictMode enabled with a logging penalty outside a debug guard). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only observing logcat at runtime proves StrictMode actually logs violations in the production build.

What this test looks for
The production build must not log StrictMode policy violations (they leak implementation details). Statically, the proxy is a StrictMode policy with `penaltyLog` (or `penaltyDropBox`) enabled outside a debug guard. Verdict: `pass` (no production StrictMode logging penalty), `fail` (>=1 StrictMode `penaltyLog`/`penaltyDropBox` enabled in production), `n/a` (no StrictMode APIs), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `StrictMode`/`penaltyLog`. If NONE appear -> `n/a` (state the search). Runtime logging is still flagged via the forced `needs_dynamic_testing`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the StrictMode policy with its logging penalty AND the surrounding guard (or its absence). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the production `penaltyLog`. "probably logs violations" with no quoted call is NOT static evidence -> `unverified` (flag for logcat).
4. **Unresolved determinacy is `unverified`, not a hedge.** If the guard can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "StrictMode|penaltyLog|penaltyDropBox|setThreadPolicy|setVmPolicy|BuildConfig\.DEBUG" jadx/sources/`. If no StrictMode -> short-circuit `n/a` (state the search).
2. For each StrictMode policy, check for a logging penalty (`penaltyLog`/`penaltyDropBox`) and the enclosing guard. Quote it.
3. Classify: logging penalty enabled outside a debug guard -> finding; debug-guarded, or no logging penalty -> Compliant. Quote the guard.
4. Owner: app (proprietary).
5. Conclude per site: Finding (production logging penalty, quoted); Compliant (debug-guarded / no logging penalty); Unverified (guard unresolved -> confirm via logcat).
6. Budget ~2-3 reads per site. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether violations are actually logged is the dynamic test's job - hence the forced `needs_dynamic_testing`. StrictMode reference presence is MASTG-TEST-0265; runtime StrictMode API use is MASTG-TEST-0264. StrictMode in native/no-source code -> `unverified`.

Output
List **all** StrictMode policies with a logging penalty - one L1 row per site with its disposition.
- Finding: L1 row plus an L2 quoting the production `penaltyLog`/`penaltyDropBox` (and missing/non-debug guard), plus owner.
- Compliant: L1 row plus an L2 quoting the debug guard / absence of a logging penalty.

```
{
  "id": "sml-001",
  "description": "Finding (StrictMode logs violations in production): A VmPolicy with penaltyLog is set unconditionally, so policy violations are written to logcat in release builds.",
  "reference": "jadx/sources/com/example/app/App.java",
  "level": 1
},
{
  "id": "L2-sml-call",
  "description": "Production logging penalty (quoted): StrictMode.setThreadPolicy(new ThreadPolicy.Builder().detectAll().penaltyLog().build()); in App.onCreate at App.java:30-34 - no debug guard. Owner: com.example.app (proprietary). Logcat confirmation required.",
  "reference": "jadx/sources/com/example/app/App.java:30-34",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0263",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S StrictMode sites with a logging penalty, G debug-guarded, N findings (production penaltyLog/penaltyDropBox), U unverified. Any production StrictMode logging? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>; logcat confirms.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that logcat observation is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 StrictMode logging penalty (`penaltyLog`/`penaltyDropBox`) quoted outside a debug-build guard. A finding stated with "likely"/"may" instead of the quoted call is INVALID -> `unverified`.
- **Debug guard / no logging penalty clears it.** A StrictMode policy with no logging penalty, or one inside `BuildConfig.DEBUG`, is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: no production StrictMode logging penalty, with L2 coverage.
- `n/a`: no StrictMode APIs appear in code (state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its logging-penalty L2 row.

Self-check before emitting (per finding)
For every Finding confirm: (1) the StrictMode logging penalty is quoted; (2) no debug-build guard restricts it; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the StrictMode search was performed (n/a state it), every site's logging penalty and guard were read and quoted (unresolved -> `unverified`), no debug-guarded/no-log site was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
