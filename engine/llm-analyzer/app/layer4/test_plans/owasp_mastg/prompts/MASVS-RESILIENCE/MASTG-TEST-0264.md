MASTG-TEST-0264

maswe_id       MASWE-0094
masvs_v2_id    MASVS-RESILIENCE-2
platform       android
title          Runtime Use of StrictMode APIs - StrictMode active at runtime (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0264 is a dynamic test (hook `StrictMode.setVmPolicy`/`setThreadPolicy`/`penaltyLog` at runtime to confirm StrictMode is active). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0265 (StrictMode enabled outside a debug guard). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only hooking the StrictMode setters at runtime confirms they execute in the production build.

What this test looks for
The production build should not use StrictMode at runtime. Statically, the proxy is StrictMode policy enablement (`setThreadPolicy`/`setVmPolicy`) outside a debug guard. Verdict: `pass` (no production StrictMode use), `fail` (>=1 StrictMode policy enabled in production), `n/a` (no StrictMode APIs), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `StrictMode`/`setThreadPolicy`/`setVmPolicy`. If NONE appear -> `n/a` (state the search). Runtime use is still flagged via the forced `needs_dynamic_testing`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the StrictMode policy enablement AND the surrounding guard (or its absence). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the production StrictMode enablement. "probably uses StrictMode" with no quoted call is NOT static evidence -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`, not a hedge.** If the guard can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "StrictMode|setThreadPolicy|setVmPolicy|penaltyLog|penaltyDeath|detectAll|BuildConfig\.DEBUG" jadx/sources/`. If no StrictMode -> short-circuit `n/a` (state the search).
2. For each StrictMode policy enablement, resolve the enclosing guard. Quote it.
3. Classify: enabled outside a debug guard (production) -> finding; debug-guarded -> Compliant. Quote the guard.
4. Owner: app (proprietary).
5. Conclude per site: Finding (production StrictMode, quoted); Compliant (debug-guarded); Unverified (guard unresolved -> confirm via hook).
6. Budget ~2-3 reads per site. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether the setters actually execute is the dynamic test's job - hence the forced `needs_dynamic_testing`. StrictMode reference presence is MASTG-TEST-0265; logging of violations is MASTG-TEST-0263. StrictMode in native/no-source code -> `unverified`.

Output
List **all** StrictMode enablement sites - one L1 row per site with its disposition.
- Finding: L1 row plus an L2 quoting the production StrictMode enablement (and missing/non-debug guard), plus owner.
- Compliant: L1 row plus an L2 quoting the debug guard.

```
{
  "id": "smr-001",
  "description": "Finding (StrictMode used at runtime in production): The app sets a ThreadPolicy unconditionally at startup.",
  "reference": "jadx/sources/com/example/app/App.java",
  "level": 1
},
{
  "id": "L2-smr-call",
  "description": "Production StrictMode (quoted): StrictMode.setThreadPolicy(new ThreadPolicy.Builder().detectAll().penaltyLog().build()); in App.onCreate at App.java:30-34 - no debug guard; runs in release. Owner: com.example.app (proprietary). Runtime hook confirms execution.",
  "reference": "jadx/sources/com/example/app/App.java:30-34",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0264",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S StrictMode enablement sites, G debug-guarded, N findings (production), U unverified. Any StrictMode used in production? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>; runtime hook confirms.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime hooking is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 StrictMode policy enablement quoted outside a debug-build guard. A finding stated with "likely"/"may" instead of the quoted call is INVALID -> `unverified`.
- **Debug guard clears it.** StrictMode inside `BuildConfig.DEBUG` / a debug variant is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: no production StrictMode use, with L2 coverage.
- `n/a`: no StrictMode APIs appear in code (state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its production-enablement L2 row.

Self-check before emitting (per finding)
For every Finding confirm: (1) the StrictMode enablement is quoted; (2) no debug-build guard restricts it; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the StrictMode search was performed (n/a state it), every site's guard was read and quoted (unresolved -> `unverified`), no debug-guarded site was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
