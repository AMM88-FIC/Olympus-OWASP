MASTG-TEST-0265

maswe_id       MASWE-0094
masvs_v2_id    MASVS-RESILIENCE-2
platform       android
title          References to StrictMode APIs - StrictMode enabled in production (static)

What this test looks for
`StrictMode` logs policy violations (disk I/O, network on main thread, leaked resources). Useful in development, but in a PRODUCTION build it can expose sensitive implementation details in logs that aid an attacker. This test checks whether the app enables StrictMode (especially with a logging penalty) outside a debug guard. Verdict: `pass` (no StrictMode use, or only inside a debug-build guard), `fail` (>=1 StrictMode policy enabled unconditionally / in production, especially with `penaltyLog`), `n/a` (no StrictMode APIs at all), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `StrictMode`. If NONE appear -> `n/a` (state the search).

Debug-guarded vs production
- Compliant: StrictMode set ONLY inside `if (BuildConfig.DEBUG)` / a debug-variant guard.
- Finding: StrictMode policy (`setThreadPolicy`/`setVmPolicy` with `penaltyLog`/`penaltyDeath`/`detectAll`) enabled unconditionally or guarded by a non-debug condition, so it runs in production.

StrictMode sinks
`StrictMode.setThreadPolicy(...)`, `StrictMode.setVmPolicy(...)`, `StrictMode.ThreadPolicy.Builder`/`VmPolicy.Builder` with `detectAll`/`detect*` + `penaltyLog`/`penaltyDeath`/`penaltyDropBox`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the StrictMode policy enablement AND the surrounding guard (or its absence). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the unconditional/production StrictMode enablement. "probably leaves StrictMode on" with no quoted call is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the guard can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "StrictMode|setThreadPolicy|setVmPolicy|penaltyLog|penaltyDeath|detectAll|BuildConfig\.DEBUG" jadx/sources/`. If no StrictMode -> short-circuit `n/a` (state the search).
2. For each StrictMode enablement, resolve the enclosing guard. Quote it.
3. Classify: enabled outside a debug guard (production) -> finding; debug-guarded -> Compliant. Quote the guard.
4. Owner: app (proprietary); a library is reported.
5. Conclude per site: Finding (production StrictMode, quoted); Compliant (debug-guarded); Unverified (guard unresolved).
6. Budget ~2-3 reads per site. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether violations are actually logged at runtime is MASTG-TEST-0263/0264 (dynamic). StrictMode in native/no-source code -> `unverified`. This test is the static REFERENCE to StrictMode enablement.

Output
List **all** StrictMode enablement sites - one L1 row per site with its disposition.
- Finding: L1 row plus an L2 quoting the production StrictMode enablement (and the missing/non-debug guard), plus owner.
- Compliant: L1 row plus an L2 quoting the debug guard.

```
{
  "id": "sm-001",
  "description": "Finding (StrictMode enabled in production): The app sets a VmPolicy with penaltyLog unconditionally, leaking implementation details into logs in release builds.",
  "reference": "jadx/sources/com/example/app/App.java",
  "level": 1
},
{
  "id": "L2-sm-call",
  "description": "Production StrictMode (quoted): StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().detectAll().penaltyLog().build()); in App.onCreate at App.java:30-34 - no BuildConfig.DEBUG guard. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/App.java:30-34",
  "level": 2
},
{
  "id": "sm-ok-001",
  "description": "Compliant: StrictMode enabled only in debug builds.",
  "reference": "jadx/sources/com/example/app/App2.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0265",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S StrictMode enablement sites, G debug-guarded, N findings (production/unguarded), U unverified. Any StrictMode enabled in production? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime is MASTG-TEST-0263/0264); it does not change `pass`/`fail`.
- `fail`: >=1 StrictMode policy enablement quoted outside a debug-build guard (production). A finding stated with "likely"/"may" instead of the quoted call is INVALID -> `unverified`.
- **Debug guard clears it.** StrictMode inside `BuildConfig.DEBUG` / a debug variant is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (enabled? guarded?) resolved by reading, unresolved -> `unverified`.
- `pass`: no StrictMode use, or only debug-guarded, with L2 coverage.
- `n/a`: no StrictMode APIs appear in code (state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its production-enablement L2 row.

Self-check before emitting (per finding)
For every Finding confirm: (1) the StrictMode enablement is quoted; (2) no debug-build guard restricts it; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the StrictMode search was performed (n/a state it), every site's guard was read and quoted (unresolved -> `unverified`), no debug-guarded site was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
