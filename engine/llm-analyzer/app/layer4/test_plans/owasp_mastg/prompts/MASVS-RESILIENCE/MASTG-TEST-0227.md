MASTG-TEST-0227

maswe_id       MASWE-0067
masvs_v2_id    MASVS-RESILIENCE-2
platform       android
title          Debugging Enabled for WebViews - setWebContentsDebuggingEnabled(true) (static)

What this test looks for
`WebView.setWebContentsDebuggingEnabled(true)` enables remote debugging for ALL WebViews in the app; in production this lets a connected PC inspect/modify any WebView's content. It works independently of the manifest `debuggable` flag. The app must not enable it unconditionally - only inside a debug-build guard. This is a static evaluation. Verdict: `pass` (the API is never called with `true`, or only inside a debug guard), `fail` (>=1 unconditional/unguarded `setWebContentsDebuggingEnabled(true)`), `n/a` (the app uses no WebView), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `setWebContentsDebuggingEnabled`. If NONE appear -> WebView debugging is not enabled -> `pass` (or `n/a` if no WebView at all; state the search).

Guarded vs unguarded
- Compliant: `setWebContentsDebuggingEnabled(true)` called ONLY when a debug condition is true - `if (BuildConfig.DEBUG)`, `if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0)`, or a build-variant check. Or the call passes `false`. Or the call is absent.
- Finding: `setWebContentsDebuggingEnabled(true)` called unconditionally, or guarded only by a condition that does not restrict it to debug builds (e.g. a feature flag that ships enabled).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `setWebContentsDebuggingEnabled(true)` call AND the surrounding guard (or its absence). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the `true` call without a debug guard. "probably enables debugging" with no quoted call is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the guard condition can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "setWebContentsDebuggingEnabled|FLAG_DEBUGGABLE|BuildConfig\.DEBUG" jadx/sources/`. If no `setWebContentsDebuggingEnabled` -> short-circuit `pass`/`n/a` (state the search).
2. For each `setWebContentsDebuggingEnabled(...)` call, resolve the argument (true/false) and the enclosing guard. Quote it.
3. Classify: `true` with no debug guard (or a non-debug guard) -> finding; `true` inside a debug-build guard, or `false`, or absent -> Compliant. Quote the guard.
4. Owner: app (proprietary); a library enabling it for the app is reported.
5. Conclude per call: Finding (unguarded true, quoted); Compliant (guarded/false); Unverified (guard unresolved).
6. Budget ~2-3 reads per call (the call, the enclosing condition). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether a debugger actually attaches is runtime; this static test flags the unguarded enablement. WebView debug is independent of the manifest `debuggable` flag (MASTG-TEST-0226) - judge it separately. Calls in native/no-source code -> `unverified`.

Output
List **all** `setWebContentsDebuggingEnabled` calls - one L1 row per call with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant guarded/false calls, but always break out every Finding and unverified call individually. Never sample findings.
- Finding: L1 row plus an L2 quoting the unguarded `setWebContentsDebuggingEnabled(true)`, plus owner.
- Compliant: L1 row plus an L2 quoting the debug guard / `false` / absence.

```
{
  "id": "wvd-001",
  "description": "Finding (WebView debugging enabled in production): The app calls setWebContentsDebuggingEnabled(true) unconditionally at startup, so all WebViews are remotely debuggable.",
  "reference": "jadx/sources/com/example/app/App.java",
  "level": 1
},
{
  "id": "L2-wvd-call",
  "description": "Unguarded enable (quoted): WebView.setWebContentsDebuggingEnabled(true); in App.onCreate at App.java:28 - no BuildConfig.DEBUG / FLAG_DEBUGGABLE guard; always on. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/App.java:28",
  "level": 2
},
{
  "id": "wvd-ok-001",
  "description": "Compliant: WebView debugging enabled only in debug builds.",
  "reference": "jadx/sources/com/example/app/App2.java",
  "level": 1
},
{
  "id": "L2-wvd-ok",
  "description": "Guarded (quoted): if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true); at App2.java:30 - debug-only.",
  "reference": "jadx/sources/com/example/app/App2.java:30",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0227",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S setWebContentsDebuggingEnabled calls, G guarded by a debug check, N findings (unguarded true), U unverified. Any unguarded WebView debugging enablement? <no -> pass / n-a if no WebView / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 `setWebContentsDebuggingEnabled(true)` quoted without a debug-build guard. A finding stated with "likely"/"may" instead of the quoted call is INVALID -> `unverified`.
- **Debug guard clears it.** `true` inside `BuildConfig.DEBUG` / `FLAG_DEBUGGABLE` / a debug variant is Compliant. `false`, or no call, is Compliant.
- **Independent of manifest debuggable.** Do not pass an unguarded WebView-debug enable just because the app isn't marked debuggable - this API works regardless.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (true? guarded?) resolved by reading, unresolved -> `unverified`.
- `pass`: the API is never enabled, or only under a debug guard, with L2 coverage.
- `n/a`: no WebView appears in code (state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its unguarded-call L2 row.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `setWebContentsDebuggingEnabled(true)` call is quoted; (2) no debug-build guard restricts it; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the search was performed (state it), every call's argument and guard were read and quoted (unresolved -> `unverified`), no guarded/false call was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
