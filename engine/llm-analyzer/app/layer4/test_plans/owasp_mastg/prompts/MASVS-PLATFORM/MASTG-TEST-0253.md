MASTG-TEST-0253

maswe_id       MASWE-0069
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          Runtime Use of Local File Access APIs in WebViews (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0253 is a dynamic test (hook the WebView file-access setting setters at runtime and observe effective values per instance, with backtraces). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0252 (the dangerous local-file-access combination, with minSdk-aware defaults). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; runtime hooking resolves dynamically-created WebViews and confirms the effective settings and whether a `file://` page is actually loaded.

What this test looks for
At runtime no WebView should let local-file JavaScript read other local files across origins. Statically, the proxy is the same dangerous combination as MASTG-TEST-0252. Verdict: `pass` (no WebView combines the dangerous settings), `fail` (>=1 WebView has the combination), `n/a` (no WebView), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `WebView`/`getSettings`. If NONE appear -> `n/a` (state the search). Runtime config is still flagged via the forced `needs_dynamic_testing`.

The failure condition (ALL must hold; minSdk-aware defaults)
1. `setJavaScriptEnabled(true)`, AND
2. `setAllowFileAccess(true)` OR not set when `minSdkVersion < 30` (default true below API 30), AND
3. `setAllowFileAccessFromFileURLs(true)` OR `setAllowUniversalAccessFromFileURLs(true)`, OR not set when `minSdkVersion < 16` (default true below API 16).
(`setAllowFileAccessFromFileURLs` is ignored if universal=true.)

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote each relevant setting (or its default with minSdk basis). No quoted code/basis -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` and `jadx/resources/AndroidManifest.xml` for minSdk, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires the three conditions on one WebView. "probably reads files" with no quoted settings is NOT static evidence -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`, not a hedge.** Dynamically-created WebViews whose settings can't be tied statically -> `unverified` (the hook resolves them). `false_positive_risks` is out-of-APK only.

Procedure
1. Resolve `minSdkVersion` (manifest / app_metadata.json). State it.
2. Enumerate WebView settings: `grep -rEn "WebView|getSettings|setJavaScriptEnabled|setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|loadUrl|loadDataWithBaseURL" jadx/sources/`. Capture absences (defaults). If no WebView -> short-circuit `n/a` (state the search).
3. For each WebView instance, resolve the three conditions (explicit or minSdk default). Tie settings to the same instance; unresolved -> `unverified`. Note any `file://` load. Quote each.
4. Owner: app (proprietary).
5. Conclude per WebView: Finding (three conditions met, quoted/justified); Compliant (a safe condition); Unverified (instance/settings/minSdk unresolved -> confirm via hook).
6. Budget ~3-5 reads per WebView. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Dynamic WebView config is the dynamic test's strength - hence the forced `needs_dynamic_testing`. Content-provider access is MASTG-TEST-0250/0251; JS bridges MASTG-TEST-0334.

Output
List **all** WebView instances - one L1 row per WebView with its disposition. Always break out every Finding and unverified WebView individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the three conditions and any `file://` load, plus owner.
- Compliant: L1 row plus an L2 showing a safe condition.

```
{
  "id": "lfwvr-001",
  "description": "Finding (runtime local file access combo): A WebView configured via a shared helper enables JS and universal file-URL access with file access at default - local-file JS could read other files at runtime.",
  "reference": "jadx/sources/com/example/app/web/WebHelper.java",
  "level": 1
},
{
  "id": "L2-lfwvr-settings",
  "description": "Dangerous combo (quoted): applyDefaults(s){ s.setJavaScriptEnabled(true); s.setAllowUniversalAccessFromFileURLs(true);} at WebHelper.java:40-43; setAllowFileAccess not called -> default true (minSdkVersion=23 < 30). Used by the report WebView loading file:///... (Report.java:35). Runtime hook confirms per-instance effective values.",
  "reference": "jadx/sources/com/example/app/web/WebHelper.java:40-43",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0253",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "minSdkVersion=<N>. W WebView instances, D with the dangerous combo, N findings, C compliant, U unverified (unresolved instances). Any WebView allowing cross-origin local file reads? <no -> pass/n-a / yes -> fail>. <one or two sentences>; runtime hook confirms per-instance config.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime hooking is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 WebView with all three conditions met (explicit or minSdk-aware default, basis quoted): JS true, file access true/default(<30), file-URL cross-origin true/default(<16). A finding stated with "likely"/"may" instead of quoted settings/defaults is INVALID -> `unverified`.
- **minSdk-aware defaults / universal-overrides-file** as in MASTG-TEST-0252. State minSdk; do not assume an insecure default without it.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved instances -> `unverified`.
- `pass`: no WebView combines the dangerous settings, with L2 coverage.
- `n/a`: no WebView appears in code (short-circuit; state the search).
- `unverified` rows name the unresolved instance/entry point. Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if minSdk-default reasoning is asserted without stating minSdk, if any false_positive_risk references in-APK code, or if any `fail` lacks its three-condition L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) JS-enabled is quoted; (2) file access is quoted true or justified default-true (minSdk<30); (3) a file-URL cross-origin setting is quoted true or justified default-true (minSdk<16) or universal=true; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the WebView search was performed (n/a state it), minSdk resolved, every finding WebView's three conditions were read/justified (unresolved instance -> `unverified`), no WebView with a safe condition was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
