MASTG-TEST-0252

maswe_id       MASWE-0069
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          References to Local File Access in WebViews - JS reading local files across origins (static)

What this test looks for
A WebView with JavaScript enabled, local file access enabled, AND file-URL cross-origin access enabled lets a malicious local HTML file read other local files (e.g. `file:///data/data/<pkg>/files/api-key.txt`) and exfiltrate them, bypassing the same-origin policy. The dangerous combination involves `setAllowFileAccess`, plus EITHER `setAllowFileAccessFromFileURLs` OR `setAllowUniversalAccessFromFileURLs`. These have secure defaults and are deprecated on API 29+, but can be explicitly set, or inherit insecure defaults on old `minSdkVersion`. This is a static evaluation of WebView settings (with minSdk-aware defaults). Verdict: `pass` (no WebView combines the dangerous settings), `fail` (>=1 WebView has the dangerous combination), `n/a` (the app uses no WebView), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `WebView`/`WebSettings`/`getSettings`. If NONE appear -> `n/a` (no WebView; state the search). The ABSENCE of `setAllow*` calls is itself interesting (defaults may be insecure on old minSdk) - capture it.

The failure condition (ALL must hold; minSdk-aware defaults)
1. `setJavaScriptEnabled(true)` is explicitly set, AND
2. `setAllowFileAccess(true)` is explicitly set, OR not used when `minSdkVersion < 30` (default `true` below API 30; default `false` on API 30+), AND
3. EITHER `setAllowFileAccessFromFileURLs(true)` OR `setAllowUniversalAccessFromFileURLs(true)` is explicitly set, OR not used when `minSdkVersion < 16` (default `true` below API 16).
Note: `setAllowFileAccessFromFileURLs` is IGNORED if `setAllowUniversalAccessFromFileURLs(true)`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote each relevant setting (or note its default with the minSdk justification) on the WebView. No quoted code/default-basis -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the settings and `jadx/resources/AndroidManifest.xml` for minSdk, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires the three conditions met (explicit or default-with-minSdk-basis) on one WebView. "probably reads files" with no quoted settings/defaults is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If settings can't be tied to a WebView or minSdk can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Resolve `minSdkVersion` (manifest `<uses-sdk>` / `app_metadata.json`) - it determines the defaults. State it.
2. Enumerate WebView settings: `grep -rEn "WebView|getSettings|setJavaScriptEnabled|setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs" jadx/sources/`. Capture ABSENCES too (default applies). If no WebView -> short-circuit `n/a` (state the search).
3. For each WebView instance, resolve the three conditions using explicit values OR the minSdk-aware defaults. Quote each (note "default true, minSdk<30" etc.). Apply the universal-overrides-file note.
4. Note whether the WebView loads `file://` content (`loadUrl("file://...")`, `loadDataWithBaseURL` with a file base) - the attack needs a local-file context; strengthens the finding.
5. Owner: app (proprietary).
6. Conclude per WebView: Finding (all three met, quoted/justified); Compliant (any condition safe); Unverified (settings/instance/minSdk unresolved).
7. Budget ~3-5 reads per WebView. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Runtime config of dynamic WebViews is MASTG-TEST-0253. Content-provider access is MASTG-TEST-0250; JS bridges MASTG-TEST-0334. WebView logic in native/no-source code -> `unverified`.

Output
List **all** WebView instances - one L1 row per WebView with its disposition. Capture absent `setAllow*` calls explicitly (default basis). <=20 -> one L1 row each. >20 (collapse) -> group Compliant WebViews, but always break out every Finding and unverified WebView individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the three conditions (explicit or default-with-minSdk) and any `file://` load, plus owner.
- Compliant: L1 row plus an L2 showing a safe condition (e.g. file access disabled, or no cross-origin file-URL access).

```
{
  "id": "lfwv-001",
  "description": "Finding (WebView allows cross-origin local file reads): A WebView enables JS, file access, and universal file-URL access, and loads a local HTML file - malicious local HTML could read and exfiltrate other private files.",
  "reference": "jadx/sources/com/example/app/web/Report.java",
  "level": 1
},
{
  "id": "L2-lfwv-settings",
  "description": "Dangerous combo (quoted): s.setJavaScriptEnabled(true) (Report.java:30); s.setAllowFileAccess(true) (line 31); s.setAllowUniversalAccessFromFileURLs(true) (line 32). Loads local content: webView.loadUrl(\"file:///android_asset/report.html\") (line 36). minSdkVersion=24.",
  "reference": "jadx/sources/com/example/app/web/Report.java:30-36",
  "level": 2
},
{
  "id": "lfwv-ok-001",
  "description": "Compliant: WebView disables file access.",
  "reference": "jadx/sources/com/example/app/web/Safe.java",
  "level": 1
},
{
  "id": "L2-lfwv-ok",
  "description": "Safe setting (quoted): s.setAllowFileAccess(false) at Safe.java:22 - local files not loadable; cross-origin file-URL access is moot.",
  "reference": "jadx/sources/com/example/app/web/Safe.java:22",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0252",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "minSdkVersion=<N>. W WebView instances, D with the dangerous combo (JS + file-access(explicit/default) + file-URL-cross-origin(explicit/default)), N findings, C compliant, U unverified. Any WebView allowing cross-origin local file reads? <no -> pass/n-a / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime config is MASTG-TEST-0253); it does not change `pass`/`fail`.
- `fail`: >=1 WebView with all three conditions met (explicit values, or minSdk-aware defaults with the basis quoted): JS true, file access true/default(<30), and file-URL cross-origin true/default(<16). A finding stated with "likely"/"may" instead of quoted settings/defaults is INVALID -> `unverified`.
- **minSdk-aware defaults.** Absence of `setAllowFileAccess` is `true` only when `minSdk < 30`; absence of the file-URL settings is `true` only when `minSdk < 16`. State minSdk and the default basis. Do not assume an insecure default without the minSdk justification.
- **universal overrides file.** `setAllowUniversalAccessFromFileURLs(true)` makes `setAllowFileAccessFromFileURLs` irrelevant - treat universal=true as satisfying condition 3.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (settings? minSdk?) resolved by reading, unresolved -> `unverified`.
- `pass`: no WebView combines the dangerous settings (a safe condition holds), with L2 coverage.
- `n/a`: no WebView appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if minSdk-default reasoning is asserted without stating minSdk, if any false_positive_risk references in-APK code, or if any `fail` lacks its three-condition L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) JS-enabled is quoted; (2) file access is quoted true or justified as default-true with minSdk<30; (3) a file-URL cross-origin setting is quoted true or justified as default-true with minSdk<16 (or universal=true); (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the WebView search was performed (n/a state it), minSdk resolved, every finding WebView's three conditions were read/justified (unresolved -> `unverified`), no WebView with a safe condition was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
