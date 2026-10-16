MASTG-TEST-0250

maswe_id       MASWE-0069
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          References to Content Provider Access in WebViews - JS reaching content:// URIs (static)

What this test looks for
A WebView with JavaScript enabled, content access enabled, AND universal file-URL access enabled lets JavaScript loaded from a `file://` origin reach the device's content providers via `content://` URIs - potentially reading the app's own (even non-exported) providers and exported providers of other apps. The dangerous combination is all three together. This is a static evaluation of WebView settings + the app's content providers. Verdict: `pass` (no WebView combines the three dangerous settings, or content providers expose nothing sensitive), `fail` (>=1 WebView has all three settings AND the app's content providers handle sensitive data), `n/a` (the app uses no WebView), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `WebView`/`WebSettings`/`getSettings`. If NONE appear -> `n/a` (no WebView; state the search).

The failure condition (ALL must hold)
1. `setJavaScriptEnabled(true)` is explicitly set, AND
2. `setAllowContentAccess(true)` is set OR not used at all (default is `true`), AND
3. `setAllowUniversalAccessFromFileURLs(true)` is explicitly set (this relaxes CORS so `file://`-origin pages can read `content://`).
AND the app declares content providers that handle sensitive data (use the provider list to confirm sensitivity). Note: `setAllowContentAccess` defaults to `true` regardless of Android version, so its ABSENCE still satisfies condition 2.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote each of the three WebView settings (or note the default) AND the sensitive content provider(s). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the WebView settings and `jadx/resources/AndroidManifest.xml` for providers, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the three settings (or the default for #2) on one WebView AND a sensitive provider. "probably reachable" with no quoted settings is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If a setting can't be resolved for a WebView instance, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate WebView settings: `grep -rEn "WebView|getSettings|setJavaScriptEnabled|setAllowContentAccess|setAllowUniversalAccessFromFileURLs" jadx/sources/`. If no WebView -> short-circuit `n/a` (state the search).
2. For each WebView instance, resolve all three settings: JS enabled? content access (explicit true, or absent=default true)? universal file-URL access true? Quote each (note defaults). Tie settings to the SAME WebView instance where possible (settings may be in different methods).
3. List content providers (`grep -nE "<provider" jadx/resources/AndroidManifest.xml`) and assess whether any handle sensitive data (the app's own providers count even if not exported). Quote the providers.
4. A finding requires the three settings on one WebView AND >=1 sensitive provider reachable. Also note whether the WebView loads `file://` content (the attack needs a file-origin page) - strengthens the finding.
5. Owner: app-declared (proprietary).
6. Conclude per WebView: Finding (three settings + sensitive provider, quoted); Compliant (any of the three settings safe, or no sensitive provider); Unverified (settings/instance unresolved).
7. Budget ~3-5 reads per WebView (the settings calls, the loadUrl, the providers). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The runtime configuration of dynamically-created WebViews is MASTG-TEST-0251. Local file access (not content://) is MASTG-TEST-0252; JS bridges are MASTG-TEST-0334. WebView logic in native/no-source code -> `unverified`.

Output
List **all** WebView instances - one L1 row per WebView with its disposition - plus one L1 row listing the app's content providers and their sensitivity. <=20 -> one L1 row each. >20 (collapse) -> group Compliant WebViews, but always break out every Finding and unverified WebView individually. Never sample findings.
- Providers: L1 row listing declared content providers and whether they handle sensitive data.
- Finding: L1 row plus L2 rows quoting the three settings and the sensitive provider (and `file://` load if present), plus owner.
- Compliant: L1 row plus an L2 showing one of the three settings is safe, or no sensitive provider.

```
{
  "id": "cpwv-001",
  "description": "Finding (WebView can reach sensitive content providers): A WebView enables JavaScript, leaves content access at its default (true), and enables universal file-URL access, while the app exposes a sensitive content provider - file-origin JS could read content:// data.",
  "reference": "jadx/sources/com/example/app/web/DocViewer.java",
  "level": 1
},
{
  "id": "L2-cpwv-settings",
  "description": "Dangerous trio (quoted): s.setJavaScriptEnabled(true) (DocViewer.java:30); setAllowContentAccess NOT called -> default true; s.setAllowUniversalAccessFromFileURLs(true) (DocViewer.java:33). WebView loads a local file: webView.loadUrl(\"file:///android_asset/doc.html\") (line 38).",
  "reference": "jadx/sources/com/example/app/web/DocViewer.java:30-38",
  "level": 2
},
{
  "id": "L2-cpwv-provider",
  "description": "Sensitive provider (quoted): <provider android:name=\".NotesProvider\" android:authorities=\"com.example.app.notes\"/> at AndroidManifest.xml:58 serving the notes table (private user notes) - reachable via content:// from the file-origin page. Owner: com.example.app (proprietary).",
  "reference": "jadx/resources/AndroidManifest.xml:58",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0250",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "W WebView instances, T with the dangerous trio (JS + content-access(default/true) + universal-file-URL), providers: <list, sensitive?>. N findings (trio + sensitive provider), C compliant, U unverified. Any WebView reaching sensitive providers? <no -> pass/n-a / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime config is MASTG-TEST-0251); it does not change `pass`/`fail`.
- `fail`: >=1 WebView with (a) L2 quoting JS-enabled AND content-access (explicit true OR absent default) AND universal-file-URL-access true, AND (b) an L2 quoting a content provider handling sensitive data. A finding stated with "likely"/"may" instead of the quoted trio+provider is INVALID -> `unverified`.
- **All three, plus a sensitive provider.** Missing any of the three settings (e.g. universal file-URL access not enabled, or JS disabled) -> Compliant. `setAllowContentAccess` ABSENT still counts (default true) for condition 2. No sensitive provider -> Compliant (per OWASP, content access alone is not a vuln).
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (the three settings? sensitive provider?) resolved by reading, unresolved -> `unverified`.
- `pass`: no WebView combines the trio with a sensitive provider, with L2 coverage.
- `n/a`: no WebView appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its trio + sensitive-provider L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) all three settings are quoted (or the default noted for content access) on the SAME WebView; (2) a sensitive content provider is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the WebView search was performed (n/a state it), every finding WebView's three settings and a sensitive provider were read and quoted (unread -> `unverified`), no WebView missing one of the trio was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
