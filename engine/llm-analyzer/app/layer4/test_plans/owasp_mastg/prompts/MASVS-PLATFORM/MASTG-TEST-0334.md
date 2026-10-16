MASTG-TEST-0334

maswe_id       MASWE-0069
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          Native Code Exposed Through WebViews - addJavascriptInterface bridge (static)

What this test looks for
A legacy WebView-Native bridge registered with `addJavascriptInterface(obj, name)` exposes the public `@JavascriptInterface`-annotated methods of `obj` to JavaScript running in the WebView. If JS is enabled, the bridge exists, and any exposed method handles sensitive data/actions while the WebView can load untrusted content, attacker-controlled JS can invoke native functionality. This is a static evaluation. Verdict: `pass` (no exposed bridge is reachable from untrusted content with sensitive methods), `fail` (>=1 WebView has JS enabled + `addJavascriptInterface` + a sensitive `@JavascriptInterface` method reachable from untrusted content), `n/a` (the app uses no WebView, or no JS bridge), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `addJavascriptInterface`. If NONE appear -> `n/a` (no JS bridge; state the search).

The failure condition (ALL must hold)
1. `setJavaScriptEnabled(true)` is explicitly set (default is false; the bridge needs JS), AND
2. `addJavascriptInterface(...)` is used at least once, AND
3. At least one method annotated `@JavascriptInterface` on the exposed object handles sensitive data or actions AND is reachable from untrusted content (the WebView can load arbitrary/weakly-validated URLs, or the content origin is not allowlisted).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote `setJavaScriptEnabled(true)`, the `addJavascriptInterface(...)`, the `@JavascriptInterface` method(s) and what they do, AND the loaded content / URL validation. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of each, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the three conditions, including a sensitive bridge method AND untrusted-content reachability. "the bridge might be reachable" with no quoted loadUrl/validation is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the bridge object/methods or the loaded content can't be resolved (wrappers, reflection, dynamic WebViews), the row is `unverified`. `false_positive_risks` is out-of-APK only.

What "reachable from untrusted content" means
The WebView loads arbitrary or weakly-validated URLs (e.g. `loadUrl` of a remote URL from input, redirects, third-party content), or there is no origin allowlist. A WebView that loads only a fixed, trusted, app-bundled asset (and never navigates to untrusted origins) is lower risk - note it; the bridge is still reported but reachability tempers the verdict.

Procedure
1. Enumerate bridges: `grep -rEn "addJavascriptInterface|@JavascriptInterface|JavascriptInterface|setJavaScriptEnabled|loadUrl|loadDataWithBaseURL" jadx/sources/`. If no `addJavascriptInterface` -> short-circuit `n/a` (state the search).
2. For each bridge, confirm JS is enabled on that WebView (quote it). Identify the exposed object and read its `@JavascriptInterface` methods - do any handle sensitive data (tokens, files, PII) or security-relevant actions (start intents, write files, exec)? Quote them.
3. Assess content reachability: what does the WebView load? Arbitrary/remote/weakly-validated -> reachable from untrusted content (finding); fixed trusted asset with no untrusted navigation -> lower-risk (note). Quote the load + any allowlist.
4. Owner: app-declared (proprietary); a library WebView/bridge handling app data is reported.
5. Conclude per bridge: Finding (JS + bridge + sensitive method + untrusted reachability, quoted); Compliant (no sensitive method, or only-trusted-content with no untrusted navigation); Unverified (object/methods/content unresolved).
6. Budget ~3-6 reads per bridge (the addJavascriptInterface, the interface class methods, the loadUrl/validation). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Parametrized/indirect bridge registration, reflection, obfuscation, and dynamically-created WebViews may defeat static resolution -> `unverified` (name the entry point; recommend dynamic). Content-provider/file access settings are MASTG-TEST-0250/0252. This test is the JS-Native BRIDGE.

Output
List **all** `addJavascriptInterface` bridges - one L1 row per bridge with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant trusted-only bridges, but always break out every Finding and unverified bridge individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting JS-enabled, the bridge registration, the sensitive `@JavascriptInterface` method, and the untrusted-content reachability, plus owner.
- Compliant: L1 row plus an L2 showing no sensitive method, or trusted-only content.

```
{
  "id": "jsb-001",
  "description": "Finding (native bridge reachable from untrusted content): A WebView with JS enabled exposes a bridge whose @JavascriptInterface method returns the auth token, and the WebView loads remote URLs - attacker JS could call it.",
  "reference": "jadx/sources/com/example/app/web/BridgeActivity.java",
  "level": 1
},
{
  "id": "L2-jsb-setup",
  "description": "JS + bridge (quoted): s.setJavaScriptEnabled(true) (BridgeActivity.java:30); webView.addJavascriptInterface(new AppBridge(), \"Android\") (line 33).",
  "reference": "jadx/sources/com/example/app/web/BridgeActivity.java:30-33",
  "level": 2
},
{
  "id": "L2-jsb-method",
  "description": "Sensitive bridge method (quoted): @JavascriptInterface public String getToken(){ return session.getAuthToken(); } in AppBridge at AppBridge.java:14-17 - exposes the auth token to JS.",
  "reference": "jadx/sources/com/example/app/web/AppBridge.java:14-17",
  "level": 2
},
{
  "id": "L2-jsb-reach",
  "description": "Untrusted reachability (quoted): webView.loadUrl(getIntent().getStringExtra(\"url\")) at BridgeActivity.java:40 - loads a caller-supplied URL with no origin allowlist, so untrusted content can call Android.getToken(). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/web/BridgeActivity.java:40",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0334",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "B addJavascriptInterface bridges, J with JS enabled, M with a sensitive @JavascriptInterface method, R reachable from untrusted content, N findings, C compliant, U unverified. Any sensitive bridge reachable from untrusted content? <no -> pass/n-a / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (set true where bridge/content resolution needs runtime); it does not change `pass`/`fail`.
- `fail`: >=1 WebView with (a) JS enabled, (b) `addJavascriptInterface` used, AND (c) a sensitive `@JavascriptInterface` method reachable from untrusted content - all quoted. A finding stated with "likely"/"may" instead of the quoted four is INVALID -> `unverified`.
- **Sensitive method AND reachability required.** A bridge with only benign methods, or a WebView that loads only fixed trusted content with no untrusted navigation, is Compliant/lower-risk - note it, don't fail.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (sensitive method? untrusted content?) resolved by reading, unresolved -> `unverified`.
- `pass`: no sensitive bridge is reachable from untrusted content, with L2 coverage.
- `n/a`: no `addJavascriptInterface` appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its JS + bridge + sensitive-method + reachability L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) JS-enabled is quoted; (2) the `addJavascriptInterface` registration is quoted; (3) a sensitive `@JavascriptInterface` method is quoted; (4) untrusted-content reachability is quoted (arbitrary/weakly-validated load, no allowlist); (5) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the bridge search was performed (n/a state it), every finding bridge's four conditions were read and quoted (unread -> `unverified`), no benign/trusted-only bridge was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
