MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-5
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          WebViews execute JavaScript safely - controlled content sources when JS is enabled (static)

What this test looks for
A WebView is safe if JavaScript is disabled; if JavaScript IS enabled, then every loaded resource must be developer-controlled: all endpoints over HTTPS, JS/HTML loaded locally or from trusted servers, and the user must NOT be able to define the data sources that get loaded. This is a static, inventory-style evaluation over each WebView. Verdict: `pass` (JS disabled; OR JS enabled but content is developer-controlled - HTTPS, trusted sources, no user-definable input), `fail` (JS enabled while loading untrusted or user-definable content), `n/a` (the app uses no WebViews), or `inconclusive`.

SHORT-CIRCUIT (decide this first, per WebView): JavaScript is DISABLED by default in a WebView (`WebSettings.getJavaScriptEnabled()` is false unless set). A WebView with no `webSettings.setJavaScriptEnabled(true)` on its settings is JS-disabled -> automatic PASS for that WebView; do NOT analyze its content sources. Only when you can QUOTE a `setJavaScriptEnabled(true)` call applied to that WebView's settings does the loaded-content analysis below apply. Do not assume JS is enabled.

EVIDENCE DISCIPLINE (applies to every row)
1. **Every verdict-affecting disposition quotes the code it rests on** - Finding, Compliant, dismissal alike. Quote the `setJavaScriptEnabled(...)` call (with its boolean) and the `loadUrl`/`loadData`/`loadDataWithBaseURL` call plus the construction of the URL/content argument. A disposition with no quoted code is an assertion -> `unverified`.
2. **Read from the code, not the index.** An evidence index locates candidates; cite `jadx/sources/...:<line-range>` of the actual WebView setup and load calls, not the index record or line 1.
3. **No finding by inference/hedge/hypothetical.** A fail requires quoting (a) `setJavaScriptEnabled(true)` on that WebView, AND (b) the load call with its source argument shown to be user-definable/untrusted (traced to user input, an Intent extra/deep-link param, or a non-HTTPS/untrusted host). "likely loads user content", "may be untrusted", "if the URL were attacker-controlled" are NOT evidence -> `unverified`. A load of a developer-constant/HTTPS-trusted URL is Compliant, not a hypothetical finding.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the loaded URL/content is built elsewhere and you cannot trace its origin within budget, or trust of a host cannot be determined, the row is `unverified`. `false_positive_risks` is out-of-APK only; in-APK facts you did not resolve go in `unverified` rows.

What makes loaded content UNSAFE (when JS is enabled)
Source (untrusted/user-definable): a URL/content from `getIntent().getData()`/`getQueryParameter`/extras (deep link), user-entered text, a file path the user controls, a server response that itself carries an attacker-influenceable URL, or `file://`/`content://` pointing at user-writable storage. UNSAFE loads:
- WV1 - User-definable source: the URL/HTML passed to `loadUrl`/`loadData`/`loadDataWithBaseURL` is derived from user input / an Intent/deep-link param, so the user/another app defines what loads.
- WV2 - Untrusted / non-HTTPS endpoint: loads `http://` (cleartext) or an untrusted/third-party host not controlled by the developer, with JS enabled.
- WV3 - JS bridge exposure to untrusted content: `addJavascriptInterface(obj, name)` exposed while loading untrusted/user-definable content (the bridge object is reachable from attacker JS). (Report the bridge as an aggravating factor of WV1/WV2; on API<17 it is especially dangerous.)

The good pattern (do not flag)
- JS disabled (no `setJavaScriptEnabled(true)`) -> PASS short-circuit.
- JS enabled but the loaded source is developer-controlled: a constant/BuildConfig HTTPS URL to a first-party host, or local content (`file:///android_asset/...`, `file:///android_res/...`, bundled HTML, `loadData` with developer-authored HTML) -> Compliant. Quote the constant/local source.
- `setAllowFileAccess(false)`/`setAllowUniversalAccessFromFileURLs(false)` and a constant HTTPS load are hardening; not required for a pass but supportive.
- Library/SDK WebViews (e.g. an ad/IAP/login SDK's own WebView) configured by the library are the library's; focus on proprietary WebViews and any WebView the app itself configures + loads.

Procedure
1. Enumerate WebViews and their settings/loads, e.g. `grep -rEn "setJavaScriptEnabled|new WebView|WebView\(|loadUrl|loadData|loadDataWithBaseURL|addJavascriptInterface|getSettings\(\)" jadx/sources/`. If there are no WebViews, the verdict is `n/a`.
2. **Per WebView, resolve the JS state first.** Find whether `setJavaScriptEnabled(true)` is called on that WebView's `WebSettings`. If not (default false) -> Compliant (PASS short-circuit), quote the absence basis (the settings configured without it) or note no setJavaScriptEnabled call exists. If true -> proceed; quote the call.
3. For each JS-enabled WebView, read every `loadUrl`/`loadData`/`loadDataWithBaseURL` and trace the URL/content argument to its origin: developer constant/local (Compliant) vs user/Intent/untrusted/non-HTTPS (WV1/WV2). Quote the load call and the source construction. Note any `addJavascriptInterface` (WV3).
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per WebView: Compliant (JS disabled, OR JS enabled + developer-controlled HTTPS/local source - quoted); Finding (JS enabled + WV1/WV2 untrusted/user-definable source, quoted, optionally WV3); Unverified (load source untraceable, host trust indeterminate, owner unresolved); documented candidate (trust of a host justified only out-of-APK).
6. Budget ~2-4 reads per WebView (settings, each load, source construction) plus 1-2 call-graph hops. If the JS state, the load source, or the host trust can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
WebView content built/loaded in native code or a no-source SDK -> `unverified` (name the entry point). Whether a remote host is "trusted" can depend on facts outside the APK; a first-party HTTPS constant is trusted, an unknown third-party host loaded with JS enabled is at least `unverified` (or WV2 if clearly untrusted/cleartext). The static verdict is made on what was determinable.

Output
List **all** WebViews - one L1 row per WebView with its JS state and (if enabled) content-source disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant WebViews by functionality (e.g. "JS-disabled help viewers - 7", "JS-enabled first-party HTTPS dashboards - 5") as one L1 row per group, but always break out every Finding, documented-candidate, and unverified WebView as its own individual L1 row. Never sample findings.
- Finding: L1 row plus L2 rows for JS enabled (the `setJavaScriptEnabled(true)` quoted) and for the unsafe load (the `loadUrl`/`loadData` call + the source construction quoted, showing user-definable/untrusted/non-HTTPS), plus owner; note WV3 bridge if present.
- Compliant: L1 row plus L2 for JS disabled (no setJavaScriptEnabled(true)), OR for JS enabled + the quoted developer-controlled HTTPS/local source.
- Group: L1 summary plus an L2 naming references and the shared safe pattern.

```
{
  "id": "wv-001",
  "description": "Finding (WV1 user-definable source; JS enabled): A WebView with JavaScript enabled loads a URL taken from an incoming Intent extra, letting another app/user define what is rendered with JS active.",
  "reference": "jadx/sources/com/example/app/WebActivity.java",
  "level": 1
},
{
  "id": "L2-WebActivity-js",
  "description": "JS enabled (quoted): webView.getSettings().setJavaScriptEnabled(true) at line 40.",
  "reference": "jadx/sources/com/example/app/WebActivity.java:36-42",
  "level": 2
},
{
  "id": "L2-WebActivity-load",
  "description": "Unsafe load (quoted, WV1): String url = getIntent().getStringExtra(\"url\"); webView.loadUrl(url); at lines 44-46 - the loaded URL is an Intent extra (user/other-app definable), no host allowlist, no scheme check. WebActivity is exported with a VIEW filter, so the source is externally controllable.",
  "reference": "jadx/sources/com/example/app/WebActivity.java:44-48",
  "level": 2
},
{
  "id": "wv-jsdisabled-group",
  "description": "Compliant group: 7 WebViews with JavaScript disabled (default) used to render bundled help/HTML.",
  "reference": "jadx/sources/com/example/app/help/",
  "level": 1
},
{
  "id": "L2-jsdisabled-coverage",
  "description": "PASS short-circuit: none of these WebViews call setJavaScriptEnabled(true) (settings configured without it; quoted HelpViewer.java:22-30); they loadUrl(\"file:///android_asset/help/...\"). JS off -> safe regardless of content. References (7 sites).",
  "reference": "jadx/sources/com/example/app/help/HelpViewer.java:22-30",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "W WebViews enumerated, D JS-disabled (pass short-circuit), E JS-enabled (S developer-controlled/safe, N findings WV1/WV2/WV3), U unverified. <one or two sentences naming the WebViews, JS state and sources>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- **JS-disabled short-circuit.** A WebView with no quoted `setJavaScriptEnabled(true)` is Compliant (PASS) and its content sources are NOT analyzed. Do not assume JS is enabled; do not flag a JS-disabled WebView for its loaded content.
- `fail`: >=1 WebView with (a) an L2 row quoting `setJavaScriptEnabled(true)` AND (b) an L2 row quoting a `loadUrl`/`loadData`/`loadDataWithBaseURL` whose source is shown to be user-definable/untrusted/non-HTTPS (WV1/WV2), with the source construction quoted. A finding stated with "likely"/"may"/"if the URL were attacker-controlled" instead of the quoted JS-enable + traced unsafe source is INVALID -> `unverified`.
- **Read both before flagging; quote both. Do not flag developer-controlled loads or library WebViews.** A JS-enabled WebView loading a constant first-party HTTPS URL or local content is Compliant - quote the source. Resolve the URL origin; do not guess trust.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (host trust established outside the APK, content/flags delivered at runtime by server) - in-APK facts (is JS enabled? where does the URL come from?) resolved by reading, unresolved -> `unverified`. Reject "might load only trusted content", "might be JS-disabled in practice", "the host may be trusted".
- `pass`: WebViews exist and each is JS-disabled, or JS-enabled with developer-controlled HTTPS/local content (no user-definable source), with L2 coverage.
- `n/a`: no WebView (enumeration performed; state this).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its JS-enable + unsafe-source L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) `setJavaScriptEnabled(true)` is quoted for that WebView (not assumed); (2) the load call is quoted AND the source is traced/quoted as user-definable/untrusted/non-HTTPS (not a developer constant, not a hypothetical); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary), not a library WebView.
Hedge/hypothetical scan: "likely", "may", "appears", "if ... were", "could", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`: confirm every JS-enabled WebView's load source was read and quoted (unread -> `unverified`), no JS-disabled WebView was flagged for content, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.