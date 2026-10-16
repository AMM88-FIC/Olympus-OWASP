MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-6
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          WebView uses minimal protocol handlers and disables the dangerous ones (file access hardening) (static)

What this test looks for
A WebView must enable only the protocol handlers it needs and disable the dangerous ones (file access and file-URL cross-access in particular). Concretely: the app should target API >= 30 (where `setAllowFileAccess` defaults to false); on API <= 29 it must call `setAllowFileAccess(false)` (or document a justification); the cross-file-access settings must not be enabled; and only necessary handlers are on. This is a static, inventory-style evaluation over each WebView's settings. Verdict: `pass` (only necessary handlers enabled; dangerous ones disabled or justified; file access restricted), `fail` (dangerous handlers enabled without justification, or file access left improperly open), `n/a` (the app uses no WebViews), or `inconclusive`.

EVIDENCE DISCIPLINE (applies to every row)
1. **Every verdict-affecting disposition quotes the code/manifest it rests on** - Finding, Compliant, dismissal alike. Quote the `WebSettings` setter call (with its boolean) and the manifest `targetSdkVersion`. A disposition with no quoted setting/targetSdk is an assertion -> `unverified`.
2. **Read from the code, not the index.** An evidence index locates candidates; cite `jadx/sources/...:<line-range>` of the actual WebView settings configuration, not the index record or line 1.
3. **No finding by inference/hedge.** A fail requires QUOTING either (a) a dangerous setting explicitly set to true, or (b) the absence of `setAllowFileAccess(false)` on `targetSdk <= 29` (with the targetSdk quoted). "likely allows file access", "may be open", "file access is probably enabled" are NOT evidence -> `unverified`. Crucially, do NOT infer a finding from the mere ABSENCE of a setter when the API default is already safe (see the defaults table).
4. **Unresolved determinacy is `unverified`, not a hedge.** If settings are applied via a runtime-built config or a helper you cannot trace within budget, the row is `unverified`. `false_positive_risks` is out-of-APK only; in-APK facts you did not resolve go in `unverified` rows.

API defaults you MUST apply (do not flag a setting whose safe state is the default)
- `setAllowFileAccess`: defaults to **false on targetSdk >= 30**, **true on targetSdk <= 29**. So: absence of the call is SAFE on >= 30; absence on <= 29 means file access is ON (finding unless `setAllowFileAccess(false)` is called or justified). A finding here requires either an explicit `setAllowFileAccess(true)`, or the absence of `setAllowFileAccess(false)` on targetSdk <= 29 - quoted.
- `setAllowFileAccessFromFileURLs` and `setAllowUniversalAccessFromFileURLs`: default to **false on API >= 16**. These are only a finding when EXPLICITLY set to true. Do NOT flag their absence.
- `setAllowContentAccess`: defaults to true; relevant only if `content://` access is unnecessary and exposes user-writable content - judge by use, not by default presence.
- `setJavaScriptEnabled`: defaults to false (covered by the separate WebView-JS test; note interaction but this test is about handlers/file access).

Dangerous handlers / settings (a finding when enabled without justification on a WebView)
- DH1 - File access open improperly: `setAllowFileAccess(true)` (explicit), OR no `setAllowFileAccess(false)` on `targetSdk <= 29` - the WebView can load `file://` resources. Aggravated if JS is enabled and untrusted content can be loaded.
- DH2 - Cross file-URL access enabled: `setAllowFileAccessFromFileURLs(true)` or `setAllowUniversalAccessFromFileURLs(true)` - a loaded file/page can read other local files (or any origin) - high risk, especially with JS enabled.
- DH3 - Unnecessary/dangerous scheme handlers: the WebView (or a custom `WebViewClient.shouldOverrideUrlLoading`/`shouldInterceptRequest`) handles dangerous schemes it does not need - `file:`, `tel:`, `app-id`/custom intent schemes, `content:` to user storage - without restriction, beyond the minimum necessary. Judge by whether the handler is needed and whether it is restricted.

The good pattern (do not flag)
- targetSdk >= 30 with no `setAllowFileAccess(true)` and no explicit cross-access enable -> file access is off by default -> Compliant. Quote the targetSdk and the absence of an explicit-true.
- `setAllowFileAccess(false)` explicitly called (any targetSdk) -> Compliant.
- Cross-access settings not set (default false) -> Compliant; do not flag absence.
- Only necessary handlers enabled; a `WebViewClient` that restricts/whitelists schemes -> Compliant (quote the restriction).
- Library/SDK WebViews configured by the library -> the library's; focus on proprietary WebViews the app configures.

Procedure
1. Read `AndroidManifest.xml` `targetSdkVersion`. Enumerate WebView settings, e.g. `grep -rEn "setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setAllowContentAccess|getSettings\(\)|new WebView|WebViewClient|shouldOverrideUrlLoading|shouldInterceptRequest" jadx/sources/`. If there are no WebViews, the verdict is `n/a`.
2. Per WebView, read its `WebSettings` configuration and quote the relevant setters. Apply the defaults table: only treat a setting as unsafe if it is explicitly enabled, OR (for `setAllowFileAccess`) absent on targetSdk <= 29.
3. Check scheme handling: read any custom `WebViewClient.shouldOverrideUrlLoading`/`shouldInterceptRequest` for which schemes it accepts and whether dangerous ones (`file:`/`tel:`/custom intent) are handled beyond need. Quote the handler.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per WebView: Compliant (file access off by default on >=30 / explicitly false / cross-access default-false / minimal restricted handlers - quoted); Finding (DH1-DH3 with the explicit-true setter or the targetSdk<=29-absence quoted); Unverified (settings runtime-built/untraceable, owner unresolved); documented candidate (file access / a handler justified only by an out-of-APK design doc).
6. Budget ~2-4 reads per WebView (manifest targetSdk once, the settings block, the WebViewClient). If the settings, targetSdk effect, or owner can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
WebView configuration in native code or a no-source SDK -> `unverified` (name the entry point). The static verdict is made on what was determinable.

Output
List **all** WebViews - one L1 row per WebView with its protocol-handler / file-access disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant WebViews by functionality (e.g. "targetSdk 31, file access default-off - 9") as one L1 row per group, but always break out every Finding, documented-candidate, and unverified WebView as its own individual L1 row. Never sample findings.
- Finding: L1 row plus L2 rows for the dangerous setting (the explicit-true setter quoted, OR `setAllowFileAccess(false)` absent on targetSdk<=29 with targetSdk quoted) and for the handler if DH3, plus owner.
- Compliant: L1 row plus L2 for the safe configuration (targetSdk>=30 default-off / explicit false / cross-access default-false / restricted handlers) - quoted.
- Group: L1 summary plus an L2 naming references and the shared safe pattern.

```
{
  "id": "wvp-001",
  "description": "Finding (DH2 cross file-URL access enabled): A WebView explicitly enables universal access from file URLs, letting a loaded local page read arbitrary files / any origin.",
  "reference": "jadx/sources/com/example/app/DocViewer.java",
  "level": 1
},
{
  "id": "L2-DocViewer-setting",
  "description": "Dangerous setting (quoted, DH2): ws.setAllowUniversalAccessFromFileURLs(true) at line 51 (default is false; explicitly enabled). ws.setAllowFileAccess(true) at line 50 also opens file:// access (DH1).",
  "reference": "jadx/sources/com/example/app/DocViewer.java:46-54",
  "level": 2
},
{
  "id": "L2-DocViewer-owner",
  "description": "Owner: com.example.app (first-party) -> proprietary (obfuscated/undecidable would also default proprietary). WebView loads local doc HTML; universal file access is unnecessary and dangerous, no justification in code.",
  "reference": "jadx/sources/com/example/app/DocViewer.java:1",
  "level": 2
},
{
  "id": "wvp-safe-group",
  "description": "Compliant group: 9 WebViews on targetSdk 31 with file access off by default and no cross-access enabled.",
  "reference": "jadx/sources/com/example/app/web/",
  "level": 1
},
{
  "id": "L2-safe-coverage",
  "description": "Good pattern: manifest targetSdkVersion=31 (setAllowFileAccess defaults false); none of these WebViews call setAllowFileAccess(true) or setAllow*AccessFromFileURLs(true) (quoted WebFactory.java:30-90). Cross-access default-false. References (9 sites).",
  "reference": "jadx/sources/com/example/app/web/WebFactory.java:30-90",
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
  "rationale": "W WebViews enumerated, S safe (file access off/restricted handlers), N findings (DH1/DH2/DH3), U unverified. targetSdk: <n>. <one or two sentences naming the WebViews, settings and handlers>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 WebView with an L2 row showing DH1 (explicit `setAllowFileAccess(true)`, or absent `setAllowFileAccess(false)` on targetSdk<=29 with targetSdk quoted), DH2 (explicit `setAllow*AccessFromFileURLs(true)`), or DH3 (unnecessary/unrestricted dangerous scheme handler quoted), plus owner. A finding stated with "likely"/"may"/inferred from a setter's ABSENCE on a safe-default API is INVALID -> `unverified`/Compliant.
- **Apply the defaults; do not flag safe defaults.** Absence of `setAllowFileAccess` on targetSdk>=30 is Compliant (default false). Absence of the cross-access setters is Compliant (default false). Only explicit-true (or `setAllowFileAccess` absent on <=29) is a finding. Quote the setter or the targetSdk.
- **Read before flagging; quote it. Do not flag library WebViews.** Resolve the actual setting value; do not guess.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (a design-documented file-access justification, settings delivered at runtime) - in-APK facts (which setting? what targetSdk? which schemes?) resolved by reading, unresolved -> `unverified`. Reject "might restrict file access", "file access might be needed".
- `pass`: WebViews exist and each has file access off (default on >=30, or explicit false, or justified) and no dangerous cross-access enabled and only necessary handlers, with L2 coverage and targetSdk recorded.
- `n/a`: no WebView (enumeration performed; state this).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, if a finding was inferred from a safe-default absence, or if any `fail` lacks its quoted-setting/targetSdk L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the dangerous setting is QUOTED as explicitly true, OR `setAllowFileAccess(false)` is shown absent with targetSdk<=29 quoted - NOT inferred from absence on a safe-default API; (2) for DH3, the handler accepting the unnecessary dangerous scheme is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary), not a library WebView.
Defaults check: confirm you did not flag `setAllowFileAccess` absence on targetSdk>=30, nor the absence of the cross-access setters (all safe defaults).
Hedge scan: "likely", "may", "appears", "might", "probably" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`: confirm every WebView's settings were read and quoted (unread -> `unverified`), no safe-default absence was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.