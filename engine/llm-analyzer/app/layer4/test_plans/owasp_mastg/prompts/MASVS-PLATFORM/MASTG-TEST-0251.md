MASTG-TEST-0251

maswe_id       MASWE-0069
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          Runtime Use of Content Provider Access APIs in WebViews (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0251 is a dynamic test (hook the WebView setting setters at runtime and observe the effective values per WebView instance, with backtraces). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0250 (the dangerous trio: JS enabled + content access (default/true) + universal file-URL access, with a sensitive content provider). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; runtime hooking resolves settings on dynamically-created WebViews and confirms which instance receives which configuration - which static analysis often cannot pin.

What this test looks for
At runtime no WebView should be configured so that file-origin JavaScript can read sensitive `content://` data. Statically, the proxy is the same dangerous trio as MASTG-TEST-0250 plus a sensitive content provider. Verdict: `pass` (no WebView combines the trio with a sensitive provider), `fail` (>=1 WebView has the trio AND a sensitive provider is reachable), `n/a` (no WebView), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `WebView`/`getSettings`. If NONE appear -> `n/a` (state the search). Runtime config is still flagged via the forced `needs_dynamic_testing`.

The failure condition (ALL must hold)
1. `setJavaScriptEnabled(true)`, AND
2. `setAllowContentAccess(true)` OR not set (default true), AND
3. `setAllowUniversalAccessFromFileURLs(true)`,
AND the app declares content providers handling sensitive data.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote each of the three settings (or default) AND the sensitive provider. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` and `jadx/resources/AndroidManifest.xml`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the trio on one WebView AND a sensitive provider. "probably configured unsafely" with no quoted settings is NOT static evidence -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`, not a hedge.** WebViews created dynamically across code paths may not be statically resolvable -> `unverified` (the hook resolves them). `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate WebView settings: `grep -rEn "WebView|getSettings|setJavaScriptEnabled|setAllowContentAccess|setAllowUniversalAccessFromFileURLs" jadx/sources/`. If no WebView -> short-circuit `n/a` (state the search).
2. For each WebView instance, resolve the three settings (note content-access default). Tie to the same instance where possible; if settings are applied via a shared helper to an unresolved instance -> `unverified`. Quote each.
3. List content providers and assess sensitivity (the app's own providers count). Quote them.
4. A finding requires the trio on one WebView AND a sensitive provider. Owner: app (proprietary).
5. Conclude per WebView: Finding (trio + sensitive provider, quoted); Compliant (a safe setting / no sensitive provider); Unverified (instance/settings unresolved -> confirm via hook).
6. Budget ~3-5 reads per WebView. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Dynamically-created WebViews whose settings can't be tied statically are the dynamic test's strength - hence the forced `needs_dynamic_testing`. Local file access is MASTG-TEST-0252; JS bridges MASTG-TEST-0334.

Output
List **all** WebView instances - one L1 row per WebView with its disposition - plus one L1 row for content providers. Always break out every Finding and unverified WebView individually. Never sample findings.
- Providers: L1 row listing providers and sensitivity.
- Finding: L1 row plus L2 rows quoting the trio and the sensitive provider, plus owner.
- Compliant: L1 row plus an L2 showing a safe setting / no sensitive provider.

```
{
  "id": "cpwvr-001",
  "description": "Finding (WebView trio + sensitive provider): A dynamically-configured WebView enables JS and universal file-URL access with content access at default, while a sensitive provider exists - file-origin JS could read content:// data at runtime.",
  "reference": "jadx/sources/com/example/app/web/WebFrag.java",
  "level": 1
},
{
  "id": "L2-cpwvr-settings",
  "description": "Dangerous trio (quoted): configureWeb(s){ s.setJavaScriptEnabled(true); s.setAllowUniversalAccessFromFileURLs(true);} at WebFrag.java:60-63 applied to the fragment's WebView (line 50); setAllowContentAccess not called -> default true. Runtime hook confirms the effective values per instance.",
  "reference": "jadx/sources/com/example/app/web/WebFrag.java:60-63",
  "level": 2
},
{
  "id": "L2-cpwvr-provider",
  "description": "Sensitive provider (quoted): <provider android:authorities=\"com.example.app.health\"/> serving health records at AndroidManifest.xml:64. Owner: com.example.app (proprietary).",
  "reference": "jadx/resources/AndroidManifest.xml:64",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0251",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "W WebView instances, T with the dangerous trio, providers: <list, sensitive?>. N findings, C compliant, U unverified (unresolved instances). Any WebView reaching sensitive providers? <no -> pass/n-a / yes -> fail>. <one or two sentences>; runtime hook confirms per-instance config.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime hooking is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 WebView with (a) L2 quoting the trio (JS + content-access default/true + universal-file-URL true) AND (b) an L2 quoting a sensitive content provider. A finding stated with "likely"/"may" instead of the quoted trio+provider is INVALID -> `unverified`.
- **All three, plus a sensitive provider.** As MASTG-TEST-0250: missing any of the three -> Compliant; absent content-access counts as default true; no sensitive provider -> Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved instances -> `unverified`.
- `pass`: no WebView combines the trio with a sensitive provider, with L2 coverage.
- `n/a`: no WebView appears in code (short-circuit; state the search).
- `unverified` rows name the unresolved instance/entry point. Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its trio + sensitive-provider L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) all three settings are quoted (or default noted) for the SAME WebView; (2) a sensitive content provider is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the WebView search was performed (n/a state it), every finding WebView's trio and a sensitive provider were read and quoted (unresolved instance -> `unverified`), no WebView missing one of the trio was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
