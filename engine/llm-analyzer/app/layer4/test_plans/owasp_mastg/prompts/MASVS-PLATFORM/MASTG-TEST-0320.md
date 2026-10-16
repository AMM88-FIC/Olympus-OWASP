MASTG-TEST-0320

maswe_id       MASWE-0118
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          WebViews Not Cleaning Up Sensitive Data - storage enabled without cleanup (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0320 is a dynamic test (exercise the app, close it, then inspect `/data/data/<pkg>/app_webview/` for leftover sensitive data and trace file operations). This static engine cannot inspect the device filesystem, so this prompt performs the best-effort static equivalent - detect WebView storage areas that the app ENABLES without a corresponding CLEANUP call. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only inspecting the WebView storage directory after the app closes proves whether sensitive data actually persists (WebViews may also write storage internally even without explicit enable calls).

What this test looks for
A WebView handling sensitive data must clean up the storage areas it enables, or that data lingers on disk. Statically, the proxy is each enabled storage area lacking its matching cleanup call. Verdict: `pass` (every enabled WebView storage area has a matching cleanup call, or no sensitive data flows through WebViews), `fail` (>=1 WebView storage area is enabled and used for sensitive data with no matching cleanup), `n/a` (the app uses no WebView), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `WebView`/`WebSettings`/`WebStorage`/`CookieManager`. If NONE appear -> `n/a` (no WebView; state the search).

Enable -> required-cleanup pairs
- Cache: `setCacheMode(!= LOAD_NO_CACHE)` / `setAppCacheEnabled(true)` (legacy) -> needs `WebView.clearCache(true)`.
- DOM storage: `setDomStorageEnabled(true)` -> needs `WebStorage.getInstance().deleteAllData()`.
- Database: `setDatabaseEnabled(true)` -> needs `WebStorage.getInstance().deleteAllData()`.
- Cookies: `CookieManager.setAcceptCookie(true)` or default (default is true) -> needs `CookieManager.removeAllCookies(...)` / `removeSessionCookies(...)`.
A finding is an enabled area (for sensitive content) with no corresponding cleanup anywhere in the WebView lifecycle (e.g. `onDestroy`/logout).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the storage-enable call AND the absence (via searches) of its matching cleanup, plus the sensitive data context. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the enable call and the cleanup search, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the enabled storage area and (b) the missing matching cleanup, for a WebView handling sensitive data. "probably leaks" with no quoted enable/cleanup is NOT static evidence -> `unverified` (flag for the filesystem check).
4. **Unresolved determinacy is `unverified`, not a hedge.** WebViews may write storage internally regardless of explicit enables - hence the forced dynamic. If a cleanup happens in an unresolved path, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate storage enables and cleanups: `grep -rEn "setDomStorageEnabled|setDatabaseEnabled|setAppCacheEnabled|setCacheMode|setAcceptCookie|clearCache|WebStorage|deleteAllData|removeAllCookies|removeSessionCookies|CookieManager" jadx/sources/`. If no WebView storage APIs -> short-circuit `n/a` (state the search).
2. For each enabled storage area, search for its matching cleanup call in the WebView's lifecycle (onDestroy, onPause, logout). Quote the enable; quote the cleanup or show its absence.
3. Confirm the WebView handles sensitive data (login pages, tokens, PII in DOM/cookies) - the leak only matters for sensitive content. Quote the context. Non-sensitive WebView -> Compliant (note).
4. Owner: app (proprietary).
5. Conclude per storage area: Finding (enabled + sensitive + no matching cleanup, quoted); Compliant (cleanup present, or non-sensitive); Unverified (cleanup in unresolved path / internal WebView storage -> confirm via filesystem).
6. Budget ~3-5 reads per WebView (the settings, the cleanup search, the sensitive-content context). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether data actually persists on disk is the dynamic test's job - hence the forced `needs_dynamic_testing`. WebView misconfig (file/content access) is MASTG-TEST-0250/0252; JS bridges MASTG-TEST-0334. This test is WebView storage CLEANUP.

Output
List **all** enabled WebView storage areas - one L1 row per area with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group cleaned/ non-sensitive areas, but always break out every Finding and unverified area individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the storage-enable call, the missing matching cleanup (searches), and the sensitive-data context, plus owner.
- Compliant: L1 row plus an L2 showing the matching cleanup, or non-sensitive content.

```
{
  "id": "wvcl-001",
  "description": "Finding (DOM storage enabled, never cleared): A login WebView enables DOM storage and never calls WebStorage.deleteAllData(), so credentials cached in localStorage persist after logout.",
  "reference": "jadx/sources/com/example/app/web/LoginWeb.java",
  "level": 1
},
{
  "id": "L2-wvcl-enable",
  "description": "Storage enabled (quoted): s.setDomStorageEnabled(true) at LoginWeb.java:31 - the WebView loads the login page (sensitive credentials in localStorage).",
  "reference": "jadx/sources/com/example/app/web/LoginWeb.java:31",
  "level": 2
},
{
  "id": "L2-wvcl-nocleanup",
  "description": "No cleanup (quoted searches): grep for WebStorage / deleteAllData across jadx/sources/ returns no call; LoginWeb.onDestroy (lines 50-54) clears nothing. Owner: com.example.app (proprietary). Filesystem check confirms persistence.",
  "reference": "jadx/sources/com/example/app/web/LoginWeb.java:50-54",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0320",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S WebView storage areas enabled (DOM/database/cache/cookies), C with matching cleanup, N findings (enabled + sensitive + no cleanup), U unverified. Any sensitive WebView storage left uncleaned? <no -> pass/n-a / yes -> fail>. <one or two sentences>; filesystem check confirms persistence.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that a filesystem check is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 WebView storage area with (a) an L2 quoting its enable call AND (b) an L2 showing no matching cleanup (searches), for a WebView handling sensitive data. A finding stated with "likely"/"may" instead of the quoted enable+missing-cleanup is INVALID -> `unverified`.
- **Match enable to cleanup.** Each enabled area needs its specific cleanup (DOM/DB -> deleteAllData; cache -> clearCache(true); cookies -> removeAllCookies). A cleanup for a different area does not cover it.
- **Sensitive content required.** A WebView that never handles sensitive data is Compliant - note it.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (enabled? cleaned? sensitive?) resolved by reading, unresolved -> `unverified`.
- `pass`: every enabled sensitive storage area has its matching cleanup, with L2 coverage.
- `n/a`: no WebView storage APIs appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or internal WebView storage). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its enable + missing-cleanup L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the storage-enable call is quoted; (2) the matching cleanup is shown absent (searches); (3) the WebView handles sensitive data; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the storage-API search was performed (n/a state it), every enabled area's matching cleanup was searched and quoted/shown-absent (unresolved -> `unverified`), no non-sensitive/cleaned area was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
