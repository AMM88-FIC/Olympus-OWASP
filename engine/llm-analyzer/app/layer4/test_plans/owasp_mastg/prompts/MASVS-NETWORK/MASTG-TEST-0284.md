MASTG-TEST-0284

maswe_id       MASWE-0052
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Incorrect SSL Error Handling in WebViews - onReceivedSslError calls proceed() (static)

What this test looks for
A `WebViewClient` that overrides `onReceivedSslError(...)` and calls `SslErrorHandler.proceed()` without proper validation bypasses the WebView's SSL/TLS certificate checks, loading pages over invalid, expired, or self-signed certificates - a MITM. Per Android guidance, apps should never call `proceed()` on an SSL error; the correct behavior is `cancel()`. This is a static evaluation of every `onReceivedSslError` override. Verdict: `pass` (no WebView overrides `onReceivedSslError`, or every override cancels / properly validates), `fail` (>=1 override calls `proceed()` without proper validation, or silently swallows the error), `n/a` (the app uses no WebView / no `WebViewClient`), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `onReceivedSslError`/`SslErrorHandler`/`WebViewClient`. If NONE appear -> `n/a` (no WebView SSL handling; state the search).

Unsafe patterns (any one -> finding)
- **Unconditional proceed**: `onReceivedSslError(...) { handler.proceed(); }` with no error inspection.
- **Proceed on partial check**: deciding via `error.getPrimaryError()` only (e.g. proceed unless `SSL_UNTRUSTED`), ignoring other errors in the chain.
- **Silent swallow**: catching/ignoring without calling `handler.cancel()`, letting the load continue.
- **User-prompt proceed** is discouraged but is a weaker finding - flag it, noting users can't evaluate SSL issues; treat an unconditional/no-real-check proceed as the primary finding.

Compliant: `onReceivedSslError(...) { handler.cancel(); }` (the safe default behavior), or not overriding the method at all (default cancels).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `onReceivedSslError` body showing `proceed()` (or the swallow), AND the WebView/WebViewClient it is attached to. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual override body, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the `proceed()` (or silent-swallow) in the override. "probably proceeds" is NOT evidence -> `unverified`. An override that cancels is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the body or its WebView attachment can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate overrides: `grep -rEn "onReceivedSslError|SslErrorHandler|setWebViewClient|WebViewClient" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each `onReceivedSslError` override, read the FULL body. Does it call `handler.proceed()` (finding, unless gated by a genuine, complete validation), `handler.cancel()` (Compliant), or neither/swallow (finding)? Quote the body.
3. Confirm the WebViewClient is attached to a live WebView (`webView.setWebViewClient(...)`) that loads content. An unattached client is not a live finding (note it). Quote the attachment.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per override: Finding (proceed/swallow + attachment quoted); Compliant (cancel / proper validation, quoted); Unverified (body/attachment unresolved).
6. Budget ~2-4 reads per override (the body, the setWebViewClient, the loadUrl). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
WebView handling inside native code or a no-source SDK -> `unverified` (name the entry point). General WebView misconfig (JS bridges, file access) is a PLATFORM test, not this one. This test is specifically `onReceivedSslError` -> `proceed()`.

Output
List **all** `onReceivedSslError` overrides - one L1 row per override with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group compliant cancel-overrides by area, but always break out every Finding and unverified override individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the `proceed()`/swallow body and the WebView attachment, plus owner.
- Compliant: L1 row plus an L2 quoting the `cancel()` / proper validation.

```
{
  "id": "wv-001",
  "description": "Finding (WebView ignores SSL errors): A WebViewClient overrides onReceivedSslError and unconditionally calls proceed(), loading pages despite invalid certificates (MITM).",
  "reference": "jadx/sources/com/example/app/ui/HelpWebClient.java",
  "level": 1
},
{
  "id": "L2-wv-body",
  "description": "Unsafe override (quoted): public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError e) { handler.proceed(); } at HelpWebClient.java:20-22 - proceeds on any SSL error, no inspection.",
  "reference": "jadx/sources/com/example/app/ui/HelpWebClient.java:20-22",
  "level": 2
},
{
  "id": "L2-wv-attach",
  "description": "Attachment (quoted): webView.setWebViewClient(new HelpWebClient()); webView.loadUrl(helpUrl) at HelpActivity.java:48-50 - the client governs a live WebView. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/ui/HelpActivity.java:48-50",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0284",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "O onReceivedSslError overrides, A attached to live WebViews, N findings (proceed / partial-check proceed / silent swallow), C compliant (cancel / proper validation), U unverified. Any WebView SSL handling? <no -> n/a / yes>. <one or two sentences naming each unsafe override>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 `onReceivedSslError` with (a) an L2 row quoting a `proceed()` (or silent swallow) without complete validation AND (b) an L2 row quoting its attachment to a live WebView. A finding stated with "likely"/"may" instead of the quoted body is INVALID -> `unverified`.
- **proceed() is the red flag.** Per Android guidance, never call `proceed()` on an SSL error. A `getPrimaryError()`-only gate is still a finding (incomplete). `cancel()` (or not overriding) is Compliant.
- **Attachment matters.** An override on a WebViewClient never attached to a live WebView is not a live finding - note it. State the attachment.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (does it proceed? is it attached?) resolved by reading, unresolved -> `unverified`.
- `pass`: no override, or every override cancels / validates properly, with L2 coverage.
- `n/a`: no WebView / `onReceivedSslError` appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its body + attachment L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `onReceivedSslError` body showing `proceed()`/swallow is quoted; (2) its attachment to a live WebView is quoted; (3) no complete validation gates the proceed; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the WebView SSL search was performed (n/a / pass state it), every override body AND its attachment were read and quoted (unread -> `unverified`), no cancel-override was miscounted, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
