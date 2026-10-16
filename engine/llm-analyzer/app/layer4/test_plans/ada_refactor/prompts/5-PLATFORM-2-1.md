MASTG-TEST-0031
masvs_v1_id	MSTG-PLATFORM-5
masvs_v2_id	MASVS-PLATFORM-2
platform	android
title	Testing JavaScript Execution in WebViews
masvs_v1_levels	L1, L2

Overview
This test evaluates whether each WebView in the app needs JavaScript execution, and whether the WebView's loading behavior is constrained to safe sources when JavaScript is enabled.

If no WebView enables JavaScript, the test passes automatically.

Static Analysis
For each `WebView`, follow `getSettings()` to any `setJavaScriptEnabled(...)` call. WebViews with JavaScript disabled (or never enabled) are out of scope.

For each JS-enabled WebView, enumerate every load call site (`loadUrl`, `postUrl`, `loadData`, `loadDataWithBaseURL`) and trace the URL/content argument to its source — hardcoded HTTPS to trusted hosts and resource-stored URLs are acceptable; user-input, intent-extras, deep-link URIs, content-provider reads, network responses, and external-storage paths are violations unless an allow-list filter is applied at the call site.

Description
WebViews shall securely execute JavaScript.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0031.

Verification
The analysis shall demonstrate that (a) WebViews load only HTTPS endpoints to trusted hosts or local content within the app sandbox, (b) the URLs and HTML loaded are not derived from user-controlled input without an allow-list, and (c) JavaScript is enabled only on WebViews that need it.

Verdict scope
This test is catalog-style with an auto-pass short-circuit. Its purpose is to give an analyst a complete inventory of every JS-enabled WebView whose loading behavior violates the safe-source requirements. A verdict that finds one example and stops is incomplete.

If no WebView enables JavaScript, the verdict is `pass`. Otherwise:

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `loadUrl`/`postUrl` call against a JS-enabled WebView whose URL scheme is `http://`
- Each `loadUrl`/`postUrl` call against a JS-enabled WebView whose URL is derived from user input, intent extras, deep-link URI parameters, content provider reads, or other untrusted sources without an allow-list filter on scheme/host
- Each `loadUrl` call against a JS-enabled WebView whose URL is a `file://` path under external storage or a `content://` URI from an untrusted provider
- Each `loadData` call against a JS-enabled WebView whose `data` argument is built from untrusted sources without HTML escaping
- Each `loadDataWithBaseURL` call against a JS-enabled WebView whose `baseUrl` is non-`null` and either attacker-controlled or set to a sensitive origin while `data` is built from untrusted input
- Each WebView with JavaScript enabled but no apparent functional need (renders only local static HTML without `<script>` tags)
- Each WebView whose `setJavaScriptEnabled` argument cannot be resolved statically

Two records describing the same load call site at the same line are duplicates and count as one. The rationale should group findings by surface (cleartext URLs, user-controlled URL flow, external storage / untrusted content URIs, untrusted `loadData` payloads, sensitive `loadDataWithBaseURL` origin combinations, unjustified JS enablement).
