MASTG-TEST-0032
masvs_v1_id	MSTG-PLATFORM-6
masvs_v2_id	MASVS-PLATFORM-2
platform	android
title	Testing WebView Protocol Handlers
masvs_v1_levels	L1, L2

Overview
This test evaluates whether each WebView permits only the resource-access protocols it actually needs (file, content, file-URL JS, cross-origin from file-URL, custom schemes). JavaScript-enable status and load-source trust are scoped to PLATFORM-2-1.

Static Analysis
For each `WebView`, follow `getSettings()` to all `WebSettings` mutations. The decisive settings:

- `setAllowFileAccess(boolean)` — controls `file://` loading from non-asset paths. Default: `true` on `targetSdkVersion <= 29`, `false` on `>= 30`.
- `setAllowContentAccess(boolean)` — controls `content://` loading. Default: `true` regardless of target SDK.
- `setAllowFileAccessFromFileURLs(boolean)` — explicit `true` is opt-in to cross-`file://` JS reads.
- `setAllowUniversalAccessFromFileURLs(boolean)` — explicit `true` is opt-in to cross-origin reads from `file://` origin (most dangerous in this group).

For each `WebView.loadUrl(...)` resolving to `file://`, verify the path: `file:///android_asset/` and `file:///android_res/` are acceptable; internal sandbox paths (`getFilesDir`, `getCacheDir`) are acceptable; external storage paths and untrusted-input-derived paths are violations.

For each `WebViewClient.shouldOverrideUrlLoading(...)` override, verify that non-`http`/`https` schemes (`tel:`, `mailto:`, `intent:`, custom app schemes) are intercepted rather than forwarded to the system.

Description
WebView shall be configured to allow the minimum set of protocol handlers required.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0032.

Verification
The analysis shall demonstrate that file and content URL access is enabled only when needed, file-URL JavaScript access is restricted, local files are loaded only from app assets/resources/sandbox, and custom URL schemes are intercepted in `shouldOverrideUrlLoading`.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every WebView protocol-handler misconfiguration and every unsafe load location. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `setAllowFileAccess(true)` call where the WebView does not demonstrably need filesystem access
- Each WebView on `targetSdkVersion <= 29` for which `setAllowFileAccess(false)` is never called and the inherited `true` default is left active without demonstrated need
- Each `setAllowContentAccess(true)` call (or absent explicit disable, since default is `true`) where the WebView does not demonstrably need `content://` access
- Each `setAllowFileAccessFromFileURLs(true)` call
- Each `setAllowUniversalAccessFromFileURLs(true)` call
- Each `WebView.loadUrl(...)` resolving to a `file://` path on external storage or composed from user input
- Each `WebView.loadUrl("javascript:...")` whose script payload is composed from untrusted input
- Each WebView whose `WebViewClient.shouldOverrideUrlLoading` does not intercept non-`http`/`https` schemes

Two records describing the same configuration call or load call site at the same line are duplicates and count as one. The rationale should group findings by surface (`setAllowFileAccess`, `setAllowContentAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs`, unsafe `file://` loads, untrusted `javascript:` payloads, missing scheme interception).
