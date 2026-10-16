MASTG-TEST-0027
masvs_v1_id	MSTG-PLATFORM-2
masvs_v2_id	MASVS-CODE-4
platform	android
title	Testing for URL Loading in WebViews
masvs_v1_levels	L1, L2

Overview
This test evaluates whether each WebView in the app prevents arbitrary navigation to attacker-controlled URLs. The default WebView behavior delegates outbound links to the system browser, which is safe. When the app installs a `WebViewClient`, navigation handling shifts to app code, and the app becomes responsible for filtering which URLs the WebView is allowed to load.

The test has a short-circuit: **if the app has no WebViews, this test passes automatically.**

Static Analysis

Navigation interception. For every `WebViewClient` set on a WebView, inspect the two interception callbacks:

- `shouldOverrideUrlLoading(WebView, String)` and the `WebResourceRequest` overload — invoked for top-level navigations. The override should validate the URL's scheme and host against an allow-list and return `true` (cancel) for non-allowed URLs. Returning `false` (or omitting the override) lets the WebView navigate freely.
- `shouldInterceptRequest(WebView, WebResourceRequest)` — invoked for sub-resource loads (XHR, iframe `src`, image/script tags). The override should validate the request URL the same way; returning `null` lets the WebView continue with the original request.

SafeBrowsing. Inspect the manifest for the meta-data tag that disables SafeBrowsing:

```
<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" />
```

The default is `true`. An explicit `false` is a violation.

Description
Arbitrary URL redirects shall not be included in the app's WebViews.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0027.

Verification
The analysis shall demonstrate that (a) every WebView's navigation callbacks validate URLs against an allow-list of trusted schemes and hosts, and (b) SafeBrowsing is not explicitly disabled in the manifest. If the app has no WebViews, the test passes automatically.

Verdict scope
This test is catalog-style with an auto-pass short-circuit. Its purpose is to give an analyst a complete inventory of every WebView whose URL-loading behavior is unrestricted, plus any manifest configuration that disables SafeBrowsing. A verdict that finds one example and stops is incomplete.

If no WebView is present in the app, the verdict is `pass` and no enumeration is needed. Otherwise:

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each WebView with a configured `WebViewClient` whose `shouldOverrideUrlLoading` does not validate the URL against an allow-list of permitted schemes and hosts
- Each WebView with a configured `WebViewClient` whose `shouldInterceptRequest` does not validate sub-resource request URLs against an allow-list
- Each WebView with a configured `WebViewClient` that overrides `onSafeBrowsingHit` to call `callback.proceed(...)` (suppressing SafeBrowsing warnings)
- Each WebView whose `WebSettings.setSafeBrowsingEnabled(false)` is invoked at runtime
- Each `<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false" />` declaration in the manifest

Two records describing the same WebViewClient method or manifest entry are duplicates and count as one. The same WebViewClient class reused across many WebViews is one row at the class definition. The rationale should group findings by surface (`shouldOverrideUrlLoading`, `shouldInterceptRequest`, SafeBrowsing override, runtime disable, manifest disable).
