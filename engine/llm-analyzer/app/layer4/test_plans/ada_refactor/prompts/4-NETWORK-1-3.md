MASTG-TEST-0034
masvs_v1_id	MSTG-NETWORK-3
masvs_v2_id	MASVS-NETWORK-2
platform	android
title	Testing Endpoint Identity Verification
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app properly validates server certificate identity for connections carrying sensitive data. Connections used purely for non-security purposes are out of scope. The unit of analysis is the **trust-customization site** — places where the app overrides, replaces, or relaxes platform certificate/hostname checks.

Static Analysis
For each trust-customization site, inspect the method bodies and the configuration.

Description
The app shall verify the identity of the remote endpoint.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0034.

Verification
The analysis shall demonstrate that the app does not bypass certificate or hostname validation, and that connections relying on a non-system trust store use certificate or public-key pinning.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every trust-customization site that weakens, bypasses, or fails to establish endpoint identity verification for sensitive connections. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each custom `X509TrustManager` whose `checkServerTrusted` is empty, returns unconditionally, swallows exceptions, or skips PKIX validation
- Each custom `X509TrustManager` whose `getAcceptedIssuers` returns an empty array on a server-trust path
- Each custom `HostnameVerifier` whose `verify(...)` returns `true` unconditionally
- Each use of `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER` (Apache HttpClient legacy) assigned into a client configuration
- Each `SSLContext.init(...)` installing a trust-all `TrustManager[]`
- Each OkHttp `OkHttpClient.Builder().sslSocketFactory(...)` / `.hostnameVerifier(...)` installing a permissive factory/verifier
- Each `WebViewClient.onReceivedSslError(...)` override that calls `handler.proceed()` on any path other than a tightly-scoped, well-justified one
- Each NSC `<trust-anchors>` entry containing `<certificates src="user" />`
- Each NSC `<base-config>`/`<domain-config>` with `<debug-overrides>` surviving into production builds
- Each app with `targetSdkVersion < 24` inheriting the legacy default that trusts user-installed CAs without explicit NSC opt-out
- Each WebView-based hybrid surface where `android:debuggable="true"` causes `onReceivedSslError` to ignore errors at runtime
- Each NSC that excludes the system CA store (e.g. `<trust-anchors>` listing only a private/internal CA) without pinning specific certificates or public keys

Two records describing the same trust-customization site at the same line are duplicates and count as one. A single trust-all `TrustManager` reused across many sites is one row at the construction/installation site. A class implementing both a permissive `TrustManager` and a permissive `HostnameVerifier` produces two rows. The rationale should group findings by surface (custom `TrustManager`, permissive `HostnameVerifier`, WebView `onReceivedSslError`, NSC user-CA opt-in, NSC debug overrides, legacy `targetSdkVersion`, Cordova-debuggable, missing pinning when system store is bypassed).
