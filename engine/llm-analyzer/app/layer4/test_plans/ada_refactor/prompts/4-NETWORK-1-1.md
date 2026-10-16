MASTG-TEST-0020
masvs_v1_id	MSTG-NETWORK-1
masvs_v2_id	MASVS-NETWORK-1
platform	android
title	Data Encryption on the Network
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app uses encrypted transport for security-sensitive network traffic. Connections used for non-security purposes (anonymized analytics, on-device servers, local-network IoT) and connections through WebView when the app advertises browser-style URL loading are out of scope.

Static Analysis
For each network configuration and call site, check:

- `AndroidManifest.xml` `<application android:usesCleartextTraffic="...">` (without Network Security Config override)
- Network Security Config `<base-config>` / `<domain-config>` with `cleartextTrafficPermitted="true"`
- `http://` URLs in `HttpURLConnection`, `OkHttpClient`, `Retrofit`, `Volley`, `URL.openConnection`, `Request.Builder().url(...)`
- `Socket`/`DatagramSocket` to off-device, non-local hosts without TLS wrapping
- Cross-platform framework setups (Flutter `http`/`dio`, Xamarin `HttpClient`, React Native `fetch`/`XMLHttpRequest`, Cordova plugins)
- Hardcoded `http://` URLs in resources/build configs/string constants

Description
Network traffic shall be encrypted.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0020.

Verification
The analysis shall demonstrate that all security-sensitive network traffic uses encrypted transport (TLS/HTTPS).

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every cleartext network configuration or call site carrying security-sensitive data. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `<application>` in `AndroidManifest.xml` declaring `android:usesCleartextTraffic="true"` without a Network Security Config override
- Each `<domain-config>` / `<base-config>` in the NSC setting `cleartextTrafficPermitted="true"` (enumerated per `<domain>` covered)
- Each call site constructing an `http://` request bound for an off-device, non-local host carrying security-sensitive data
- Each `Socket`/`DatagramSocket` connection to an off-device, non-local host without TLS wrapping
- Each cross-platform-framework HTTP client setup configured to allow or default to cleartext
- Each hardcoded `http://` URL referenced by network code carrying security-sensitive data

Two records describing the same call site or same NSC entry are duplicates and count as one. The rationale should group findings by surface (manifest declaration, NSC permissive entries, app-code HTTP calls, low-level sockets, cross-platform framework, hardcoded URLs).
