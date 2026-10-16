MASTG-TEST-0033
masvs_v1_id	MSTG-NETWORK-2
masvs_v2_id	MASVS-NETWORK-1
platform	android
title	Testing TLS Settings
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app configures TLS at industry-best-practice baselines on the client side. The unit of analysis is the **configuration site** — places where the app explicitly chooses a TLS protocol version, ciphersuite list, `SSLContext`, `SSLSocketFactory`, `ConnectionSpec`, or equivalent. Sites that rely on platform defaults inherit modern defaults and do not produce findings. Custom `TrustManager`/`HostnameVerifier` weaknesses are scoped to NETWORK-1-3.

Static Analysis
For each TLS configuration site, inspect the explicit protocol and ciphersuite selections.

Description
TLS shall be configured according to industry best practices.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0033.

Verification
The analysis shall demonstrate that all explicit TLS configurations in the app use TLS 1.2 or 1.3 and avoid weak ciphersuites.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every TLS configuration site that pins a deprecated protocol or weak ciphersuite. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `SSLContext.getInstance(...)` pinning a deprecated protocol (`"SSL"`, `"SSLv2"`, `"SSLv3"`, `"TLSv1"`, `"TLSv1.1"`)
- Each `SSLSocket.setEnabledProtocols(...)` whose argument array includes a deprecated protocol
- Each `SSLSocket.setEnabledProtocols(...)` whose argument array does not include `"TLSv1.2"` or `"TLSv1.3"`
- Each `SSLSocket.setEnabledCipherSuites(...)` enabling known-weak suites (NULL, aNULL/ADH/AECDH, EXPORT, RC4, 3DES, MD5-based MAC, no-forward-secrecy where required)
- Each OkHttp `ConnectionSpec.Builder` configured with deprecated `tlsVersions(...)` or weak `cipherSuites(...)` lists
- Each NSC `<base-config>`/`<domain-config>` with configuration that effectively disables modern TLS for covered domains
- Each cross-platform-framework TLS setup pinning a deprecated protocol or weak cipher list
- Each custom `SSLSocketFactory`/`HostnameVerifier`/`X509TrustManager` whose method bodies select protocols or ciphers below baseline

Two records describing the same call site or NSC entry are duplicates and count as one. A single misconfigured `SSLContext` reused across many sites is one row at the construction site. A "no TLS 1.2 in enabledProtocols" finding and "includes TLSv1.1" finding at the same call site are one violation, not two. The rationale should group findings by surface (`SSLContext` family, `setEnabledProtocols`, `setEnabledCipherSuites`, OkHttp `ConnectionSpec`, NSC, cross-platform framework, custom factories).
