MASTG-TEST-0217

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Insecure TLS Protocols Explicitly Allowed in Code - deprecated TLS versions enabled (static)

What this test looks for
The app must not explicitly enable deprecated TLS protocol versions (SSLv3, TLS 1.0, TLS 1.1) for network communication. Modern Android negotiates TLS 1.2/1.3 by default, but code can downgrade this: requesting an insecure `SSLContext`/`SSLSocket` protocol, calling `setEnabledProtocols(...)` with old versions, or selecting a permissive OkHttp `ConnectionSpec`. This is a static evaluation of every explicit TLS-version configuration. Verdict: `pass` (no insecure TLS version is explicitly enabled; defaults / TLS 1.2+ only), `fail` (>=1 deprecated TLS version - or a permissive spec that allows one - is explicitly enabled), `n/a` (the app configures no TLS protocol versions in code at all), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the TLS-config APIs below. If NONE appear -> `n/a` (the app relies on platform TLS defaults; nothing explicitly enabled to assess; state the search).

Insecure TLS versions (deny-list)
`SSLv3`, `SSL`, `TLSv1` (TLS 1.0), `TLSv1.1`. Secure: `TLSv1.2`, `TLSv1.3`, or `TLS` requesting the platform default context (which negotiates 1.2/1.3). A bare `SSLContext.getInstance("TLS")` is acceptable; `getInstance("TLSv1.1")`/`("SSLv3")` is a finding.

TLS-config sinks
- `SSLContext.getInstance("<protocol>")` with a deprecated protocol.
- `SSLSocket.setEnabledProtocols(new String[]{... "TLSv1", "TLSv1.1" ...})` / `SSLEngine.setEnabledProtocols(...)` including a deprecated version.
- OkHttp: `ConnectionSpec.COMPATIBLE_TLS` (permits old versions), or `ConnectionSpec.Builder.tlsVersions(TlsVersion.TLS_1_0 / TLS_1_1)`, wired via `connectionSpecs(...)`.
- Apache HttpClient / other libs pinning `SSLConnectionSocketFactory` to old protocols.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the API call and the deprecated protocol string / permissive spec it enables. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual configuration call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the explicit insecure-TLS configuration. "might allow TLS 1.0" with no quoted call is NOT evidence -> `unverified`. A `setEnabledProtocols` that lists only 1.2/1.3 is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the protocol array is built from values that can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate TLS-config sites: `grep -rEn "SSLContext\.getInstance|setEnabledProtocols|ConnectionSpec|TlsVersion|tlsVersions|COMPATIBLE_TLS|SSLConnectionSocketFactory|SSLv3|TLSv1" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each, resolve the protocol(s) enabled (resolve constants/finals; runtime-built arrays that can't be pinned -> `unverified`).
3. Flag a finding when a deprecated version (SSLv3/TLS 1.0/1.1) is explicitly enabled, or a permissive spec (`COMPATIBLE_TLS`) that admits one is selected for real connections. Quote the call + protocol.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A library default that the app does not override is attributed to the library but reported if it governs app traffic.
5. Conclude per site: Finding (deprecated TLS / permissive spec quoted); Compliant (defaults or 1.2/1.3 only, quoted); Unverified (protocol set unresolved).
6. Budget ~2-3 reads per site (the config call, any protocol-array constant, the socket/client wiring). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The actually-negotiated TLS version is observable only at runtime (MASTG-TEST-0218). TLS configuration inside native code or a no-source SDK -> `unverified` (name the entry point). Cleartext (non-TLS) traffic is MASTG-TEST-0235/0233. This test judges explicitly-enabled TLS PROTOCOL VERSIONS only.

Output
List **all** explicit TLS-version configuration sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant 1.2/1.3-only sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus an L2 quoting the config call and the deprecated protocol / permissive spec, plus owner.
- Compliant: L1 row plus an L2 quoting the default / 1.2-1.3-only configuration.
- Group: L1 summary plus an L2 naming references and the shared secure configuration.

```
{
  "id": "tls-001",
  "description": "Finding (deprecated TLS enabled in code): The app explicitly enables TLS 1.0 and 1.1 on its SSLSocket, allowing downgraded, attackable connections.",
  "reference": "jadx/sources/com/example/app/net/TlsFactory.java",
  "level": 1
},
{
  "id": "L2-tls-call",
  "description": "Insecure protocols (quoted): socket.setEnabledProtocols(new String[]{\"TLSv1\", \"TLSv1.1\", \"TLSv1.2\"}); at TlsFactory.java:51-53 - TLSv1 (1.0) and TLSv1.1 are deprecated. Socket used for the API client (lines 40-48). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/net/TlsFactory.java:51-53",
  "level": 2
},
{
  "id": "tls-ok-001",
  "description": "Compliant: OkHttp client restricted to MODERN_TLS (TLS 1.2/1.3).",
  "reference": "jadx/sources/com/example/app/net/HttpClient.java",
  "level": 1
},
{
  "id": "L2-tls-ok",
  "description": "Secure spec (quoted): new OkHttpClient.Builder().connectionSpecs(Collections.singletonList(ConnectionSpec.MODERN_TLS)) at HttpClient.java:30-33 - only TLS 1.2/1.3.",
  "reference": "jadx/sources/com/example/app/net/HttpClient.java:30-33",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0217",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "T explicit TLS-config sites enumerated, N findings (deprecated SSLv3/TLS1.0/1.1 or permissive COMPATIBLE_TLS), C compliant (defaults / 1.2-1.3), U unverified. Any explicit TLS-version config present? <no -> n/a / yes>. <one or two sentences naming each insecure configuration>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false - the negotiated version is confirmed at runtime by MASTG-TEST-0218); it does not change `pass`/`fail`.
- `fail`: >=1 site quoting an explicitly-enabled deprecated TLS version (SSLv3/TLS 1.0/1.1) or a permissive spec (`COMPATIBLE_TLS`) admitting one, governing real connections. A finding stated with "likely"/"may" instead of the quoted call is INVALID -> `unverified`.
- **Explicit enabling is the test.** Relying on platform defaults (`SSLContext.getInstance("TLS")`, no `setEnabledProtocols`) is Compliant. A `setEnabledProtocols` listing only 1.2/1.3 is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (e.g. the server enforces 1.2+ regardless) - in-APK facts (which protocols are enabled?) resolved by reading, unresolved -> `unverified`.
- `pass`: no insecure TLS version is explicitly enabled (defaults or 1.2/1.3 only), with L2 coverage.
- `n/a`: no explicit TLS-version configuration appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its quoted config call + protocol.

Self-check before emitting (per finding)
For every Finding confirm: (1) the TLS-config call is quoted; (2) the deprecated protocol / permissive spec is named; (3) it governs real connections (not a disabled/test path); (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the TLS-config search was performed (n/a / pass state it), every config site's enabled protocols were read and quoted (unread -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
