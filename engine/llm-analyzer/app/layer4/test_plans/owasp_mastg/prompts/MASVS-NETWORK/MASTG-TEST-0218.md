MASTG-TEST-0218

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Insecure TLS Protocols in Network Traffic - negotiated TLS version (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0218 is a dynamic test (capture live traffic and observe the TLS version actually negotiated between app and server). This static engine cannot observe negotiated protocols, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0217 (explicitly-enabled TLS protocol versions in code/config). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the negotiated version depends on the server and runtime and the static verdict is indicative only - a server enforcing TLS 1.2+ can make a permissive client connect securely anyway, and conversely a client that looks safe statically may still negotiate down with a weak server.

What this test looks for
At runtime the app must not communicate over a deprecated TLS version (SSLv3, TLS 1.0, TLS 1.1). Statically, the detectable proxy is the explicitly-enabled TLS configuration (as in MASTG-TEST-0217): an insecure `SSLContext`/`SSLSocket` protocol, `setEnabledProtocols` listing old versions, or a permissive OkHttp `ConnectionSpec`. Verdict: `pass` (no insecure TLS version is explicitly enabled; defaults / 1.2-1.3 only), `fail` (>=1 deprecated TLS version - or a permissive spec admitting one - is explicitly enabled), `n/a` (no explicit TLS-version configuration in code), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the TLS-config APIs (below). If NONE appear -> `n/a` (the app relies on platform TLS defaults; nothing explicitly enabled to assess statically; state the search). The runtime negotiation is still flagged via the forced `needs_dynamic_testing`.

Insecure TLS versions (deny-list)
`SSLv3`, `SSL`, `TLSv1` (1.0), `TLSv1.1`. Secure: `TLSv1.2`, `TLSv1.3`, or the platform-default `TLS` context.

TLS-config sinks
- `SSLContext.getInstance("<deprecated>")`.
- `SSLSocket`/`SSLEngine.setEnabledProtocols(...)` including a deprecated version.
- OkHttp `ConnectionSpec.COMPATIBLE_TLS`, or `ConnectionSpec.Builder.tlsVersions(TLS_1_0/TLS_1_1)`.
- Apache HttpClient `SSLConnectionSocketFactory` pinned to old protocols.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the API call and the deprecated protocol / permissive spec. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual config call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the explicit insecure-TLS configuration. "might negotiate TLS 1.0" with no quoted config is NOT static evidence -> `unverified` (flagged for the dynamic test).
4. **Unresolved determinacy is `unverified`, not a hedge.** If the protocol set can't be resolved statically, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate TLS-config sites: `grep -rEn "SSLContext\.getInstance|setEnabledProtocols|ConnectionSpec|TlsVersion|tlsVersions|COMPATIBLE_TLS|SSLConnectionSocketFactory|SSLv3|TLSv1" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each, resolve the enabled protocol(s) (resolve constants; unresolvable runtime arrays -> `unverified`).
3. Flag a finding when a deprecated version is explicitly enabled, or a permissive spec admitting one governs real connections. Quote call + protocol.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (deprecated TLS / permissive spec quoted); Compliant (defaults or 1.2/1.3 only, quoted); Unverified (protocol set unresolved -> confirm at runtime).
6. Budget ~2-3 reads per site. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The actually-negotiated version is runtime-only - the static verdict is a configuration proxy, hence the forced `needs_dynamic_testing`. TLS config in native code or a no-source SDK -> `unverified` (name the entry point). Cleartext (non-TLS) is MASTG-TEST-0235/0233.

Output
List **all** explicit TLS-version configuration sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant 1.2/1.3-only sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus an L2 quoting the config call and the deprecated protocol / permissive spec, plus owner.
- Compliant: L1 row plus an L2 quoting the default / 1.2-1.3-only configuration.
- Group: L1 summary plus an L2 naming references and the shared secure configuration.

```
{
  "id": "tlsr-001",
  "description": "Finding (deprecated TLS enabled - likely negotiated): The app selects OkHttp's COMPATIBLE_TLS spec, permitting TLS 1.0/1.1 to be negotiated at runtime.",
  "reference": "jadx/sources/com/example/app/net/ApiClient.java",
  "level": 1
},
{
  "id": "L2-tlsr-spec",
  "description": "Permissive spec (quoted): .connectionSpecs(Arrays.asList(ConnectionSpec.COMPATIBLE_TLS, ConnectionSpec.CLEARTEXT)) at ApiClient.java:44-46 - COMPATIBLE_TLS admits deprecated TLS versions. Governs all API calls. Owner: com.example.app (proprietary). Runtime confirmation required.",
  "reference": "jadx/sources/com/example/app/net/ApiClient.java:44-46",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0218",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "T explicit TLS-config sites enumerated, N findings (deprecated version / permissive spec), C compliant (defaults / 1.2-1.3), U unverified. Any explicit TLS-version config present? <no -> n/a / yes>. <one or two sentences naming each insecure configuration; runtime confirms the negotiated version>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation of the negotiated version is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 site quoting an explicitly-enabled deprecated TLS version or a permissive spec admitting one, governing real connections. A finding stated with "likely"/"may" instead of the quoted config is INVALID -> `unverified`.
- **Explicit enabling is the static test.** Platform defaults and 1.2/1.3-only configs are Compliant statically; runtime still flagged via the forced flag.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (server enforces 1.2+) - in-APK facts (which protocols enabled?) resolved by reading, unresolved -> `unverified`.
- `pass`: no insecure TLS version explicitly enabled, with L2 coverage.
- `n/a`: no explicit TLS-version configuration appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its quoted config call + protocol.

Self-check before emitting (per finding)
For every Finding confirm: (1) the TLS-config call is quoted; (2) the deprecated protocol / permissive spec is named; (3) it governs real connections; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the TLS-config search was performed (n/a / pass state it), every config site's enabled protocols were read and quoted (unread -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
