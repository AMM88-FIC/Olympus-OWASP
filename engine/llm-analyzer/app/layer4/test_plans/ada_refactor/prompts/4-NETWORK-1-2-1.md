MASTG-TEST-XXXX

masvs_v1_id    MSTG-NETWORK-1
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Robust TLS negotiation - strong protocol versions and cipher suites, app side (static)

========================================================================
READ THIS FIRST - HOW TO JUDGE `SSLContext.getInstance("TLS")`
`getInstance("TLS")` selects the provider DEFAULT context. Its disposition is NOT decided by the `getInstance` line alone - it depends on (A) whether the code restricts protocols, and (B) the app's `minSdkVersion`, because the platform's default enabled-protocol set differs by API level:
  - API 16-19: TLS 1.1/1.2 are supported but NOT enabled by default; the default socket tops out at TLS 1.0 and SSLv3 is enabled. (SSLv3/TLS1.0 negotiable -> weak.)
  - API 20+: TLS 1.1/1.2 are enabled by default (modern). (SSLv3 is removed from defaults in later releases.)

DECISION PROCEDURE (follow in order; you MUST read the factory body, do not stop at the `getInstance` line):
  1. Read the enclosing socket factory / setup (`TLSSocketFactory.create*`, `createSocket`, the SSLContext init and the socket it returns). Does it call `setEnabledProtocols(...)` (or equivalent) to enable only TLS 1.2/1.3 and exclude SSLv3/older? A custom `TLSSocketFactory` in a low-minSdk app usually exists for exactly this.
     -> If YES (protocols forced to >=TLS 1.2): COMPLIANT, regardless of minSdk. No finding.
  2. If there is NO such restriction, read `minSdkVersion` from the manifest:
     -> minSdk >= 20: COMPLIANT (platform enables TLS 1.2 by default).
     -> minSdk < 20: FINDING - on the supported API 16-19 devices the default socket negotiates SSLv3/TLS 1.0 and does NOT use TLS 1.2 by default. This matches the FAIL criteria (permits SSL 3.0 / defaults to TLS 1.0).

So: do NOT flag `getInstance("TLS")` merely because the string is "TLS" or because of vague "older Android" reasoning - that alone is not a finding. But DO flag it when you have CONFIRMED (a) no `setEnabledProtocols` restriction in the factory AND (b) `minSdk < 20`. A finding requires both facts, each quoted (the absence of a restriction in the factory body you read, and the minSdk value). The evidence index listing the site is a candidate to inspect, not a verdict.

WRONG (do not produce this): flagging `getInstance("TLS")` from the call line alone, with rationale "best practice is TLSv1.2" or "may be weak on old Android", WITHOUT reading the factory body or citing minSdk.
ALSO WRONG: passing it blindly when minSdk < 20 and no protocol restriction exists.
RIGHT: "TLSSocketFactory.create reads SSLContext.getInstance(\"TLS\") and does NOT call setEnabledProtocols; minSdk=19 -> on API 16-19 the default negotiates SSLv3/TLS1.0 -> Finding." OR "...calls setEnabledProtocols([\"TLSv1.2\",\"TLSv1.3\"]) -> Compliant."
========================================================================

What this test looks for
The app must negotiate TLS robustly: support TLS 1.2 or higher, not support SSL 2.0/3.0, not default to TLS 1.0/1.1, and not be able to negotiate known-vulnerable cipher suites - per NIST SP.800-52r2 and BSI TR-02102-2. Scope is the APP, not the backend: what protocol versions and cipher suites the app's TLS configuration enables/prefers. This is a static, inventory-style evaluation: enumerate every TLS use, read its configuration, and classify version + ciphers against the standards. Verdict: `pass` (TLS 1.2+, no vulnerable ciphers, conformant), `fail` (SSL 2.0/3.0 enabled, default to TLS 1.0/1.1, or a known-vulnerable cipher negotiable), `n/a` (the app establishes no TLS connections / transmits no sensitive data over the network), or `inconclusive`.

This test is about **negotiation strength (versions + ciphers) only**. Trust/identity problems - trust-all `TrustManager`, hostname-verifier bypass, missing pinning - are a separate control (MASVS-NETWORK-2); note them in passing but do not base this verdict on them. Cleartext (no TLS at all) is the separate cleartext-traffic test.

HARD RULE - what makes a TLS site a FINDING (explicit weak artifact, quoted from code):
  (1) a legacy protocol STRING literally passed to `getInstance` - `"SSL"`, `"SSLv2"`, `"SSLv3"`, `"TLSv1"`, `"TLSv1.1"`;
  (2) a `setEnabledProtocols`/`tlsVersions` array whose HIGHEST element is below TLS 1.2 or that contains SSLv3;
  (3) a `setEnabledCipherSuites`/`cipherSuites` array containing a known-vulnerable suite; OR
  (4) a `getInstance("TLS")`/default-context socket that you have CONFIRMED (by reading the factory body) is NOT protocol-restricted, in an app whose `minSdk < 20` (the API 16-19 default enables SSLv3/TLS 1.0 and not TLS 1.2).
Anything else - a bare `getInstance("TLS")` on `minSdk >= 20`, a factory that forces TLS 1.2/1.3, or "best practice is TLSv1.2" reasoning with no quoted weak artifact - is NOT a finding.

The good pattern (do not flag)
An app that uses `HttpsURLConnection`, OkHttp, Retrofit, Ktor, etc. with **default TLS configuration** inherits the device platform's TLS stack. On `minSdk >= 20` (and current Android) that default negotiates TLS 1.2/1.3 and excludes SSLv3 -> **Compliant**, do not flag. Likewise OkHttp `ConnectionSpec.MODERN_TLS` and `Conscrypt.newProvider()` are modern. `SSLContext.getInstance("TLS")` selects the provider default (not a weak-protocol request) - but its disposition is decided by the READ-THIS-FIRST procedure: Compliant when the factory forces >=TLS 1.2 or `minSdk >= 20`; a Finding only when `minSdk < 20` and the factory imposes no protocol restriction. A custom `SSLSocketFactory`/`TLSSocketFactory` is **usually the remediation** (it calls `setEnabledProtocols` to force TLS 1.2/1.3) - you MUST read its body before concluding. Findings arise from an explicit weak artifact (legacy protocol string, sub-1.2 protocol array, vulnerable cipher) or the confirmed `minSdk < 20` + unrestricted-default case.

Source is ground truth. A network/TLS evidence index is a candidate list only - confirm protocol strings, enabled-protocol/cipher arrays, and library specs by reading `jadx/sources/`. The `find_callers`/`find_callees` call graph gives *candidate* chains, not confirmed flow.

Version classification (NIST SP.800-52r2 / BSI TR-02102-2)
- Compliant: TLS 1.2 or 1.3 (explicitly, or via platform default on `minSdk >= 20`), `"TLSv1.2"`/`"TLSv1.3"`, and `getInstance("TLS")` when the factory forces >=TLS 1.2 or `minSdk >= 20` (see the decision procedure). `"TLS"` is the default selector, not a weak-protocol request - but on `minSdk < 20` the default set is weak unless the code restricts it.
- Finding (hard): SSL 2.0/3.0 enabled or requested - `SSLContext.getInstance("SSL"|"SSLv2"|"SSLv3")`, `TlsVersion.SSL_3_0`, `SSLv3` in `setEnabledProtocols`.
- Finding: defaulting to / only supporting TLS 1.0 or 1.1 - `SSLContext.getInstance("TLSv1"|"TLSv1.1")` as the connection's protocol, an explicit `setEnabledProtocols` array whose highest is 1.0/1.1, or an OkHttp `ConnectionSpec` whose `tlsVersions` top out at TLS_1_0/TLS_1_1.
- Pass-with-note: TLS 1.0/1.1 left ENABLED as fallback alongside 1.2+ (highest is negotiated by default) - record the weakness and recommend disabling; OkHttp `ConnectionSpec.COMPATIBLE_TLS` falls here (it permits 1.0/1.1).
- `getInstance("TLS")`/`"Default"` disposition is minSdk- and factory-aware (see the READ THIS FIRST decision procedure): Compliant if the factory restricts protocols to >=TLS 1.2 OR `minSdk >= 20`; Finding if `minSdk < 20` AND no `setEnabledProtocols` restriction (the API 16-19 default negotiates SSLv3/TLS 1.0). Decide only after reading the factory body and the manifest `minSdk` - never from the `getInstance` line alone.

Cipher classification (NIST SP.800-52r2 / BSI TR-02102-2)
- Compliant: AEAD suites with forward secrecy - `TLS_ECDHE_*`/`TLS_DHE_*` with `*_GCM_*` or ChaCha20-Poly1305 (e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_AES_128_GCM_SHA256`). Platform-default cipher list is Compliant.
- Finding (known-vulnerable, never negotiable): any suite containing `NULL`, `anon`/`ADH`/`aNULL`, `EXPORT`, `DES` (single), `3DES`/`DES_CBC3` (Sweet32), `RC4`, `MD5`-based MAC, or `< 128`-bit keys.
- Pass-with-note: non-AEAD CBC suites or static-RSA suites (`TLS_RSA_WITH_*`, no forward secrecy) explicitly enabled - discouraged by BSI/NIST; record but not a hard fail unless combined with a vulnerable element.

TLS configuration APIs to enumerate
`javax.net.ssl.SSLContext.getInstance(...)`+`init`, `SSLSocketFactory`/`SSLSocket`, `SSLSocket.setEnabledProtocols`/`setEnabledCipherSuites`, `SSLServerSocket`; OkHttp `ConnectionSpec`(`MODERN_TLS`/`COMPATIBLE_TLS`/`Builder().tlsVersions(...).cipherSuites(...)`), `OkHttpClient.Builder().connectionSpecs(...)`; Retrofit/Ktor client TLS config; `HttpsURLConnection.setSSLSocketFactory`; `Conscrypt`/BouncyCastle JSSE provider setup; `WebView` (uses platform TLS - default Compliant unless a custom stack is injected).

Procedure
1. Detect TLS usage, e.g. `grep -rEn "SSLContext|SSLSocket|SSLSocketFactory|setEnabledProtocols|setEnabledCipherSuites|ConnectionSpec|TlsVersion|tlsVersions|cipherSuites|HttpsURLConnection|Conscrypt|getInstance\(\"(SSL|TLS)" jadx/sources/` plus the network libraries in use. If there are no TLS connections (and no sensitive network traffic), the verdict is `n/a`.
2. For each TLS use, determine whether it uses platform/library DEFAULTS (Compliant good-pattern, including `getInstance("TLS")`) or an EXPLICIT weak configuration. For any custom `SSLSocketFactory`/`TLSSocketFactory`/`SSLContext`, **read the full class body** - its `createSocket`/wrap methods and constructor - to see whether it calls `setEnabledProtocols`/`setEnabledCipherSuites`, and what it enables. Do not conclude from the `getInstance("TLS")` line alone; only an explicit weak artifact (legacy protocol string, sub-1.2 protocol array, or vulnerable cipher) is a finding. Read explicit configs for: the protocol string passed to `SSLContext.getInstance`, the arrays in `setEnabledProtocols`/`setEnabledCipherSuites`, and OkHttp `ConnectionSpec` versions/ciphers.
3. Classify version and ciphers against the lists above. Resolve cipher constants/arrays to their suite names.
4. **Read the surrounding context** to confirm what the connection carries (sensitivity) and that the config is actually applied to a live client (not an unused builder). Indeterminate -> prefer `unverified`.
5. **Ownership + reachability (mandatory for a `fail`).** Confirm proprietary code applies the weak config with `find_callers`/source, and cite it. (Third-party network libraries the app configures are in scope for misconfiguration; an independent SDK's own internal TLS the app does not configure is the SDK's posture - note but do not fail the app on it.) Owner undecidable/obfuscated -> proprietary (in scope); never silently dropped. A `fail` without an evidenced owner + cited path is invalid -> `unverified`.
6. Conclude per TLS use: Finding (SSL2/3 enabled, default to TLS1.0/1.1, or vulnerable cipher negotiable - proprietary & reachable); Compliant (TLS1.2+, modern ciphers, or platform default); Pass-with-note (1.0/1.1 fallback enabled, or non-AEAD/static-RSA enabled); Unverified (config runtime-driven / unresolved); documented candidate (see rules).
7. Budget ~2-4 reads per explicit TLS config plus 1-2 call-graph hops. If the protocol/cipher set, applicability, owner, or reachability can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
The actually-negotiated protocol/suite depends on a live handshake with the backend; static analysis judges only the app-side configuration (which is the test's scope). Where the TLS config is assembled from runtime/server config not in the bytecode, it can't be confirmed statically -> `unverified`, and `needs_dynamic_testing` may be set (non-binding) for a handshake scan. TLS handled fully inside native code or a no-source SDK -> `unverified` (name the entry point). The static verdict is made on what was determinable.

Output
List **all** TLS uses - one L1 row per use with its version/cipher disposition. <=20 uses -> one L1 row each. >20 uses (collapse) -> group Compliant uses by functionality (e.g. "API clients on platform-default TLS - 14 uses") as one L1 row per group, but always break out every Finding, Pass-with-note, documented-candidate, and unverified use as its own individual L1 row. Never sample findings.
- Finding: L1 row plus L2 rows for the weak version/cipher config (the protocol string / enabled arrays / ConnectionSpec), for the context (it is a live client carrying app traffic), and for ownership+`find_callers` reachability.
- Compliant: L1 row plus L2 for the modern config or the platform-default usage.
- Group: L1 summary plus an L2 naming the references and the shared (default/modern) posture.

```
{
  "id": "tls-001",
  "description": "Finding (SSLv3 + RC4 enabled): A custom SSLSocketFactory enables SSLv3 and an RC4 cipher suite on the app's primary API client.",
  "reference": "jadx/sources/com/example/app/net/LegacyTls.java",
  "level": 1
},
{
  "id": "L2-LegacyTls-version",
  "description": "Version (hard finding): SSLContext.getInstance(\"SSLv3\") at line 18, and socket.setEnabledProtocols(new String[]{\"SSLv3\",\"TLSv1\"}) at line 31 - SSL 3.0 enabled and the highest offered is TLSv1. Violates NIST SP.800-52r2 / BSI TR-02102-2.",
  "reference": "jadx/sources/com/example/app/net/LegacyTls.java:14-34",
  "level": 2
},
{
  "id": "L2-LegacyTls-cipher",
  "description": "Cipher (vulnerable): setEnabledCipherSuites includes TLS_RSA_WITH_RC4_128_SHA at line 38 - RC4 is a known-broken stream cipher, never negotiable per the standards.",
  "reference": "jadx/sources/com/example/app/net/LegacyTls.java:36-42",
  "level": 2
},
{
  "id": "L2-LegacyTls-reachability",
  "description": "Ownership + reachability: LegacyTls is first-party (app namespace) -> proprietary (obfuscated/undecidable would also default proprietary). find_callers: LegacyTls.factory <- ApiClient.<init> <- Repository.fetchProfile. The weak factory is applied to the live API client in proprietary code.",
  "reference": "jadx/sources/com/example/app/net/ApiClient.java:50-60",
  "level": 2
},
{
  "id": "tls-default-group",
  "description": "Compliant group: 14 API/CDN clients on platform-default TLS (no protocol/cipher override) - inherit TLS 1.2/1.3 and modern ciphers.",
  "reference": "jadx/sources/com/example/app/net/",
  "level": 1
},
{
  "id": "L2-default-coverage",
  "description": "Good pattern: OkHttpClient built without connectionSpecs/SSLSocketFactory overrides (or with ConnectionSpec.MODERN_TLS); Retrofit baseUrl https. No setEnabledProtocols/CipherSuites calls. References NetModule.java:20-110 (and 13 more).",
  "reference": "jadx/sources/com/example/app/net/NetModule.java:20-110",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "T TLS uses enumerated, E with explicit config, N findings (SSL2/3, default TLS1.0/1.1, vulnerable cipher), C compliant (incl. platform default), W pass-with-note, U unverified. <one or two sentences naming the clients, protocols and ciphers>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only to recommend a handshake scan where the config is runtime-driven (recorded `unverified`). It does not change `pass`/`fail`.
- `fail`: >=1 TLS use with (a) an L2 row showing SSL 2.0/3.0 enabled, a default to TLS 1.0/1.1, or a known-vulnerable cipher enabled/negotiable; (b) an L2 row showing the config applies to a live client carrying app traffic; AND (c) an L2 row giving an evidenced proprietary-ownership + `find_callers` reachability determination.
- **Do not flag platform/library-default TLS or `getInstance("TLS")` on the call line alone.** A client with no override on `minSdk >= 20` inherits modern defaults and is Compliant. But `getInstance("TLS")` is a Finding when, after reading the factory body, you confirm it imposes no protocol restriction AND `minSdk < 20` (API 16-19 default = SSLv3/TLS 1.0). Decide by reading the factory and the manifest minSdk - never flag on the `getInstance` line without both, and never blindly pass when `minSdk < 20` and no restriction exists.
- **Enforcement.** A candidate finding missing the applicability/context row OR the ownership+reachability row is invalid -> `unverified`. Ownership/reachability may NOT be asserted from a package name or prose; they come from an actual `find_callers` result and an evidenced owner decision.
- **No sampling.** Every finding is its own L1 row; the rationale finding count MUST equal the finding L1 rows (grouping is only for Compliant uses).
- `pass`: TLS is used and every app-side TLS configuration is TLS 1.2+ with non-vulnerable ciphers (explicit or platform default), with L2 coverage; pass-with-note items are recorded but do not by themselves fail.
- `n/a`: the app establishes no TLS connections / transmits no sensitive network data (enumeration performed; state this).
- Documented exception: a documented justification for a legacy protocol/cipher (e.g. a mandated legacy backend) is a documentation fact outside the APK - record as a Finding "documented candidate" with a matching `false_positive_risks` entry; counts toward `fail` unless the assessor downgrades it.
- Trust/identity issues (trust-all, no pinning) are a different control - do not fail this test on them; mention only.
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `false_positive_risks` is for factors **outside the static artifact only** (documented legacy-backend justifications, config delivered at runtime by server, OEM TLS-stack behavior, the live-negotiated suite differing from the offered set). Statements about what in-APK code does must be resolved by reading it (Finding/Compliant/Pass-with-note/`unverified`), not placed here. In particular, hedges like "the code path may only run on newer Android versions" or "the app might subsequently enable secure protocols on the socket" are in-APK facts you must RESOLVE by reading the factory/call site and the `minSdk` - they are INVALID as `false_positive_risks` entries.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a candidate finding was dropped/out-of-scoped without evidence, or if any `fail` lacks its three L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) you can QUOTE the weak basis - either an explicit weak artifact (legacy protocol string in `getInstance`; a `setEnabledProtocols`/`tlsVersions` array topping out below TLS 1.2 or containing SSLv3; a vulnerable cipher in `setEnabledCipherSuites`/`cipherSuites`), OR a confirmed `getInstance("TLS")`/default site where you READ the factory body and it imposes no protocol restriction AND `minSdk < 20` (quote the minSdk). A finding from a `getInstance("TLS")` call line alone - no factory read, no minSdk - or from "best practice is TLSv1.2" reasoning is INVALID; delete it. Conversely do not pass a `minSdk < 20` unrestricted-default site. (2) the config applies to a live client; (3) an evidenced proprietary-ownership decision was made AND `find_callers` was run and cited. If any is missing, downgrade to `unverified` or Compliant. Then confirm the rationale counts reconcile (no sampling) and no `false_positive_risks` entry describes in-APK code (no "may only run on newer versions" / "might enable protocols later" hedges - read and resolve them). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.