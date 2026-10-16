MASTG-TEST-XXXX

masvs_v1_id    MSTG-NETWORK-1
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Network connections used for sensitive purposes are encrypted (no unjustified cleartext) (static)

What this test looks for
Every network connection used for a sensitive purpose over the internet must be encrypted (typically TLS). The app must not permit or use cleartext (http/ws/raw TCP) for sensitive purposes without justification - checked across the manifest, the network-security-config (NSC), third-party network-library configuration, and actual usage in code. This is a static, inventory-style evaluation: enumerate every network use, infer its purpose from the call context, and flag any cleartext + sensitive + internet connection that is permitted or used without justification. Verdict: `pass` (no unjustified sensitive cleartext over the internet), `fail` (sensitive cleartext over the internet is permitted or used without justification), `n/a` (the app makes no network connections for sensitive purposes), or `inconclusive`.

This test is about **encryption (cleartext vs encrypted) only**. Encrypted-but-unauthenticated problems - trust-all `TrustManager`, `HostnameVerifier` returning true, disabled pinning - are a separate control (certificate/identity validation, MASVS-NETWORK-2); note them in passing but do not base this verdict on them.

Source is ground truth. A network-call evidence index is a candidate list only - confirm schemes, endpoints, the NSC contents, and library config by reading `jadx/sources/`, `AndroidManifest.xml`, and `res/xml/*network*security*config*.xml` (and other `res/xml` configs). The `find_callers`/`find_callees` call graph gives *candidate* chains, not confirmed flow.

Scope - sensitivity and reach
In scope: connections whose inferred purpose is sensitive - authentication/login, API calls carrying user data/tokens/credentials/session, payment, account management, PII, user file upload/download, push/registration carrying tokens, security-relevant config fetch.
Out of scope (per spec - report but do not fail): anonymous analytics/telemetry with no PII, advertising, free-browsing WebViews (user navigates arbitrary sites), connections to on-device (`localhost`/`127.0.0.1`/`10.0.2.2`) or local-network servers (RFC1918: `10.*`, `192.168.*`, `172.16-31.*`, `.local`/mDNS), and any connection with a documented valid justification (a documentation fact - see rules). Public static-asset CDNs of non-sensitive content are low-risk; judge by whether sensitive data rides the connection.

Cleartext signals (declarative + code)
- Manifest: `android:usesCleartextTraffic="true"` on `<application>`. Also the **targetSdk default**: with no NSC and no explicit attribute, cleartext is *blocked by default on targetSdk >= 28* but *allowed by default on targetSdk < 28* - so an app targeting < 28 with no NSC permits cleartext globally.
- network-security-config (referenced via `android:networkSecurityConfig="@xml/..."`): `<base-config cleartextTrafficPermitted="true">` (global allow), `<domain-config cleartextTrafficPermitted="true"><domain>host</domain>` (per-domain allow). `cleartextTrafficPermitted="false"` blocks it. Read the actual XML and map which domains are permitted cleartext.
- Code/resources: hardcoded `http://` (or `ws://`) URLs for sensitive endpoints; Retrofit/Ktor `baseUrl`/host on `http`; OkHttp `ConnectionSpec.CLEARTEXT` or allowing http; `WebView.loadUrl("http://...")` for a sensitive page; raw `java.net.Socket`/`ServerSocket` (not `SSLSocket`/`SSLServerSocket`) to an internet host; `URL("http://...").openConnection()`.

Purpose inference (REQUIRED per network use)
For every network use, infer and record what it is for from the call context - the host and path, the data placed in the request (auth headers, credentials, PII), the calling method/class name, and surrounding code. Examples: a POST to `/login` with username/password -> authentication (sensitive); a GET of `/v1/account` with a bearer token -> account API (sensitive); a beacon to an analytics host with a random id -> anonymous analytics (out of scope); a WebView loading user-entered URLs -> free browsing (out of scope). Do not infer from the URL string alone if the surrounding code contradicts it; if the purpose is indeterminate, prefer `unverified` over guessing sensitive or non-sensitive.

Procedure
1. Read `AndroidManifest.xml` for `usesCleartextTraffic`, `targetSdkVersion`, and the `networkSecurityConfig` reference; read the referenced NSC XML and record the global/per-domain cleartext posture (accounting for the targetSdk default when nothing is declared).
2. Enumerate network uses in code/resources, e.g. `grep -rEn "http://|ws://|HttpURLConnection|openConnection|OkHttpClient|Retrofit|\.baseUrl|Request\.Builder|Volley|Ktor|HttpClient|new Socket|SSLSocket|WebView|loadUrl|ConnectionSpec\.CLEARTEXT" jadx/sources/` plus a scan of `res/` for `http://` URLs. If there are no network uses at all, or none for a sensitive purpose, the verdict is `n/a`.
3. For each network use, determine: the scheme (cleartext vs encrypted), the host (internet vs localhost/local-network), and the **inferred purpose** (sensitive vs out-of-scope) from context. Record the inferred purpose on the row regardless of outcome.
4. Cross the declarative posture with actual use: a sensitive endpoint reachable over cleartext because (a) the NSC/manifest permits cleartext for its domain (or by targetSdk default) and/or (b) the code uses an `http://` URL for it.
5. **Ownership + reachability (mandatory for a `fail`).** Confirm proprietary code performs/permits the sensitive cleartext connection with `find_callers`/source reading, and cite it. (Third-party *network libraries the app drives* - OkHttp/Retrofit/etc. - are in scope for misconfiguration; independent analytics/ad SDKs doing their own anonymous traffic are out of scope by purpose.) Owner undecidable/obfuscated -> proprietary (in scope); never silently dropped. A `fail` without an evidenced owner + cited path is invalid -> `unverified`.
6. Conclude per network use: Finding (cleartext + sensitive + internet, permitted or used, unjustified, proprietary & reachable); Compliant (encrypted, or cleartext but out-of-scope by purpose/reach); Out-of-scope (analytics/ads/free-WebView/local); Unverified (scheme, purpose, host, owner, or reachability unresolved); justification candidate (see rules).
7. Budget ~2-4 reads per non-trivial network use (manifest/NSC once, then per endpoint) plus 1-2 call-graph hops. If scheme, purpose, host, owner, or reachability can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Network calls fully inside native code or a no-source SDK can't be classified statically -> `unverified` (name the entry point). Whether a given endpoint actually carries sensitive data may depend on runtime payloads not fully visible statically; where the purpose is genuinely indeterminate, use `unverified`. The static verdict is made on what was determinable and is not deferred to runtime.

Output
List **all** network uses - one L1 row per use, and **every row MUST state the inferred purpose from the call context**. <=20 uses -> one L1 row each. >20 uses -> group Compliant and Out-of-scope uses by functionality (e.g. "image CDN over https - 12 uses (purpose: public asset loading)", "analytics beacons - 6 uses (purpose: anonymous telemetry, out of scope)") as one L1 row per group with the shared inferred purpose, but always break out every Finding, justification-candidate, and unverified use as its own individual L1 row. Never sample findings.
- Finding: L1 row (stating inferred purpose) plus L2 rows for the cleartext evidence (manifest/NSC permission and/or the http URL), for the sensitive-purpose context read from code, and for ownership+`find_callers` reachability.
- Compliant: L1 row (inferred purpose) plus L2 for the encryption or the out-of-scope reason.
- Group: L1 summary with shared inferred purpose plus an L2 naming the references.

```
{
  "id": "net-001",
  "description": "Finding (inferred purpose: authentication): The login request is sent over cleartext HTTP to an internet host; the NSC permits cleartext for that domain.",
  "reference": "jadx/sources/com/example/app/net/AuthApi.java",
  "level": 1
},
{
  "id": "L2-AuthApi-cleartext",
  "description": "Cleartext: Retrofit baseUrl \"http://api.example.com/\" at line 30 (http scheme), and res/xml/network_security_config.xml has <domain-config cleartextTrafficPermitted=\"true\"><domain>api.example.com</domain>. Internet host, cleartext permitted and used.",
  "reference": "jadx/sources/com/example/app/net/AuthApi.java:26-34",
  "level": 2
},
{
  "id": "L2-AuthApi-purpose",
  "description": "Sensitive purpose: AuthApi.login POSTs /login with the user's username and password in the body (read from surrounding code). Credentials transit in cleartext.",
  "reference": "jadx/sources/com/example/app/net/AuthApi.java:40-52",
  "level": 2
},
{
  "id": "L2-AuthApi-reachability",
  "description": "Ownership + reachability: AuthApi is first-party (app namespace) -> proprietary (obfuscated/undecidable would also default proprietary). find_callers: AuthApi.login <- LoginViewModel.submit <- LoginActivity.onLogin. Live in proprietary code.",
  "reference": "jadx/sources/com/example/app/ui/LoginActivity.java:70-78",
  "level": 2
},
{
  "id": "net-analytics-group",
  "description": "Out-of-scope group (inferred purpose: anonymous analytics): 6 cleartext beacons to a telemetry host carrying only a random install id, no PII. Out of scope per spec.",
  "reference": "jadx/sources/com/example/app/metrics/",
  "level": 1
},
{
  "id": "L2-analytics-coverage",
  "description": "Out of scope: Metrics.send posts a counter and a random UUID to http://t.example-metrics.com; no credentials/PII in the payload (read from code). References Metrics.java:18-60 (and 5 more).",
  "reference": "jadx/sources/com/example/app/metrics/Metrics.java:18-60",
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
  "rationale": "W network uses enumerated, S sensitive-in-scope, N findings (sensitive cleartext over internet), C compliant, O out-of-scope (analytics/ads/free-WebView/local), J justification-candidates, U unverified. Manifest/NSC cleartext posture: <summary>. <one or two sentences naming the endpoints, purposes and config>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only to recommend a capture where a payload's sensitivity could not be confirmed statically (recorded `unverified`). It does not change `pass`/`fail`.
- `fail`: >=1 network use with (a) an L2 row showing cleartext to an internet host is permitted (manifest/NSC/targetSdk default) and/or used (http/ws/raw socket) for it, (b) an L2 row establishing a **sensitive inferred purpose** read from the call context, AND (c) an L2 row giving an evidenced proprietary-ownership + reachability determination.
- **Enforcement.** A candidate finding missing the purpose row OR the ownership+reachability row is invalid -> downgrade to `unverified`. Ownership/reachability may NOT be asserted from a package name or prose; they come from an actual `find_callers` result and an evidenced owner decision. Purpose may NOT be inferred from a URL string alone when the surrounding code is unread.
- **Every row states an inferred purpose.** A network-use row (finding, compliant, group, or unverified) without an inferred purpose is incomplete -> `inconclusive`.
- **No sampling.** Every finding is its own L1 row; the rationale finding count MUST equal the finding L1 rows (grouping is only for compliant/out-of-scope uses).
- `pass`: network is used but no sensitive cleartext crosses the internet - all sensitive traffic is encrypted, and any cleartext is out-of-scope by purpose/reach or justified, with L2 coverage and the NSC/manifest posture summarized.
- `n/a`: the app makes no network connections, or none for a sensitive purpose (enumeration performed; state this).
- Justification clause: a documented valid justification for a specific cleartext connection is a documentation fact outside the APK - record such a use as a Finding "justification-candidate" with a matching `false_positive_risks` entry stating the assessor should downgrade it only if the justification is documented. It counts toward `fail` unless the assessor applies it.
- Out-of-scope by purpose/reach (anonymous analytics, ads, free-browsing WebView, localhost/RFC1918/.local) is reported as Out-of-scope, not Finding - but the non-sensitive purpose / local reach must be evidenced from code, not assumed.
- Encrypted-but-unauthenticated issues (trust-all, no pinning) are a different control - do not fail this test on them; mention only.
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `false_positive_risks` is for factors **outside the static artifact only** (documented justifications, payload sensitivity decided at runtime, server-side redirect to https). Statements about what in-APK code does must be resolved by reading it (Finding/Compliant/Out-of-scope/`unverified`), not placed here.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any row lacks an inferred purpose, if any false_positive_risk references in-APK code, if a candidate finding was dropped/out-of-scoped without evidence, or if any `fail` lacks its three L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) cleartext-to-internet is evidenced from manifest/NSC and/or an http URL in code; (2) the sensitive purpose was read from the call context (not the URL string alone); (3) an evidenced proprietary-ownership decision was made AND `find_callers` was run and cited. Confirm every network-use row carries an inferred purpose, the rationale counts reconcile (no sampling), and no `false_positive_risks` entry describes in-APK code. If any per-finding item is missing, downgrade to `unverified`. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.