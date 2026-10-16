MASTG-TEST-0233

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Hardcoded HTTP URLs - cleartext endpoints used for communication (static)

What this test looks for
The app must not communicate over unencrypted HTTP. This test enumerates hardcoded `http://` URLs in code/resources and determines whether any are actually USED to make network requests (vs inert constants, comments, XML namespaces, or documentation links). A confirmed cleartext request is a finding. This is a static, taint-style evaluation: an `http://` URL reaching a networking API. Verdict: `pass` (no `http://` URL is used for communication - none present, or all are inert/non-network), `fail` (>=1 `http://` URL is used to make a request), `n/a` (the app contains no `http://` URLs at all), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `http://`. If NONE appear in code/resources -> `n/a` (state the search). Many `http://` hits are namespaces/schemas (e.g. `http://schemas.android.com/...`, `http://www.w3.org/...`) or analytics/docs links - these are NOT findings unless used for app data transfer.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `http://` URL AND the networking call that consumes it. A URL with no quoted network use is an inert constant -> Compliant/Unverified, not a Finding.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` (or the resource path) of the URL and its use, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the `http://` URL and (b) its use in a networking API. "this URL is probably requested" is NOT evidence -> `unverified`. A URL used only as an XML namespace / a constant never passed to a network call is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If a URL's use (network vs inert) can't be resolved within budget, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Networking sinks (where an http URL becomes a request)
`new URL(httpUrl).openConnection()` / `HttpURLConnection`, `OkHttpClient`/`Request.Builder().url(httpUrl)`, Retrofit `@GET/@POST`/`baseUrl(httpUrl)`, Apache `HttpGet/HttpPost`, `Volley`, `WebView.loadUrl(httpUrl)`, `Socket`/`SocketChannel` to port 80, gRPC/WebSocket cleartext endpoints, any HTTP client library fed the URL.

Inert (NOT a finding)
XML/XSD/RDF namespaces (`http://schemas.android.com`, `http://www.w3.org`, `http://apache.org`), licence/documentation/marketing links never requested, string constants present but never passed to a network call, URLs only logged.

Procedure
1. Enumerate cleartext URLs: `grep -rEn "http://" jadx/sources/ jadx/resources/` (also `strings.xml`/`res/`). If none -> short-circuit `n/a` (state the search). Exclude obvious namespace prefixes when tallying findings (but still account for them as inert).
2. For each non-namespace `http://` URL, trace whether it reaches a networking sink (directly or via a constant/baseUrl). Quote the URL + the sink. Inert -> Compliant.
3. Cross-check cleartext policy as supporting context: whether the manifest `android:usesCleartextTraffic` / the Network Security Configuration would even permit the request (see MASTG-TEST-0235). A request blocked by a strict NSC weakens (but does not by itself clear) a finding - note it; the presence of a real cleartext request remains the test. State the cleartext policy as an Observation.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A cleartext endpoint inside a third-party SDK carrying app data is reported.
5. Conclude per URL: Finding (http URL + networking use quoted); Compliant (inert/namespace/non-network, quoted); Unverified (use unresolved).
6. Budget ~2-4 reads per candidate URL (the literal, the consuming call, 1-2 hops). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
URL construction/use inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a request actually fires is confirmed at runtime (MASTG-TEST-0236/0238). TLS version is MASTG-TEST-0217. This test confirms cleartext-HTTP USE statically.

Output
List **all** non-namespace `http://` URLs carrying potential app traffic - one L1 row per URL (or per endpoint) with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group inert/namespace URLs as one L1 row per group, but always break out every Finding and unverified URL individually. Never sample findings.
- Cleartext policy: one L1 row stating the manifest `usesCleartextTraffic` value and whether an NSC is present (a required Observation; cross-ref MASTG-TEST-0235).
- Finding: L1 row plus L2 rows quoting the `http://` URL and the networking use, plus owner.
- Compliant: L1 row plus an L2 showing the URL is inert/namespace/non-network (quoted).
- Group: L1 summary plus an L2 naming references and the shared inert pattern.

```
{
  "id": "http-001",
  "description": "Finding (cleartext HTTP used for communication): The app fetches its config over http://, exposing it to interception and tampering.",
  "reference": "jadx/sources/com/example/app/net/ConfigApi.java",
  "level": 1
},
{
  "id": "L2-http-url",
  "description": "Cleartext URL (quoted): private static final String BASE = \"http://api.example.com/v1/\"; at ConfigApi.java:18.",
  "reference": "jadx/sources/com/example/app/net/ConfigApi.java:18",
  "level": 2
},
{
  "id": "L2-http-use",
  "description": "Networking use (quoted): Retrofit r = new Retrofit.Builder().baseUrl(BASE).build(); r.create(ConfigService.class).getConfig() at lines 24-28 - http base URL drives real API calls. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/net/ConfigApi.java:24-28",
  "level": 2
},
{
  "id": "http-inert-group",
  "description": "Compliant group: 12 http:// strings that are XML namespaces / documentation links, never passed to a network call.",
  "reference": "jadx/resources/res/",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0233",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Cleartext policy: usesCleartextTraffic=<value>, NSC <present/absent>. H http:// URLs found, X namespace/inert, R reaching a networking sink, N findings, C compliant, U unverified. Any http:// URL used for communication? <no -> pass / n/a if none at all / yes>. <one or two sentences naming each cleartext request>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` MAY be true where a URL's request can only be confirmed at runtime; it does not change `pass`/`fail`.
- `fail`: >=1 `http://` URL with (a) an L2 row quoting the URL AND (b) an L2 row quoting its use in a networking API. A finding stated with "likely"/"may" instead of the quoted URL+use is INVALID -> `unverified`.
- **Use, not mere presence.** A hardcoded `http://` URL that is a namespace, a doc link, or a never-requested constant is Compliant - not a finding. The OWASP control explicitly fails only on CONFIRMED communication use.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (a strict NSC blocks the request at runtime; the endpoint redirects to HTTPS server-side) - in-APK facts (is the URL requested?) resolved by reading, unresolved -> `unverified`.
- `pass`: no `http://` URL is used for communication - either none present beyond namespaces/inert, or all are demonstrably non-network, with L2 coverage.
- `n/a`: no `http://` URLs at all in code/resources (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its URL + networking-use L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `http://` URL is quoted; (2) its use in a networking API is quoted; (3) it is not a namespace/inert constant; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the http:// search was performed (n/a / pass state it), the cleartext policy Observation is recorded, every candidate URL's use was read and quoted (unread -> `unverified`), no namespace/inert URL was flagged as a Finding, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
