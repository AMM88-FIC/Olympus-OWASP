MASTG-TEST-0236

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Cleartext Traffic Observed on the Network - actual HTTP communication (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0236 is a dynamic test (intercept live traffic and observe any cleartext communication the app actually makes). This static engine cannot capture traffic, so this prompt performs the best-effort static equivalent - the combined analysis of MASTG-TEST-0235 (manifest/NSC permits cleartext) and MASTG-TEST-0233 (an `http://` URL reaches a networking API). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only a traffic capture proves a cleartext request was actually sent - the static verdict shows whether the app is CONFIGURED and CODED to send cleartext, which is the best static proxy.

What this test looks for
At runtime the app must send no cleartext traffic. Statically, the proxy is twofold: (a) the configuration permits cleartext (manifest `usesCleartextTraffic`/NSC `cleartextTrafficPermitted`), AND/OR (b) the code passes an `http://` URL to a networking API. A confirmed cleartext request site - especially one that the configuration also permits - is a finding. Verdict: `pass` (no cleartext is both permitted and used - no `http://` networking use, or configuration blocks it and no code uses it), `fail` (>=1 `http://` URL reaches a networking API, with cleartext permitted by config), `n/a` (no `http://` URLs and no permissive cleartext config), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `http://` and read the cleartext policy. If there are no `http://` URLs in code AND the configuration does not permit cleartext -> `n/a`/`pass` (state the searches).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code/config it rests on.** Quote the `http://` URL + networking call, and the cleartext-permitting config (manifest/NSC) where relevant. No quoted evidence -> `unverified`.
2. **Read from the code/config, not the index.** Cite `jadx/sources/...:<line-range>` and `jadx/resources/...:<line>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the `http://` URL and (b) its use in a networking API. "the app probably sends cleartext" is NOT evidence -> `unverified` (flagged for the dynamic capture).
4. **Unresolved determinacy is `unverified`, not a hedge.** If a URL's network use can't be resolved statically, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Networking sinks
`HttpURLConnection`, OkHttp/Retrofit (`url(...)`/`baseUrl(...)`), Apache HttpClient, Volley, `WebView.loadUrl`, raw `Socket` to port 80, cleartext gRPC/WebSocket. (Same sinks as MASTG-TEST-0233.)

Procedure
1. Enumerate cleartext URLs: `grep -rEn "http://" jadx/sources/ jadx/resources/` (exclude XML namespaces / inert constants from findings). Read the cleartext policy (manifest `usesCleartextTraffic`, NSC `cleartextTrafficPermitted`) as in MASTG-TEST-0235. If no http networking use and no permissive config -> short-circuit (state both).
2. For each non-namespace `http://` URL, trace whether it reaches a networking sink. Quote URL + sink.
3. Correlate with config: a cleartext request that the manifest/NSC also PERMITS is a strong finding; a cleartext request that a strict NSC would block is still reported (the code intends cleartext) but note the config tension. Quote the governing config.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per URL: Finding (http URL + networking use quoted, config noted); Compliant (inert/namespace/non-network, or blocked-and-unused); Unverified (use unresolved -> confirm at runtime).
6. Budget ~2-4 reads per candidate (URL, consuming call, config). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether the request actually fires is runtime-only - hence the forced `needs_dynamic_testing`. URL use in native code or a no-source SDK -> `unverified` (name the entry point). TLS-version downgrade is MASTG-TEST-0217/0218.

Output
List **all** non-namespace `http://` networking uses - one L1 row per URL with its disposition - plus one L1 row for the cleartext policy. <=20 -> one L1 row each. >20 (collapse) -> group inert/namespace URLs as one L1 row, but always break out every Finding and unverified URL individually. Never sample findings.
- Cleartext policy: L1 row (manifest + NSC summary; cross-ref MASTG-TEST-0235).
- Finding: L1 row plus L2 rows quoting the `http://` URL, its networking use, and the permitting config, plus owner.
- Compliant: L1 row plus an L2 showing inert/non-network or blocked-and-unused.

```
{
  "id": "ctr-001",
  "description": "Finding (cleartext request configured and coded): The app POSTs telemetry to an http:// endpoint, and the NSC permits cleartext for that domain - cleartext almost certainly flows at runtime.",
  "reference": "jadx/sources/com/example/app/net/Telemetry.java",
  "level": 1
},
{
  "id": "L2-ctr-url",
  "description": "Cleartext networking use (quoted): Request req = new Request.Builder().url(\"http://logs.example.com/ingest\").post(body).build(); client.newCall(req).execute() at Telemetry.java:55-60. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/net/Telemetry.java:55-60",
  "level": 2
},
{
  "id": "L2-ctr-config",
  "description": "Permitting config (quoted): <domain-config cleartextTrafficPermitted=\"true\"><domain>logs.example.com</domain></domain-config> at network_security_config.xml:12-15 - config permits this cleartext request. Runtime capture required to confirm.",
  "reference": "jadx/resources/res/xml/network_security_config.xml:12-15",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0236",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Cleartext policy: usesCleartextTraffic=<val>, NSC <summary>. H http:// URLs, R reaching a networking sink, P also permitted by config, N findings, C compliant, U unverified. Cleartext coded+permitted? <no -> pass/n-a / yes>. <one or two sentences; runtime capture confirms>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that a traffic capture is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 `http://` URL with (a) an L2 row quoting the URL AND (b) an L2 row quoting its use in a networking API; the permitting config is quoted where it applies. A finding stated with "likely"/"may" instead of the quoted URL+use is INVALID -> `unverified`.
- **Use, not mere presence.** Namespaces/inert constants are Compliant (as MASTG-TEST-0233).
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (a strict NSC blocks the coded request; the endpoint upgrades to HTTPS) - in-APK facts (is the URL requested? does config permit it?) resolved by reading, unresolved -> `unverified`.
- `pass`: no cleartext networking use (beyond namespaces/inert), or config blocks it and no code uses it, with L2 coverage.
- `n/a`: no `http://` URLs and no permissive cleartext config (short-circuit; state the searches).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code/config, if a finding was dropped without evidence, or if any `fail` lacks its URL + networking-use L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `http://` URL is quoted; (2) its networking use is quoted; (3) it is not a namespace/inert constant; (4) the permitting config is quoted where it applies; (5) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the http:// search and the cleartext-policy read were performed (state them), every candidate URL's use was read and quoted (unread -> `unverified`), no namespace/inert URL was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
