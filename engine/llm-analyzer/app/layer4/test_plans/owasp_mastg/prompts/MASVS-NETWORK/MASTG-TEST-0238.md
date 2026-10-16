MASTG-TEST-0238

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Runtime Use of Network APIs Transmitting Cleartext Traffic - cleartext via networking APIs (dynamic; static approximation)

NOTE - DYNAMIC TEST + UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC APPROXIMATION: OWASP ships MASTG-TEST-0238 as a `status: placeholder` DYNAMIC test (hook the networking APIs with Frida and `.backtrace()` to attribute every cleartext transmission to an exact code location in THIS app). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - enumerate the networking-API call sites that transmit over cleartext (`http://` URLs / port-80 sockets reaching a networking sink), the same surface as MASTG-TEST-0233, attributed to the call site. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only the hook+backtrace proves a cleartext send occurred and pins the exact runtime location - the static verdict lists the call sites capable of it.

What this test looks for
The app must transmit nothing over cleartext through its networking APIs. Statically, the proxy is each networking call site whose endpoint is `http://` (or a raw socket to port 80). Verdict: `pass` (no networking call site transmits over cleartext - all endpoints are https / inert), `fail` (>=1 networking call site uses an `http://` endpoint / port-80 socket for app traffic), `n/a` (the app makes no network calls / contains no `http://` networking use), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `http://` and the networking sinks. If no networking call site uses cleartext -> `pass`/`n/a` (state the searches). The runtime send is still flagged via the forced `needs_dynamic_testing`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the networking call AND the `http://` endpoint / port-80 target it transmits to. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual call site, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the networking API call and (b) its cleartext endpoint. "this method probably sends cleartext" is NOT static evidence -> `unverified` (flagged for the hook).
4. **Unresolved determinacy is `unverified`, not a hedge.** If the endpoint is built at runtime and can't be resolved statically, the row is `unverified` (the backtrace resolves it dynamically). `false_positive_risks` is out-of-APK only.

Networking sinks (cleartext-capable)
`HttpURLConnection`/`URL.openConnection()` on an `http://` URL, OkHttp/Retrofit `url(...)`/`baseUrl(...)` with `http://`, Apache `HttpGet/HttpPost`, Volley, `WebView.loadUrl("http://...")`, raw `Socket("host", 80)` / `SocketChannel` writing an HTTP request, cleartext gRPC (`usePlaintext()`)/WebSocket (`ws://`).

Procedure
1. Enumerate networking call sites with a cleartext endpoint: `grep -rEn "http://|ws://|usePlaintext|new Socket\(|openConnection|HttpURLConnection|\.url\(|baseUrl\(|loadUrl\(" jadx/sources/`. If none use cleartext -> short-circuit (state the search).
2. For each, resolve the endpoint and confirm it is cleartext (`http://`/`ws://`/port 80/`usePlaintext`). Quote the call + endpoint. Endpoint unresolved at compile time -> `unverified` (hook to confirm).
3. Attribute each finding to its precise call site (`<ClassFQN>.<method>:<line>`) - the static analogue of the dynamic backtrace.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A cleartext send inside a third-party SDK carrying app data is reported.
5. Conclude per site: Finding (cleartext networking call quoted + attributed); Compliant (https-only / inert); Unverified (endpoint runtime-built).
6. Budget ~2-4 reads per site. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether a send actually occurs (and its exact runtime location) is the hook's job - hence the forced `needs_dynamic_testing`. Networking inside native code or a no-source SDK -> `unverified` (name the entry point). Configuration permission is MASTG-TEST-0235; TLS version is MASTG-TEST-0217.

Output
List **all** cleartext-capable networking call sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group compliant https sites by area, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the networking call and the cleartext endpoint, attributed to the call site, plus owner.
- Compliant: L1 row plus an L2 showing https-only / inert.

```
{
  "id": "ctapi-001",
  "description": "Finding (networking API transmitting cleartext): A worker uploads logs via HttpURLConnection over http:// - cleartext on the wire.",
  "reference": "jadx/sources/com/example/app/sync/LogUploader.java",
  "level": 1
},
{
  "id": "L2-ctapi-call",
  "description": "Cleartext networking call (quoted): URL u = new URL(\"http://logs.example.com/upload\"); HttpURLConnection c = (HttpURLConnection) u.openConnection(); c.getOutputStream().write(payload) at LogUploader.java:60-66 - attributed to com.example.app.sync.LogUploader.upload:60. Owner: proprietary. Hook+backtrace confirms the send at runtime.",
  "reference": "jadx/sources/com/example/app/sync/LogUploader.java:60-66",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0238",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S cleartext-capable networking call sites enumerated, N findings (http/ws/port-80/plaintext endpoints), C compliant (https-only), U unverified (runtime-built endpoint). Any cleartext networking use? <no -> pass/n-a / yes>. <one or two sentences naming each call site; hook+backtrace confirms the send>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that a hook+backtrace is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 networking call site with (a) an L2 row quoting the call AND (b) an L2 row quoting its cleartext endpoint, attributed to the call site. A finding stated with "likely"/"may" instead of the quoted call+endpoint is INVALID -> `unverified`.
- **Call-site attribution.** Each finding names `<ClassFQN>.<method>:<line>` - the static analogue of the dynamic backtrace OWASP wants.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (config blocks the send; endpoint upgrades server-side) - in-APK facts (which endpoint?) resolved by reading, unresolved -> `unverified`.
- `pass`: no networking call site uses cleartext, with L2 coverage.
- `n/a`: no `http://`/cleartext networking use appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its call + cleartext-endpoint L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the networking call is quoted; (2) the cleartext endpoint (http/ws/port-80/plaintext) is quoted; (3) the finding is attributed to a precise call site; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the cleartext-networking search was performed (n/a / pass state it), every call site's endpoint was read and quoted (runtime-built -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
