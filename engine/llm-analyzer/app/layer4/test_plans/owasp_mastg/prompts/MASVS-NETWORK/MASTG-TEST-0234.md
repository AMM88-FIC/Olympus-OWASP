MASTG-TEST-0234

maswe_id       MASWE-0052
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Missing Implementation of Server Hostname Verification with SSLSockets - SSLSocket without HostnameVerifier (static)

What this test looks for
`SSLSocket` does NOT perform hostname verification by default - the app must explicitly verify that the server certificate matches the intended hostname (via a `HostnameVerifier.verify(...)` call against the socket's session). An `SSLSocket` used to send app data WITHOUT an explicit hostname check accepts a valid certificate for ANY hostname, enabling a MITM. Note: this holds even with a fully secure NSC, because `SSLSocket` is not governed by the NSC. This is a static evaluation of every `SSLSocket` usage for a missing hostname verification. Verdict: `pass` (every `SSLSocket` carrying app data performs hostname verification, or the app uses no raw `SSLSocket`), `fail` (>=1 `SSLSocket` sends app data with no hostname verification), `n/a` (the app uses no `SSLSocket` - higher-level clients like OkHttp/HttpsURLConnection verify hostnames automatically), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `SSLSocket`/`SSLSocketFactory`. If NONE appear -> `n/a` (no raw SSLSocket; managed HTTPS clients verify automatically; state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `SSLSocket` creation/use AND either the hostname-verification call (Compliant) or its absence across the socket's data path (Finding). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the socket and any verifier call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting an `SSLSocket` that carries app data and showing no `HostnameVerifier.verify(...)` / `getDefaultHostnameVerifier().verify(...)` is invoked on its session. "probably no hostname check" is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the verification path can't be resolved within budget, the row is `unverified`. `false_positive_risks` is out-of-APK only.

What counts as proper verification (Compliant)
After the handshake, the app calls `HostnameVerifier.verify(hostname, sslSocket.getSession())` (e.g. `HttpsURLConnection.getDefaultHostnameVerifier().verify(...)`) and aborts on `false`, OR it uses `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` on the socket (which makes the TLS stack verify the hostname during the handshake). Either is Compliant. Using a higher-level client (OkHttp, `HttpsURLConnection`) instead of a raw `SSLSocket` is out of scope (those verify automatically).

Procedure
1. Enumerate SSLSocket sites: `grep -rEn "SSLSocket|SSLSocketFactory|createSocket|setEndpointIdentificationAlgorithm|getDefaultHostnameVerifier|HostnameVerifier" jadx/sources/`. If no `SSLSocket` -> short-circuit `n/a` (state the search).
2. For each `SSLSocket` that carries app data, check whether the code (a) calls a `HostnameVerifier.verify(...)` on the socket's session and acts on the result, or (b) sets `setEndpointIdentificationAlgorithm("HTTPS")`. Quote the verification (Compliant) or its absence (Finding).
3. Confirm app data actually flows over the socket (a socket opened but unused is not a finding). Quote the data path.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (SSLSocket + data, no hostname verification); Compliant (verify(...) called / endpoint-identification set); Unverified (verification path unresolved).
6. Budget ~2-4 reads per site (the socket, the handshake/verify, the data write). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
SSLSocket usage inside native code or a no-source SDK -> `unverified` (name the entry point). An incorrectly-IMPLEMENTED `HostnameVerifier` (present but always-true) is MASTG-TEST-0283; a no-op `TrustManager` is MASTG-TEST-0282. This test is about the ABSENCE of hostname verification on raw `SSLSocket`.

Output
List **all** `SSLSocket` sites carrying app data - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group compliant verified sites by area, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the `SSLSocket` + data path and the absence of hostname verification, plus owner.
- Compliant: L1 row plus an L2 quoting the `verify(...)` call or `setEndpointIdentificationAlgorithm("HTTPS")`.

```
{
  "id": "hv-001",
  "description": "Finding (SSLSocket without hostname verification): The app sends API data over a raw SSLSocket and never verifies the certificate hostname, so a valid cert for any host is accepted (MITM).",
  "reference": "jadx/sources/com/example/app/net/SecureChannel.java",
  "level": 1
},
{
  "id": "L2-hv-socket",
  "description": "SSLSocket + data (quoted): SSLSocket s = (SSLSocket) f.createSocket(host, 443); s.startHandshake(); s.getOutputStream().write(request) at SecureChannel.java:40-46 - app request written; no setEndpointIdentificationAlgorithm and no HostnameVerifier.verify on s.getSession() anywhere in the flow. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/net/SecureChannel.java:40-46",
  "level": 2
},
{
  "id": "hv-ok-001",
  "description": "Compliant: SSLSocket sets endpoint identification to HTTPS, so the TLS stack verifies the hostname.",
  "reference": "jadx/sources/com/example/app/net/SafeChannel.java",
  "level": 1
},
{
  "id": "L2-hv-ok",
  "description": "Hostname verification (quoted): SSLParameters p = s.getSSLParameters(); p.setEndpointIdentificationAlgorithm(\"HTTPS\"); s.setSSLParameters(p); at SafeChannel.java:30-33 before the handshake - hostname verified by the stack.",
  "reference": "jadx/sources/com/example/app/net/SafeChannel.java:30-33",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0234",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S SSLSocket sites carrying app data, V with hostname verification (verify(...) or endpoint-identification HTTPS), N without (findings), U unverified. Any raw SSLSocket? <no -> n/a / yes>. <one or two sentences naming each unverified socket>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false; MITM confirmation is MASTG-TEST-0244); it does not change `pass`/`fail`.
- `fail`: >=1 `SSLSocket` with (a) an L2 row quoting the socket + app-data path AND (b) an L2 row showing no hostname verification (no `verify(...)` on the session, no `setEndpointIdentificationAlgorithm("HTTPS")`). A finding stated with "likely"/"may" instead of the quoted absence is INVALID -> `unverified`.
- **Either verification form is Compliant.** A `HostnameVerifier.verify(...)` acted upon, OR endpoint-identification set to HTTPS, clears the socket. Managed clients (OkHttp/HttpsURLConnection) are out of scope (auto-verify).
- **NSC does not save SSLSocket.** Do not pass an unverified SSLSocket because the NSC is secure - SSLSocket is not governed by the NSC.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is verify called? endpoint-id set?) resolved by reading, unresolved -> `unverified`.
- `pass`: every SSLSocket carrying app data verifies the hostname, or no raw SSLSocket is used, with L2 coverage.
- `n/a`: no `SSLSocket` appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its socket + missing-verification L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `SSLSocket` and its app-data path are quoted; (2) the absence of hostname verification (no verify(...), no endpoint-identification HTTPS) is shown across the flow; (3) it is a raw SSLSocket (not a managed client); (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the SSLSocket search was performed (n/a / pass state it), every socket's verification path was read and quoted (unread -> `unverified`), no managed-client usage was miscounted, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
