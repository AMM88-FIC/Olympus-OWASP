MASTG-TEST-0239

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Using Low-level APIs to Set Up a Custom HTTP Connection - raw sockets carrying cleartext HTTP (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0239 as a `status: placeholder` (no procedure body; note flags it could also map to MASWE-0049). This prompt implements the best-effort static detection the title describes: the app building its OWN HTTP (or other application-protocol) connection over a low-level `Socket`/`SocketChannel`/`DatagramSocket` instead of a managed HTTP client - a pattern that bypasses the platform's cleartext protections and TLS handling and easily transmits cleartext.

What this test looks for
The app should use managed, TLS-capable HTTP clients, not hand-rolled connections over raw sockets that send plaintext application data. This is a static evaluation of low-level socket usage that transmits app-protocol data (HTTP requests, credentials, messages) without TLS. Verdict: `pass` (no raw-socket custom connection carrying cleartext app data - sockets are TLS (`SSLSocket`) or absent), `fail` (>=1 raw `Socket`/channel carries cleartext application data, e.g. a manual HTTP request to port 80), `n/a` (the app uses no low-level socket APIs), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the low-level socket APIs below. If NONE appear -> `n/a` (no raw socket usage; managed clients are MASTG-TEST-0233/0238; state the search).

Low-level sinks
`new Socket(host, port)`, `SocketFactory.createSocket(...)` (non-SSL), `java.nio.channels.SocketChannel`, `DatagramSocket`/`DatagramChannel`, raw `InputStream`/`OutputStream` over such a socket writing/reading an application protocol (e.g. `"GET ... HTTP/1.1\r\n"` assembled by hand, credentials/messages written to the stream). TLS sockets (`SSLSocketFactory.createSocket`, `SSLSocket`) are the secure alternative - a raw socket later wrapped in TLS is Compliant; a plaintext socket is the concern.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the socket construction AND the cleartext application data written/read over it (or the port-80/plaintext HTTP assembly). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the socket and the stream write, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the raw socket and (b) cleartext app data over it. "uses sockets, probably cleartext" is NOT evidence -> `unverified`. A socket wrapped in TLS, or carrying only a TLS handshake, is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the data over the socket or its TLS-wrapping can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate low-level socket sites: `grep -rEn "new Socket\(|createSocket|SocketChannel|DatagramSocket|DatagramChannel|getOutputStream|getInputStream" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each, determine: is it an `SSLSocket`/TLS-wrapped socket (Compliant) or a plaintext socket? What data is written/read - an HTTP request assembled by hand, credentials, app messages (cleartext app data -> finding), or only a TLS handshake / benign control bytes? Quote the construction + the data.
3. Note the target port/host where resolvable (port 80 / non-TLS port reinforces a finding; a port-443 socket still plaintext-without-TLS is also a finding). Quote it.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per site: Finding (raw socket + cleartext app data quoted); Compliant (SSLSocket/TLS-wrapped, or no app data); Unverified (data/TLS-wrapping unresolved).
6. Budget ~2-4 reads per site (the socket, the stream writes, any handshake/TLS wrap). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Socket usage inside native code or a no-source SDK -> `unverified` (name the entry point). Managed HTTP clients over `http://` are MASTG-TEST-0233/0238. This test targets HAND-ROLLED low-level connections carrying cleartext.

Output
List **all** low-level socket sites - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group compliant TLS sockets by area, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the raw socket and the cleartext app data (and port where known), plus owner.
- Compliant: L1 row plus an L2 showing TLS wrapping / no app data.

```
{
  "id": "sock-001",
  "description": "Finding (custom cleartext HTTP over raw socket): The app opens a plain Socket to port 80 and writes a handcrafted HTTP request including an auth header in cleartext.",
  "reference": "jadx/sources/com/example/app/net/RawHttp.java",
  "level": 1
},
{
  "id": "L2-sock-open",
  "description": "Raw socket (quoted): Socket s = new Socket(\"api.example.com\", 80); OutputStream os = s.getOutputStream(); at RawHttp.java:30-32 - plaintext socket, port 80, no TLS.",
  "reference": "jadx/sources/com/example/app/net/RawHttp.java:30-32",
  "level": 2
},
{
  "id": "L2-sock-data",
  "description": "Cleartext app data (quoted): os.write((\"GET /me HTTP/1.1\\r\\nAuthorization: Bearer \" + token + \"\\r\\n\\r\\n\").getBytes()) at lines 34-37 - bearer token sent in cleartext over the raw socket. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/net/RawHttp.java:34-37",
  "level": 2
},
{
  "id": "sock-ok-001",
  "description": "Compliant: connection uses an SSLSocket (TLS) rather than a plaintext socket.",
  "reference": "jadx/sources/com/example/app/net/TlsConn.java",
  "level": 1
},
{
  "id": "L2-sock-ok",
  "description": "TLS socket (quoted): SSLSocket s = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443); at TlsConn.java:20 - data carried over TLS.",
  "reference": "jadx/sources/com/example/app/net/TlsConn.java:20",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0239",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S low-level socket sites enumerated, N findings (raw socket carrying cleartext app data), C compliant (SSLSocket/TLS-wrapped or no app data), U unverified. Any raw socket usage? <no -> n/a / yes>. <one or two sentences naming each cleartext socket and the data it carries>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 site with (a) an L2 row quoting a raw (non-TLS) socket AND (b) an L2 row quoting cleartext application data written/read over it. A finding stated with "likely"/"may" instead of the quoted socket+data is INVALID -> `unverified`.
- **TLS-wrapped is Compliant.** An `SSLSocket`, or a raw socket immediately wrapped in TLS before any app data, is Compliant. A socket carrying only a TLS handshake is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is it TLS? what data?) resolved by reading, unresolved -> `unverified`.
- `pass`: no raw socket carries cleartext app data (TLS sockets or none), with L2 coverage.
- `n/a`: no low-level socket APIs appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its socket + cleartext-data L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the raw (non-TLS) socket construction is quoted; (2) the cleartext application data over it is quoted; (3) it is not TLS-wrapped; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the socket search was performed (n/a / pass state it), every socket site's data and TLS-wrapping were read and quoted (unread -> `unverified`), no SSLSocket was miscounted as a Finding, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
