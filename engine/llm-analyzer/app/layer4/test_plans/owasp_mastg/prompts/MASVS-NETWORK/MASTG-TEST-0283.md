MASTG-TEST-0283

maswe_id       MASWE-0052
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Incorrect Implementation of Server Hostname Verification - permissive HostnameVerifier (static)

What this test looks for
A custom `HostnameVerifier.verify(...)` that does not actually check the server hostname against the certificate - chiefly one that unconditionally returns `true` - turns off hostname validation for the affected connections, enabling a MITM with a valid certificate for a different host. This is a static evaluation of every custom `HostnameVerifier` implementation. Verdict: `pass` (no custom HostnameVerifier, or every custom one verifies correctly), `fail` (>=1 custom `verify(...)` is permissive - always-true, overly-broad matching, or incomplete coverage), `n/a` (the app defines no custom HostnameVerifier - the platform default verifies), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `HostnameVerifier`/`verify(`/`setHostnameVerifier`/`ALLOW_ALL_HOSTNAME_VERIFIER`. If NONE appear -> `n/a` (platform default hostname verification; state the search).

Permissive patterns (any one -> finding)
- **Always true**: `verify(...) { return true; }` (or returns a constant true regardless of hostname/session).
- **`ALLOW_ALL_HOSTNAME_VERIFIER`** / `NullHostnameVerifier` / `org.apache.http.conn.ssl.AllowAllHostnameVerifier` used.
- **Overly broad matching**: permissive wildcard logic that matches unintended domains (e.g. accepts any `*.` or substring match).
- **Incomplete coverage**: verification not applied on all SSL/TLS channels (e.g. set on one client but not the SSLSocket path), or a verifier that ignores its `hostname`/`session` arguments.

Compliant: delegates to `HttpsURLConnection.getDefaultHostnameVerifier()` / `OkHostnameVerifier`, or correctly compares the hostname to the certificate's CN/SAN and returns `false` on mismatch.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the custom `verify(...)` body AND its installation (`setHostnameVerifier(...)`, OkHttp `.hostnameVerifier(...)`, `HttpsURLConnection.setDefaultHostnameVerifier(...)`). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual body, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the permissive `verify(...)` body (and its installation). "probably returns true" is NOT evidence -> `unverified`. A delegating/correct verifier is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the body or installation can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate HostnameVerifiers: `grep -rEn "HostnameVerifier|setHostnameVerifier|hostnameVerifier|setDefaultHostnameVerifier|ALLOW_ALL|AllowAllHostnameVerifier|verify\(" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each custom `verify(...)`, read the FULL body. Match against the permissive patterns (esp. unconditional `return true` and ALLOW_ALL). Quote the body.
3. Confirm it is INSTALLED on a live connection (`setHostnameVerifier`, OkHttp builder, `setDefaultHostnameVerifier`). An unused verifier class is not a live finding (note it). Quote the installation.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per verifier: Finding (permissive body + installation quoted); Compliant (delegates / correct CN-SAN check, quoted); Unverified (body/installation unresolved).
6. Budget ~2-4 reads per verifier (the body, the install site). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Verifier logic inside native code or a no-source SDK -> `unverified` (name the entry point). MISSING hostname verification on raw SSLSocket is MASTG-TEST-0234; unsafe TrustManager is MASTG-TEST-0282. This test is the incorrect IMPLEMENTATION of a present HostnameVerifier.

Output
List **all** custom HostnameVerifiers - one L1 row per verifier with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group compliant delegating verifiers by area, but always break out every Finding and unverified verifier individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the permissive `verify(...)` body and its installation, plus owner.
- Compliant: L1 row plus an L2 quoting the delegate / correct CN-SAN comparison.

```
{
  "id": "hnv-001",
  "description": "Finding (always-true HostnameVerifier): A custom verifier returns true for every hostname and is installed on the HTTPS client, disabling hostname validation (MITM).",
  "reference": "jadx/sources/com/example/app/net/AllowAll.java",
  "level": 1
},
{
  "id": "L2-hnv-body",
  "description": "Permissive body (quoted): public boolean verify(String hostname, SSLSession session) { return true; } at AllowAll.java:14-16 - ignores hostname/session, always accepts.",
  "reference": "jadx/sources/com/example/app/net/AllowAll.java:14-16",
  "level": 2
},
{
  "id": "L2-hnv-install",
  "description": "Installation (quoted): new OkHttpClient.Builder().hostnameVerifier(new AllowAll()).build() at ApiClient.java:42 - governs all API calls. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/net/ApiClient.java:42",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0283",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "H custom HostnameVerifiers, I installed on live connections, N findings (always-true / ALLOW_ALL / overly-broad / incomplete), C compliant (delegate / correct CN-SAN), U unverified. Any custom HostnameVerifier? <no -> n/a / yes>. <one or two sentences naming each permissive verifier>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (MITM is MASTG-TEST-0244); it does not change `pass`/`fail`.
- `fail`: >=1 custom `verify(...)` with (a) an L2 row quoting a permissive body AND (b) an L2 row quoting its installation on a live connection. A finding stated with "likely"/"may" instead of the quoted body is INVALID -> `unverified`.
- **Installation matters.** A permissive verifier class never installed on a live connection is not a live finding - note it, don't fail on it (unless reachable). State the installation.
- **Delegate/correct is Compliant.** Delegating to the default verifier or correctly comparing hostname to CN/SAN (and returning false on mismatch) passes.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (what does verify return? is it installed?) resolved by reading, unresolved -> `unverified`.
- `pass`: no custom HostnameVerifier, or every custom one verifies correctly, with L2 coverage.
- `n/a`: no custom HostnameVerifier appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its body + installation L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the permissive `verify(...)` body is quoted; (2) its installation on a live connection is quoted; (3) it governs app traffic (not dead code); (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the HostnameVerifier search was performed (n/a / pass state it), every custom body AND its installation were read and quoted (unread -> `unverified`), no delegating verifier was miscounted, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
