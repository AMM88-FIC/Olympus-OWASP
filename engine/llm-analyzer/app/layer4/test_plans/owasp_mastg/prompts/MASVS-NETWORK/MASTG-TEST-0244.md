MASTG-TEST-0244

maswe_id       MASWE-0047
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Missing Certificate Pinning in Network Traffic - pinning enforced at runtime (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0244 is a dynamic test (run a MITM against the app; if HTTPS can be intercepted, pinning is absent or broken). This static engine cannot perform a MITM, so this prompt performs the best-effort static equivalent - enumerate every pinning mechanism the app COULD be using (NSC `<pin-set>`, OkHttp `CertificatePinner`, custom `TrustManager`/`X509TrustManager` pinning, third-party pinning libs, native pinning) and judge whether relevant backend domains are covered. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only a MITM proves enforcement - obfuscation, dynamic loading, and native pinning can hide or fake the static picture either way.

What this test looks for
At runtime a MITM with an untrusted CA must fail for the app's relevant backend domains, i.e. pinning must be enforced. Statically, the proxy is the presence of a credible pinning mechanism covering those domains. Verdict: `pass` (a credible pinning mechanism - NSC pin-set, OkHttp CertificatePinner, or a correct custom TrustManager - covers the relevant domains), `fail` (no pinning mechanism is present for the relevant domains), `n/a` (pinning not in scope - L1; state it), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for all pinning mechanisms (below). If NONE appear AND the NSC has no pin-set -> static evidence of no pinning -> lean `fail` (still forced-dynamic). If a mechanism appears, assess coverage.

Pinning mechanisms (any one, covering the relevant domains, is credible)
- **NSC**: `<pin-set>` in a `<domain-config>` (see MASTG-TEST-0242).
- **OkHttp**: `new CertificatePinner.Builder().add("host", "sha256/...")` wired into the client.
- **Custom TrustManager**: an `X509TrustManager.checkServerTrusted` that validates against a pinned cert/public key (NOT a no-op - a no-op trust manager is the OPPOSITE; see MASTG-TEST-0282).
- **Third-party**: TrustKit, `okhttp-tls`, Volley pinning, Conscrypt pinning.
- **Native**: pinning in a `.so` (often only inferable; flag as unverified/dynamic).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the pinning mechanism (NSC pin-set / CertificatePinner / TrustManager) and the domain(s) it covers, OR show (via searches) that no mechanism covers a relevant domain. No quoted evidence -> `unverified`.
2. **Read from the code/config, not the index.** Cite the source/NSC line, not an index record or line 1.
3. **No finding by inference/hedge.** A `fail` requires showing the searches turned up no pinning for the relevant domains; a `pass` requires quoting the covering mechanism. "probably pinned in native" is NOT static evidence -> `unverified` (flag for MITM).
4. **Unresolved determinacy is `unverified`, not a hedge.** Obfuscated/native pinning that can't be confirmed -> `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate mechanisms: `grep -rEn "CertificatePinner|sha256/|checkServerTrusted|X509TrustManager|TrustKit|pinning|setSSLSocketFactory|network_security_config" jadx/sources/ jadx/resources/`; read the NSC for `<pin-set>`. State all searches.
2. Identify the relevant backend domains (the API/auth hosts the app talks to; cross-ref hardcoded URLs). For each, check whether a mechanism covers it. Quote coverage or the gap.
3. Decide: a credible mechanism covering the relevant domains -> Compliant (`pass`); no mechanism for a relevant domain -> finding (`fail`); a custom TrustManager that is a no-op is NOT pinning (it disables validation - cross-ref MASTG-TEST-0282) -> still unpinned (finding here) plus a separate trust issue there.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude: pass (covered, quoted) / fail (uncovered, searches shown) / unverified (native/obfuscated). Forced dynamic regardless.
6. Budget ~3-5 reads (NSC, CertificatePinner wiring, TrustManager body, domain cross-ref). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Runtime enforcement (the actual MITM result) is the dynamic test - hence the forced `needs_dynamic_testing`. NSC-pin presence is MASTG-TEST-0242; expired pins MASTG-TEST-0243; unsafe TrustManager MASTG-TEST-0282. This test asks: is ANY credible pinning present for the relevant domains?

Output
List **all** relevant backend domains - one L1 row per domain (pinned/unpinned) - plus one L1 row per pinning mechanism found. Always break out every unpinned relevant domain individually. Never sample.
- Mechanism: L1 row quoting each pinning mechanism and its covered domains.
- Each relevant domain: L1 row stating pinned-by-<mechanism> or unpinned.

```
{
  "id": "pinrt-001",
  "description": "Finding (no pinning for a relevant domain): the auth backend auth.example.com is not covered by any pinning mechanism - a MITM would likely succeed.",
  "reference": "jadx/sources/com/example/app/net/",
  "level": 1
},
{
  "id": "L2-pinrt-search",
  "description": "No covering mechanism (quoted searches): NSC has no <pin-set> for auth.example.com (network_security_config.xml read, only system trust-anchors); grep for CertificatePinner / checkServerTrusted / TrustKit returns no host match for auth.example.com. Owner: app (proprietary). MITM confirmation required.",
  "reference": "jadx/resources/res/xml/network_security_config.xml",
  "level": 2
},
{
  "id": "pinrt-ok-001",
  "description": "Compliant: api.example.com pinned via OkHttp CertificatePinner.",
  "reference": "jadx/sources/com/example/app/net/HttpClient.java",
  "level": 1
},
{
  "id": "L2-pinrt-ok",
  "description": "Pinning mechanism (quoted): new CertificatePinner.Builder().add(\"api.example.com\", \"sha256/AAAA...=\").build() wired via .certificatePinner(...) at HttpClient.java:40-44 - covers api.example.com.",
  "reference": "jadx/sources/com/example/app/net/HttpClient.java:40-44",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0244",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "D relevant backend domains, mechanisms found: <NSC pin-set / CertificatePinner / TrustManager / native / none>. P domains pinned, M unpinned, U unverified (native/obfuscated). All relevant domains pinned? <yes -> pass / no -> fail>. <one or two sentences>; MITM confirms enforcement.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... e.g. native/obfuscated pinning not statically visible ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that a MITM is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 relevant backend domain with no covering pinning mechanism, shown via quoted searches across NSC + code. A `fail` stated without showing the searches is INVALID -> `unverified`.
- **Any credible mechanism counts.** NSC pin-set, OkHttp CertificatePinner, a correct custom TrustManager, or a known pinning lib covering the domain all pass. A no-op TrustManager does NOT count (it removes validation - MASTG-TEST-0282).
- **Relevant domains.** Scope to the app's real backend/API/auth hosts; state any domain treated as out of scope and why.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every unpinned relevant domain broken out individually; undecidable owner -> proprietary; `false_positive_risks` out-of-APK only (native/obfuscated pinning not statically visible) - statically-resolvable facts read, unresolved -> `unverified`.
- `pass`: every relevant backend domain is covered by a credible pinning mechanism, quoted.
- `n/a`: only when pinning is genuinely not in scope (L1) - state it.
- `unverified` rows name the native/obfuscated entry point. Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if an unpinned relevant domain was dropped, if any false_positive_risk references statically-resolvable in-APK evidence, or if a `fail` lacks its quoted no-coverage searches.

Self-check before emitting
For every domain confirm: (1) covering mechanism quoted (pass) OR no-coverage searches quoted (fail); (2) a no-op TrustManager was NOT counted as pinning; (3) owner decided from evidence.
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the NSC + code pinning searches were performed and shown, every relevant domain accounted for (no sampling), and `false_positive_risks` contains only non-static (native/obfuscated) factors. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
