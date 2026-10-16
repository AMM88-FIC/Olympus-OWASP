MASTG-TEST-0243

maswe_id       MASWE-0047
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Expired Certificate Pins in the Network Security Configuration - past pin expiration (static)

What this test looks for
When the app pins certificates via the Network Security Configuration (NSC) `<pin-set expiration="YYYY-MM-DD">`, an expiration date in the PAST silently disables pinning for that set - the app falls back to its configured trust anchors (system/user CAs), so pinning is no longer enforced even though the developer believes it is. This test checks every NSC `<pin-set>` expiration. Verdict: `pass` (no `<pin-set>` has an expiration in the past - none set, or all in the future), `fail` (>=1 `<pin-set expiration=...>` is in the past), `n/a` (no NSC pin-set exists - pinning-presence is MASTG-TEST-0242, not this test), or `inconclusive`.

SHORT-CIRCUIT (decide first): read the NSC. If there is no `<pin-set>` at all -> `n/a` (no pins to expire; MASTG-TEST-0242 covers missing pinning; state it).

Reference date: evaluate "in the past" against the analysis date. State the reference date you use (e.g. today's date) in the rationale, since "expired" is relative to when the assessment runs.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the config it rests on.** Quote each `<pin-set expiration="...">` with its domain(s) and line. No quoted config -> `unverified`.
2. **Read from the actual NSC file, not the index.** Cite `jadx/resources/res/xml/<nsc>.xml:<line>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting an expiration date and showing it is before the reference date. "the pin might be expired" with no quoted date is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the NSC is referenced but unreadable, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest -> NSC: `grep -nE "networkSecurityConfig" jadx/resources/AndroidManifest.xml`, then read the NSC file. If no NSC or no `<pin-set>` -> short-circuit `n/a` (state it).
2. Enumerate every `<pin-set>`: note its `expiration` attribute (or absence) and the `<domain>`(s) it covers. Quote each.
3. For each `<pin-set>` with an `expiration`, compare to the reference date. Past -> finding (quote the date + domains); future or no expiration -> Compliant. (No `expiration` means the pins never expire - Compliant for THIS test.)
4. Owner: NSC is app-level config (proprietary).
5. Budget ~2-3 reads (manifest, NSC). NSC unreadable -> `unverified` naming the file.

Out-of-scope / static limits
Whether pinning exists at all is MASTG-TEST-0242; runtime enforcement is MASTG-TEST-0244. This test only judges the EXPIRATION of NSC pin-sets. Code-level pinning libraries (OkHttp CertificatePinner) have their own expiry semantics and are out of this NSC-focused test (note them if present).

Output
One L1 row per `<pin-set>` with its expiration disposition. Always break out every expired pin-set individually. Never sample.
- Finding: L1 row plus an L2 quoting the `<pin-set expiration=...>` (past date) and its domains.
- Compliant: L1 row plus an L2 quoting a future/absent expiration.

```
{
  "id": "exp-001",
  "description": "Finding (expired NSC pin-set): the pin-set for api.example.com expired in 2023, so pinning is no longer enforced and the app falls back to CA trust.",
  "reference": "jadx/resources/res/xml/network_security_config.xml",
  "level": 1
},
{
  "id": "L2-exp-pin",
  "description": "Expired pin-set (quoted): <domain-config><domain>api.example.com</domain><pin-set expiration=\"2023-01-01\"><pin digest=\"SHA-256\">AAAA...=</pin></pin-set></domain-config> at network_security_config.xml:6-12 - expiration 2023-01-01 is before the reference date (analysis date). Owner: app (proprietary).",
  "reference": "jadx/resources/res/xml/network_security_config.xml:6-12",
  "level": 2
},
{
  "id": "exp-ok-001",
  "description": "Compliant: pin-set for cdn.example.com has a future expiration.",
  "reference": "jadx/resources/res/xml/network_security_config.xml",
  "level": 1
},
{
  "id": "L2-exp-ok",
  "description": "Future expiration (quoted): <pin-set expiration=\"2027-12-31\"> at network_security_config.xml:16 - not expired.",
  "reference": "jadx/resources/res/xml/network_security_config.xml:16",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0243",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Reference date: <date>. P pin-sets in the NSC, E with an expiration attribute, X expired (past), F future/absent. Any pin-set expired? <no -> pass / n-a if no pin-set / yes -> fail>. <one sentence naming each expired pin-set and its date>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 `<pin-set expiration=...>` quoted with a date before the reference date. State the reference date. A finding stated without the quoted past date is INVALID -> `unverified`.
- **No expiration = not expired.** A `<pin-set>` with no `expiration` attribute never expires - Compliant for this test.
- **Reference date stated.** Because "expired" is relative, the rationale must state the date used.
- **false_positive hygiene**: `false_positive_risks` out-of-APK only - the NSC dates are in-APK and must be read; unreadable -> `unverified`.
- `pass`: no pin-set has a past expiration (all future or no expiration), quoted.
- `n/a`: no `<pin-set>` exists (short-circuit; MASTG-TEST-0242 covers missing pinning; state it).
- `unverified` rows name the unreadable NSC file. Neither pass nor fail.
- `inconclusive` if the cited dates don't support the verdict, if an expired pin-set was dropped, if any false_positive_risk references in-APK config, or if a `fail` lacks its quoted past-date pin-set.

Self-check before emitting
Confirm: (1) the NSC was read and every `<pin-set>` expiration quoted; (2) the reference date is stated; (3) each finding shows expiration < reference date; (4) pin-sets without expiration treated as Compliant.
Before any `pass`/`fail`/`n/a`: confirm the NSC was read (unreadable -> `unverified`), every pin-set accounted for (no sampling), and no `false_positive_risks` entry describes in-APK config. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
