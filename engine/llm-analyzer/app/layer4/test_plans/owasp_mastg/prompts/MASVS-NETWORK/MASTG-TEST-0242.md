MASTG-TEST-0242

maswe_id       MASWE-0047
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Missing Certificate Pinning in Network Security Configuration - no NSC pin-set (static)

What this test looks for
For L2 assurance, the app should pin server certificates. This test checks specifically whether certificate pinning is implemented via the Network Security Configuration (NSC) `<pin-set>`. It FAILS if no NSC is set, or if any relevant domain lacks a pin-set. NOTE: the app may pin by OTHER means (OkHttp `CertificatePinner`, a custom `TrustManager`, native code) - those are not this test's mechanism, but you must record them so the verdict and `false_positive_risks` reflect that NSC-pinning absence may be compensated elsewhere. Verdict: `pass` (an NSC is set and every relevant domain has a `<pin-set>`), `fail` (no NSC, or a relevant domain has no pin-set), `n/a` (L1-only scope where pinning is not required - state this; otherwise prefer pass/fail), or `inconclusive`.

SHORT-CIRCUIT (decide first): read the manifest for `android:networkSecurityConfig`. If absent -> the NSC-pinning mechanism is absent -> `fail` (state it), while recording any code-level pinning found as context.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the config it rests on.** Quote the manifest `networkSecurityConfig` reference and each `<domain-config>`/`<pin-set>` (with lines). No quoted config -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` and `jadx/resources/res/xml/<nsc>.xml:<line>`, not an index record or line 1. `network_security.json` may orient you; the verdict quotes the raw NSC.
3. **No finding by inference/hedge.** The verdict follows the explicit rule (NSC present? each relevant domain pinned?). "probably not pinned" with no quoted NSC is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the NSC is referenced but unreadable, the row is `unverified`. `false_positive_risks` is out-of-APK only - and code-level pinning elsewhere is the canonical entry here.

What counts as a pin-set
A `<domain-config>` containing `<pin-set>` with one or more `<pin digest="SHA-256">...</pin></pin-set>` covering the domain(s) in its `<domain>` elements. A `<domain-config>` for a relevant domain with NO `<pin-set>` is unpinned (finding). Relevant domains = those the app actually communicates with (API/backend hosts); generic CDN/analytics domains may be out of the L2 pinning expectation - note your scoping.

Procedure
1. Manifest: `grep -nE "networkSecurityConfig" jadx/resources/AndroidManifest.xml`. If absent -> `fail` (NSC pinning mechanism absent); still do step 4. If present, read the NSC file.
2. NSC: enumerate every `<domain-config>` with its `<domain>` list and whether it contains a `<pin-set>` (and how many `<pin>` digests). Quote each.
3. Decide per relevant domain: pinned (has pin-set) -> Compliant; relevant domain without a pin-set, or no NSC at all -> finding. Quote the gap.
4. Record OTHER pinning mechanisms as context: `grep -rEn "CertificatePinner|certificatePinner|checkServerTrusted|X509TrustManager|pinning|sha256/" jadx/sources/`. If the app pins in code/native, the NSC-pinning failure may be compensated - state this in the rationale and as an out-of-APK-independent `false_positive_risks` only if the compensating control is real and quoted (else leave it as context, not a risk).
5. Owner: NSC is app-level config (proprietary).
6. Budget ~2-4 reads (manifest, NSC, code-pinning scan). NSC unreadable -> `unverified` naming the file.

Out-of-scope / static limits
Whether pinning actually blocks a MITM at runtime is MASTG-TEST-0244. Expired pins are MASTG-TEST-0243. Code/native pinning correctness is separate; here the mechanism under test is the NSC `<pin-set>`.

Output
One L1 row for the manifest NSC reference, one L1 row per relevant `<domain-config>` (pinned/unpinned), and one L1 row summarizing any code-level pinning found. Always break out every unpinned relevant domain individually. Never sample.
- Manifest: L1 row quoting `networkSecurityConfig` presence.
- Each relevant domain: L1 row quoting its `<domain-config>` and whether a `<pin-set>` is present.
- Code-pinning context: L1 row summarizing CertificatePinner/TrustManager/native pinning (quoted if claimed as compensating).

```
{
  "id": "pin-nsc",
  "description": "Observation: manifest references an NSC; checking each domain-config for a pin-set.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "pin-001",
  "description": "Finding (relevant domain not pinned in NSC): the api.example.com domain-config has no <pin-set>.",
  "reference": "jadx/resources/res/xml/network_security_config.xml",
  "level": 1
},
{
  "id": "L2-pin-gap",
  "description": "Unpinned domain (quoted): <domain-config><domain includeSubdomains=\"true\">api.example.com</domain><trust-anchors><certificates src=\"system\"/></trust-anchors></domain-config> at network_security_config.xml:6-11 - no <pin-set>. Owner: app (proprietary).",
  "reference": "jadx/resources/res/xml/network_security_config.xml:6-11",
  "level": 2
},
{
  "id": "pin-code-ctx",
  "description": "Context: no OkHttp CertificatePinner or custom TrustManager pinning found in code either (grep clean) - the NSC gap is not compensated.",
  "reference": "jadx/sources/",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0242",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "NSC <set/absent>. D relevant domain-configs, P with a pin-set, M without. Code-level pinning: <CertificatePinner/TrustManager/native found & quoted / none>. NSC pinning present for all relevant domains? <yes -> pass / no -> fail>. <one sentence>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... e.g. real, quoted code/native pinning compensating the NSC gap (out-of-mechanism) ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime pinning is MASTG-TEST-0244); it does not change `pass`/`fail`.
- `fail`: no `networkSecurityConfig` in the manifest, OR >=1 relevant `<domain-config>` without a `<pin-set>`, quoted. A verdict stated without quoting the gap is INVALID -> `unverified`.
- **NSC mechanism specifically.** Pinning via OkHttp `CertificatePinner`, a custom `TrustManager`, or native code is NOT this test's mechanism - but record it; if it genuinely compensates, note it in the rationale and (only if real and quoted) as an out-of-mechanism `false_positive_risks` entry. Do not silently pass on code pinning.
- **Relevant domains.** Scope pinning expectation to the app's real backend/API hosts; state any domain you treat as out of scope and why.
- **false_positive hygiene**: `false_positive_risks` out-of-APK/out-of-mechanism only - the NSC itself is in-APK and must be read; unreadable -> `unverified`.
- `pass`: an NSC is set and every relevant domain has a `<pin-set>` (quoted).
- `n/a`: only when pinning is genuinely not in scope (L1) - state it; otherwise prefer pass/fail.
- `unverified` rows name the unreadable NSC file. Neither pass nor fail.
- `inconclusive` if the cited config doesn't support the verdict, if an unpinned relevant domain was dropped, if any false_positive_risk references in-APK NSC config (vs a real out-of-mechanism control), or if a `fail` lacks its quoted gap.

Self-check before emitting
Confirm: (1) the manifest `networkSecurityConfig` presence is quoted; (2) if an NSC exists, every relevant `<domain-config>` and its pin-set presence are quoted; (3) code-level pinning was searched and its presence/absence recorded; (4) the verdict matches the rule (no NSC or any unpinned relevant domain -> fail).
Before any `pass`/`fail`: confirm the manifest + NSC were read (unreadable NSC -> `unverified`), every relevant domain accounted for (no sampling), and `false_positive_risks` contains only real, quoted out-of-mechanism controls. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
