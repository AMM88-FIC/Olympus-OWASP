MASTG-TEST-0235

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Android App Configurations Allowing Cleartext Traffic - manifest & NSC permit HTTP (static)

What this test looks for
The app's configuration must not permit cleartext (unencrypted HTTP) traffic. Since Android 9 (API 28) cleartext is blocked by default, but the app can re-enable it via the manifest `android:usesCleartextTraffic="true"` or via the Network Security Configuration (NSC) `cleartextTrafficPermitted="true"` on `<base-config>` or `<domain-config>`. This is a static evaluation of the manifest + NSC. Verdict: `pass` (cleartext is not permitted by configuration), `fail` (configuration permits cleartext per the rules below), `n/a` (not applicable - see note; in practice this control resolves to pass/fail), or `inconclusive`.

The configuration FAILS if ANY of the following is true (per OWASP):
1. The manifest sets `android:usesCleartextTraffic="true"` AND there is NO `android:networkSecurityConfig` (no NSC). (If an NSC is present - even an empty `<network-security-config/>` - the manifest flag is ignored, so this clause does not fire.)
2. The NSC sets `cleartextTrafficPermitted="true"` on the `<base-config>`.
3. The NSC sets `cleartextTrafficPermitted="true"` on ANY `<domain-config>`.

PASS otherwise: cleartext flag absent/false with no permissive NSC; or an NSC that does not permit cleartext (including the default, an empty NSC overriding a `true` manifest flag, or explicit `cleartextTrafficPermitted="false"`).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the config it rests on.** Quote the manifest attribute (with line) and each relevant NSC element/attribute (with line). No quoted config -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` and `jadx/resources/res/xml/<nsc>.xml:<line>` (the NSC file named by `android:networkSecurityConfig`), not an index record or line 1. The evidence file `network_security.json` may orient you, but the verdict quotes the raw config.
3. **No finding by inference/hedge.** The verdict follows the three explicit clauses; quote whichever fires. "probably allows cleartext" with no quoted attribute is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the NSC file is referenced but cannot be read/resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest: obtain `jadx/resources/AndroidManifest.xml`. Read `android:usesCleartextTraffic` on `<application>` (`grep -nE "usesCleartextTraffic|networkSecurityConfig" jadx/resources/AndroidManifest.xml`) and whether `android:networkSecurityConfig` is set. Quote both (with lines).
2. NSC: if `android:networkSecurityConfig="@xml/<name>"` is set, read the file (typically `jadx/resources/res/xml/<name>.xml`). Enumerate `<base-config cleartextTrafficPermitted=...>` and every `<domain-config cleartextTrafficPermitted=...>` (with the domains). Quote each.
3. Apply the three FAIL clauses in order. The first clause that fires -> `fail` (quote it). If none fire -> `pass` (quote the governing config: default, empty NSC, or explicit false).
4. Note multi-config nuance: a permissive `<domain-config>` fails even if `<base-config>` is strict (clause 3). An empty NSC neutralizes a `true` manifest flag (clause 1 does not fire) -> typically `pass` unless a domain-config permits cleartext.
5. Owner: this is app-level configuration (the app's manifest/NSC) - attribute to the app (proprietary). A library cannot set the app manifest's cleartext policy.
6. Budget ~2-4 reads (manifest, the NSC file, any referenced sub-config). NSC referenced but unreadable -> `unverified` naming the missing file.

Out-of-scope / static limits
Whether cleartext is actually SENT is MASTG-TEST-0233 (code use) and MASTG-TEST-0236/0238 (runtime). Cross-platform framework HTTP libraries that bypass the platform NSC are MASTG-TEST-0237. This test judges the manifest + NSC CONFIGURATION only.

Output
One L1 row for the manifest cleartext config, one L1 row for the NSC base-config, and one L1 row per relevant `<domain-config>` - each with its disposition. Always break out every permissive (failing) config individually. Never sample.
- Manifest: L1 row quoting `usesCleartextTraffic` and whether `networkSecurityConfig` is set (with lines).
- NSC base-config: L1 row quoting `<base-config cleartextTrafficPermitted=...>` (or noting default/absent).
- Each domain-config: L1 row quoting `cleartextTrafficPermitted` and the domains.
- Finding: the clause that fires, quoted at L2.

```
{
  "id": "ct-manifest",
  "description": "Observation: AndroidManifest sets usesCleartextTraffic and references an NSC.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-ct-manifest",
  "description": "Manifest (quoted): <application android:usesCleartextTraffic=\"true\" android:networkSecurityConfig=\"@xml/network_security_config\" ...> at AndroidManifest.xml:42 - flag is true but an NSC is present, so the flag is ignored (clause 1 does not fire); the NSC governs.",
  "reference": "jadx/resources/AndroidManifest.xml:42",
  "level": 2
},
{
  "id": "ct-domain-001",
  "description": "Finding (NSC domain-config permits cleartext - clause 3): a <domain-config> enables cleartext for api.example.com.",
  "reference": "jadx/resources/res/xml/network_security_config.xml",
  "level": 1
},
{
  "id": "L2-ct-domain",
  "description": "NSC (quoted): <domain-config cleartextTrafficPermitted=\"true\"><domain includeSubdomains=\"true\">api.example.com</domain></domain-config> at network_security_config.xml:8-11 - clause 3 fires. Owner: app (proprietary).",
  "reference": "jadx/resources/res/xml/network_security_config.xml:8-11",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0235",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Manifest usesCleartextTraffic=<val>, networkSecurityConfig <set/absent>. NSC base-config cleartextTrafficPermitted=<val/none>, D domain-configs (P permitting cleartext). Failing clause: <1 manifest-true-no-NSC / 2 base-config-true / 3 domain-config-true / none -> pass>. <one sentence>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false; runtime cleartext is MASTG-TEST-0236); it does not change `pass`/`fail`.
- `fail`: any of the three clauses fires, quoted: (1) manifest `usesCleartextTraffic="true"` AND no NSC; (2) NSC `<base-config cleartextTrafficPermitted="true">`; (3) any NSC `<domain-config cleartextTrafficPermitted="true">`. A verdict stated without quoting the firing clause is INVALID -> `unverified`.
- **NSC overrides the manifest flag.** If an NSC is present (even empty), clause 1 does NOT fire - the manifest `usesCleartextTraffic` is ignored. Do not fail on the manifest flag alone when an NSC exists.
- **Per-domain granularity.** A permissive `<domain-config>` fails (clause 3) even with a strict base-config. Break out each permissive domain.
- **false_positive hygiene**: `false_positive_risks` out-of-APK only - the configuration is fully in-APK and must be read; unreadable referenced NSC -> `unverified`, not a guess.
- `pass`: no clause fires (cleartext not permitted - default, empty NSC over a true flag, or explicit false), with quoted config.
- `unverified` rows name the missing/unreadable config file. Neither pass nor fail.
- `inconclusive` if the cited config doesn't support the verdict, if a permissive domain-config was dropped, if any false_positive_risk references in-APK config, or if a `fail` lacks its quoted firing clause.

Self-check before emitting
Confirm: (1) the manifest `usesCleartextTraffic` and `networkSecurityConfig` presence are quoted with lines; (2) if an NSC is referenced, it was read and its base-config + every domain-config quoted; (3) the firing FAIL clause (or the pass-justifying config) is quoted; (4) NSC-overrides-manifest logic applied correctly (no clause-1 fail when an NSC exists).
Before any `pass`/`fail`: confirm the manifest was read, the referenced NSC was read (unreadable -> `unverified`), every domain-config accounted for (no sampling), and no `false_positive_risks` entry describes in-APK config. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
