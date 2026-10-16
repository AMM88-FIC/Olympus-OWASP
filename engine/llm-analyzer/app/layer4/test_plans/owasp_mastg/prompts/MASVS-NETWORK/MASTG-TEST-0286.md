MASTG-TEST-0286

maswe_id       MASWE-0052
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Network Security Configuration Allowing Trust in User-Provided CAs - certificates src=user (static)

What this test looks for
Since Android 7.0 (API 24) apps no longer trust user-added CAs by default, but an app can OPT BACK IN by declaring `<certificates src="user"/>` in a `<trust-anchors>` of its Network Security Configuration (NSC). This re-enables trust in user-installed CAs, exposing the app to MITM via a malicious user CA. This test checks the NSC trust-anchors. Verdict: `pass` (no `<certificates src="user"/>` in any trust-anchors - only `system` (and pinned) anchors), `fail` (>=1 `<certificates src="user"/>` appears in base-config or any domain-config trust-anchors), `n/a` (no NSC is set - default trust is system-only on API 24+, which is pass-equivalent; state it), or `inconclusive`.

SHORT-CIRCUIT (decide first): read the manifest for `android:networkSecurityConfig`. If absent -> `n/a`/`pass` (default system-only trust on modern Android; note that MASTG-TEST-0285 covers the pre-24 implicit-trust case; state it).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the config it rests on.** Quote each `<trust-anchors>` and its `<certificates src=...>` entries (with lines). No quoted config -> `unverified`.
2. **Read from the actual NSC file, not the index.** Cite `jadx/resources/res/xml/<nsc>.xml:<line>`, not an index record or line 1. `network_security.json` may orient you; the verdict quotes the raw NSC.
3. **No finding by inference/hedge.** A finding requires quoting `<certificates src="user"/>`. "might trust user CAs" with no quoted element is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the NSC is referenced but unreadable, the row is `unverified`. `false_positive_risks` is out-of-APK only.

What counts (finding vs compliant)
- Finding: `<certificates src="user"/>` inside `<trust-anchors>` of `<base-config>` (affects all domains) or any `<domain-config>` (affects those domains). Break out base-config vs each domain-config.
- Compliant: trust-anchors list only `<certificates src="system"/>` (and/or pinned `<certificates src="@raw/...">` for the app's own CA). The absence of a `user` anchor is the secure state.
- Debug-overrides: `<debug-overrides>` with `src="user"` applies only when `android:debuggable="true"`. Note it; treat as a finding only if the app ships debuggable (cross-ref the manifest `debuggable` flag) - otherwise a documented lower-severity observation.

Procedure
1. Manifest -> NSC: `grep -nE "networkSecurityConfig|debuggable" jadx/resources/AndroidManifest.xml`, then read the NSC file. If no NSC -> short-circuit `n/a`/`pass` (state it).
2. Enumerate every `<trust-anchors>` (base-config, each domain-config, debug-overrides) and its `<certificates src=...>`. Quote each.
3. Flag a finding for each `<certificates src="user"/>` in base-config/domain-config. For a `user` anchor only under `<debug-overrides>`, check `android:debuggable`: debuggable app -> finding; non-debuggable -> documented observation (not a fail by itself). Quote the relevant config + the debuggable flag.
4. Owner: NSC is app-level config (proprietary).
5. Budget ~2-4 reads (manifest, NSC). NSC unreadable -> `unverified` naming the file.

Out-of-scope / static limits
The pre-API-24 implicit user-CA trust (no NSC, old minSdk) is MASTG-TEST-0285 - a separate finding. Cleartext config is MASTG-TEST-0235; pinning is MASTG-TEST-0242. This test is the EXPLICIT `<certificates src="user"/>` opt-in.

Output
One L1 row per `<trust-anchors>` block (base-config, each domain-config, debug-overrides) with its disposition. Always break out every `user`-trusting block individually. Never sample.
- Finding: L1 row plus an L2 quoting the `<certificates src="user"/>` in its trust-anchors (and the debuggable flag if it's a debug-override).
- Compliant: L1 row plus an L2 quoting system-only (and/or pinned) anchors.

```
{
  "id": "uca-001",
  "description": "Finding (NSC trusts user-added CAs): the base-config trust-anchors include <certificates src=\"user\"/>, so user-installed CAs can intercept all of the app's TLS traffic.",
  "reference": "jadx/resources/res/xml/network_security_config.xml",
  "level": 1
},
{
  "id": "L2-uca",
  "description": "User-CA trust (quoted): <base-config><trust-anchors><certificates src=\"system\"/><certificates src=\"user\"/></trust-anchors></base-config> at network_security_config.xml:4-9 - src=\"user\" re-enables user-CA trust app-wide. Owner: app (proprietary).",
  "reference": "jadx/resources/res/xml/network_security_config.xml:4-9",
  "level": 2
},
{
  "id": "uca-ok-001",
  "description": "Compliant: domain-config trust-anchors list system only.",
  "reference": "jadx/resources/res/xml/network_security_config.xml",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0286",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "NSC <set/absent>. T trust-anchors blocks (base-config, domain-configs, debug-overrides), U with <certificates src=\"user\"/>. App debuggable: <yes/no> (affects debug-overrides). Any production user-CA trust? <no -> pass / n-a if no NSC / yes -> fail>. <one sentence>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 `<certificates src="user"/>` in a production `<base-config>`/`<domain-config>` trust-anchors, quoted. A `user` anchor only under `<debug-overrides>` fails only if the app ships `debuggable="true"` (quote the flag); otherwise it is a documented observation. A finding stated without the quoted `src="user"` element is INVALID -> `unverified`.
- **Debug-overrides nuance.** Quote the `android:debuggable` flag when the only `user` anchor is in `<debug-overrides>`; non-debuggable release -> not a fail by itself.
- **Additive to minSdk.** This is independent of MASTG-TEST-0285 (pre-24 implicit trust).
- **false_positive hygiene**: `false_positive_risks` out-of-APK only - the NSC is in-APK and must be read; unreadable -> `unverified`.
- `pass`: no production `<certificates src="user"/>` (system-only / pinned anchors), with quoted config.
- `n/a`: no NSC set (short-circuit; default system-only trust on API 24+; state it, and cross-ref MASTG-TEST-0285 for old minSdk).
- `unverified` rows name the unreadable NSC file. Neither pass nor fail.
- `inconclusive` if the cited config doesn't support the verdict, if a user-trusting block was dropped, if any false_positive_risk references in-APK config, or if a `fail` lacks its quoted `src="user"` element.

Self-check before emitting
Confirm: (1) the manifest `networkSecurityConfig` (and `debuggable` if relevant) were read; (2) every `<trust-anchors>` and its `<certificates src=...>` quoted; (3) each `user` anchor classified (production fail vs debug-override observation) with the debuggable flag quoted where needed.
Before any `pass`/`fail`/`n/a`: confirm the NSC was read (unreadable -> `unverified`), every trust-anchors block accounted for (no sampling), and no `false_positive_risks` entry describes in-APK config. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
