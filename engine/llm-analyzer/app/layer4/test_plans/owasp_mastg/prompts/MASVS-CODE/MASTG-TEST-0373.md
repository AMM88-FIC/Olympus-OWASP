MASTG-TEST-0373

maswe_id       MASWE-0066
masvs_v2_id    MASVS-CODE-4
platform       android
title          Internal Component Unintentionally Exported (static)

What this test looks for
Activities (and other components) intended for INTERNAL use must not be exported. An exported component can be launched by any app, potentially exposing internal functionality. Some components must be exported (launcher, deep-link handler, components that legitimately receive external intents); INTERNAL ones should set `android:exported="false"`. On older Android a component with an `<intent-filter>` is exported by DEFAULT; on `targetSdk >= 31` `exported` must be set explicitly. This is a static evaluation of the manifest. Verdict: `pass` (every exported component has a legitimate external purpose; internal ones are not exported), `fail` (>=1 internal-only component is exported), `n/a` (the app declares only a launcher with nothing else exported - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate exported components from the manifest (`android:exported="true"`, or an `<intent-filter>` with no explicit `exported`). If only the launcher is exported and is benign -> `pass`/`n/a` (state it).

This test vs the PLATFORM export tests
MASTG-TEST-0364/0365/0366 (MASVS-PLATFORM) ask whether an exported component exposes SENSITIVE functionality WITHOUT a permission. THIS test (CODE) is the broader code-quality question: is the component exported when it was only ever meant for internal use (regardless of whether the exposed functionality is sensitive)? An unintentionally-exported internal component is a finding here even if its functionality isn't obviously sensitive (reduced attack surface / least privilege). Cross-reference 0364-0366 for the sensitive-functionality severity.

Legitimate-to-export (NOT a finding)
Launcher activity (`MAIN`/`LAUNCHER`), deep-link/`VIEW` handlers meant for external links, share/`SEND` targets, components designed as a public API with adequate protection, system-triggered receivers for protected broadcasts. An exported component with a clear external contract is fine.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the config it rests on.** Quote the `<activity>`/component manifest entry (export + intent-filters) AND the basis for internal-only intent (no external contract; only internal callers). No quoted config -> `unverified`.
2. **Read from the actual manifest/code, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` (and the component class), not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the exported manifest entry and (b) that the component is internal-only (no launcher/deep-link/share/public-API role). "probably internal" with no quoted basis is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If export status or the component's role can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest: enumerate `<activity>`/`<activity-alias>`/`<service>`/`<receiver>`/`<provider>` and `android:exported`, `<intent-filter>` actions/categories, and `android:permission` (`grep -nE "<activity|<service|<receiver|<provider|exported|intent-filter|action android:name|category android:name" jadx/resources/AndroidManifest.xml`). Determine which are exported. Quote each.
2. For each exported component, determine its INTENDED role: launcher / deep-link / share / public-API (legitimate external) vs internal-only (a screen reached only from within the app; an internal helper service/receiver). Read the component and its callers where needed. Quote the basis.
3. Flag internal-only components that are exported (especially exported WITHOUT a guarding permission). A protected exported component with an external contract is Compliant. Note `exported="true"` set without an intent-filter (explicit, deliberate export) vs default-exported legacy.
4. Owner: app-declared (proprietary).
5. Conclude per component: Finding (internal-only but exported, quoted); Compliant (legitimate external role / not exported); Unverified (export/role unresolved).
6. Budget ~2-4 reads per component (the manifest entry, the component class/callers). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Component logic inside native code or a no-source SDK -> `unverified` (name the entry point). The sensitive-functionality + permission severity is MASTG-TEST-0364/0365/0366. This test is the unintended EXPORT of internal components.

Output
List **all** exported components - one L1 row per component with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group legitimately-exported components, but always break out every Finding and unverified component individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the exported manifest entry and the internal-only basis, plus owner.
- Compliant: L1 row plus an L2 showing a legitimate external role, or not-exported.

```
{
  "id": "exp-001",
  "description": "Finding (internal component unintentionally exported): An internal settings activity reached only from the app's own menu is exported, needlessly enlarging the attack surface.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-exp-manifest",
  "description": "Exported internal component (quoted): <activity android:name=\".InternalSettingsActivity\" android:exported=\"true\"/> at AndroidManifest.xml:66 - no intent-filter, no launcher/deep-link role, exported=true.",
  "reference": "jadx/resources/AndroidManifest.xml:66",
  "level": 2
},
{
  "id": "L2-exp-basis",
  "description": "Internal-only basis (quoted): InternalSettingsActivity is started only via explicit intents from within the app (SettingsMenu.java:40 new Intent(this, InternalSettingsActivity.class)); it has no external contract, so exported=true is unintended. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/SettingsMenu.java:40",
  "level": 2
},
{
  "id": "exp-ok-001",
  "description": "Compliant: the launcher activity is legitimately exported.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0373",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "C components, E exported, L legitimate external (launcher/deep-link/share/public-API), N findings (internal-only but exported), U unverified. Any internal component unintentionally exported? <no -> pass/n-a / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 component with (a) an L2 quoting an exported manifest entry AND (b) an L2 quoting that the component is internal-only (no launcher/deep-link/share/public-API role). A finding stated with "likely"/"may" instead of the quoted manifest+basis is INVALID -> `unverified`.
- **Internal-only is the test.** Legitimate external roles (launcher, deep-link, share, protected public API) are Compliant. The finding is an internal component exported without need.
- **Export determination.** `android:exported="true"`, or an `<intent-filter>` with no explicit `exported` (legacy default exported). On targetSdk>=31 absence is a build error - rely on the explicit value.
- **Code-quality scope.** This fails on unnecessary export regardless of whether the functionality is obviously sensitive (least privilege). Sensitive-functionality severity is 0364-0366 - cross-reference, don't merge.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (exported? internal?) resolved by reading, unresolved -> `unverified`.
- `pass`: every exported component has a legitimate external role; internal ones are not exported, with L2 coverage.
- `n/a`: only a benign launcher is exported (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK config, if a finding was dropped without evidence, or if any `fail` lacks its manifest + internal-only-basis L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the exported manifest entry is quoted; (2) the internal-only basis (no external contract; internal callers) is quoted; (3) it is not a launcher/deep-link/share/public-API component; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the manifest was read and exported components enumerated, every finding component's role was read and quoted (unresolved -> `unverified`), no legitimately-external component was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
