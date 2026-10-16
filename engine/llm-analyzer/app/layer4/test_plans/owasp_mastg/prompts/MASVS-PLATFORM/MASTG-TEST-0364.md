MASTG-TEST-0364

maswe_id       MASWE-0119
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          Exported And Unprotected Activities That Expose Sensitive Functionality (static)

What this test looks for
An exported activity that performs or exposes sensitive functionality without an appropriate `android:permission` can be started by any third-party app via an `Intent`, reaching that functionality outside the app's intended flow (e.g. bypassing a login screen, displaying sensitive data, performing a security-relevant action). This is a static evaluation of the manifest + each exported activity's code. Verdict: `pass` (no exported activity exposes sensitive functionality without adequate protection), `fail` (>=1 exported, inadequately-protected activity exposes sensitive functionality), `n/a` (the app declares no exported activities beyond a standard launcher with no sensitive functionality - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate exported activities from the manifest. An activity is EXPORTED if `android:exported="true"`, or (legacy) it has an `<intent-filter>` and no explicit `android:exported`. If the only exported activity is the LAUNCHER (`MAIN`/`LAUNCHER`) and it exposes no sensitive functionality -> lean `pass`/`n/a` (state it).

What "adequately protected" means
The activity declares an `android:permission` with a protection level effective for the trust boundary - `signature` (only same-signature apps) or a custom permission not broadly grantable. A `normal`/`dangerous` protection level is broadly grantable and does NOT adequately restrict untrusted apps. No permission at all on an exported activity exposing sensitive functionality -> finding.

Sensitive functionality (what makes exposure a finding)
Displaying/returning sensitive data (account details, messages, stored secrets), performing a security-relevant action (changing settings/credentials, initiating a transaction), or allowing a caller to bypass an authentication step (login/PIN) the app relies on elsewhere.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the `<activity>` manifest entry (export + permission) AND the code in the activity that exposes sensitive functionality. No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` and `jadx/sources/...:<line-range>` of the activity body, not an index record or line 1. `components.json`/`manifest_findings.json` may orient you; the verdict quotes the manifest + code.
3. **No finding by inference/hedge.** A finding requires quoting (a) the exported+unprotected manifest entry and (b) the sensitive functionality in the activity. "probably exposes data" with no quoted code is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If export/permission can't be resolved or the activity body is unreadable, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest: enumerate `<activity>`/`<activity-alias>` elements and their `android:exported`, `<intent-filter>`, and `android:permission` (`grep -nE "<activity|exported|permission|intent-filter|category android:name=\"android.intent.category.LAUNCHER\"" jadx/resources/AndroidManifest.xml`). Determine which are exported. Quote each.
2. For each exported activity, check `android:permission` and (if a custom permission) its `<permission android:protectionLevel=...>` definition. Classify protection: adequate (`signature`/restricted custom) vs inadequate (`normal`/`dangerous`/none). Quote it.
3. For each exported, inadequately-protected activity, read its code (`onCreate`/handlers) to determine whether it exposes sensitive functionality (sensitive data, security-relevant action, auth bypass). Quote the code. No sensitive functionality -> Compliant (note: exported but benign).
4. Owner: app-declared components are the app's (proprietary). A library activity exported by the app is reported.
5. Conclude per activity: Finding (exported + inadequate permission + sensitive functionality, quoted); Compliant (not exported, adequately protected, or benign); Unverified (export/permission/body unresolved).
6. Budget ~2-4 reads per activity (the manifest entry, the permission def, the activity body). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Activity logic inside native code or a no-source SDK -> `unverified` (name the entry point). Services are MASTG-TEST-0365; receivers MASTG-TEST-0366; providers MASTG-TEST-0355/0357. This test is exported ACTIVITIES.

Output
List **all** exported activities - one L1 row per activity with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group benign exported activities, but always break out every Finding and unverified activity individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the exported+unprotected manifest entry and the sensitive functionality in the code, plus owner.
- Compliant: L1 row plus an L2 showing not-exported / adequate permission / benign.

```
{
  "id": "act-001",
  "description": "Finding (exported activity bypasses authentication): An exported, unprotected activity opens the account-details screen directly, skipping the login the app enforces elsewhere.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-act-manifest",
  "description": "Exported + unprotected (quoted): <activity android:name=\".AccountActivity\" android:exported=\"true\"/> at AndroidManifest.xml:55 - exported, no android:permission.",
  "reference": "jadx/resources/AndroidManifest.xml:55",
  "level": 2
},
{
  "id": "L2-act-code",
  "description": "Sensitive functionality (quoted): AccountActivity.onCreate loads and displays the user's account profile and balance without any auth check (no session/PIN gate) at AccountActivity.java:30-48 - a third-party app can start it via Intent and reach account data, bypassing login. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/AccountActivity.java:30-48",
  "level": 2
},
{
  "id": "act-ok-001",
  "description": "Compliant: exported deep-link activity is protected by a signature permission.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0364",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "A activities, E exported, P adequately protected (signature/restricted), N findings (exported + inadequate/none + sensitive functionality), C compliant (benign/protected), U unverified. Any exported activity exposing sensitive functionality without protection? <no -> pass/n-a / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 activity with (a) an L2 quoting an exported manifest entry with no/inadequate (`normal`/`dangerous`) permission AND (b) an L2 quoting sensitive functionality (sensitive data, security action, or auth bypass) in its code. A finding stated with "likely"/"may" instead of the quoted manifest+code is INVALID -> `unverified`.
- **Export determination.** `android:exported="true"`, or an `<intent-filter>` with no explicit `exported` (legacy default exported). On `targetSdk >= 31`, a component with an intent-filter MUST declare `exported` - absence is a build error, so rely on the explicit value when present.
- **Protection adequacy.** `signature` or a restricted custom permission is adequate; `normal`/`dangerous`/none is not. Quote the `protectionLevel`.
- **Sensitive functionality required.** An exported, unprotected activity that exposes nothing sensitive (e.g. a public share-target) is Compliant - note it.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (exported? protected? sensitive?) resolved by reading, unresolved -> `unverified`.
- `pass`: no exported activity exposes sensitive functionality without adequate protection, with L2 coverage.
- `n/a`: no exported activities beyond a benign launcher (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK evidence, if a finding was dropped without evidence, or if any `fail` lacks its manifest + sensitive-functionality L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the exported+unprotected manifest entry is quoted; (2) the sensitive functionality in the activity code is quoted; (3) the permission (if any) is inadequate (normal/dangerous/none, protectionLevel quoted); (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the manifest was read and exported activities enumerated, every finding's activity body was read and quoted (unread -> `unverified`), no benign exported activity was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
