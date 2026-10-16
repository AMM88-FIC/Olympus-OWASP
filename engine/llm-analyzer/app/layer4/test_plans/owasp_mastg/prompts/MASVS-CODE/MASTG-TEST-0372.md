MASTG-TEST-0372

maswe_id       MASWE-0066
masvs_v2_id    MASVS-CODE-4
platform       android
title          Implicit Intents Used for Internal App Communication (static)

What this test looks for
Using IMPLICIT intents (no explicit target component/package) to communicate between the app's OWN components risks intent hijacking: Android resolves the action against all matching apps, so a malicious app registering the same action can intercept the intent (or the user picks it in a resolver dialog), leaking data or hijacking the flow. Internal communication must use EXPLICIT intents (`setClass`/`setClassName`/`setComponent`, or `new Intent(ctx, Target.class)`) or set an explicit package (`setPackage`). This is a static evaluation. Verdict: `pass` (internal component communication uses explicit intents / setPackage), `fail` (>=1 implicit intent is used to reach an internal component / deliver to self), `n/a` (the app performs no component-to-component intent communication), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for intent dispatch APIs (`startActivity`/`startService`/`sendBroadcast`/`bindService`). If none -> `n/a` (state the search).

Implicit vs explicit
- Implicit (candidate finding for INTERNAL targets): `new Intent("com.example.app.ACTION_X")` / `new Intent(Intent.ACTION_VIEW)` with only an action/category/data and NO `setClass`/`setClassName`/`setComponent`/`setPackage`, dispatched to reach one of the app's OWN components.
- Explicit / safe: `new Intent(ctx, Target.class)`, `setComponent(new ComponentName(...))`, `setClassName(getPackageName(), ...)`, or an implicit intent constrained with `setPackage(getPackageName())` (delivers only within the app).

When implicit is legitimate (NOT a finding)
An implicit intent INTENDED for other apps / the system (open a URL in a browser, `ACTION_SEND` share sheet, `ACTION_VIEW` a map, dial, pick a contact) is correct use - not a finding. The finding is implicit dispatch meant for the app's OWN internal handling.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the intent construction (showing no explicit component/package) AND evidence it targets an internal component (a same-app receiver/service/activity registered for that action). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the intent build + dispatch, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) an implicit intent and (b) that it is meant for an internal component. "might be internal" with no quoted target evidence is NOT a finding -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the intent's target (internal vs external) can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate intent dispatch: `grep -rEn "new Intent\(|setAction|startActivity|startService|sendBroadcast|bindService|setComponent|setClass|setClassName|setPackage" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each dispatched intent, classify explicit (component/class set, or setPackage(self)) vs implicit (action-only). Quote it.
3. For each implicit intent, determine the INTENT of the target: internal (a same-app component declares an `<intent-filter>` for that action, or the code clearly expects self-handling) -> finding; external/system (browser/share/view) -> Compliant. Cross-ref the manifest intent-filters. Quote the target evidence.
4. Classify owner (proprietary vs library; OEM-aware; obfuscated -> proprietary).
5. Conclude per intent: Finding (implicit + internal target, quoted); Compliant (explicit/setPackage, or legitimately external); Unverified (target unresolved).
6. Budget ~2-4 reads per intent (the build, the dispatch, the manifest filter for the action). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Intent dispatch inside native code or a no-source SDK -> `unverified` (name the entry point). Sensitive data in implicit-intent EXTRAS is MASTG-TEST-0374; unintended export is MASTG-TEST-0373. This test is implicit intents used for INTERNAL communication.

Output
List **all** implicit intents reaching internal components - one L1 row per intent with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant explicit/external intents, but always break out every Finding and unverified intent individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the implicit intent and the internal-target evidence (same-app intent-filter), plus owner.
- Compliant: L1 row plus an L2 showing explicit component/setPackage, or a legitimate external target.

```
{
  "id": "impi-001",
  "description": "Finding (implicit intent for internal communication): The app broadcasts a custom action implicitly to trigger its own receiver, so any app registering that action can intercept it.",
  "reference": "jadx/sources/com/example/app/SyncTrigger.java",
  "level": 1
},
{
  "id": "L2-impi-intent",
  "description": "Implicit intent (quoted): Intent i = new Intent(\"com.example.app.SYNC_NOW\"); sendBroadcast(i); at SyncTrigger.java:30-32 - action only, no setComponent/setPackage.",
  "reference": "jadx/sources/com/example/app/SyncTrigger.java:30-32",
  "level": 2
},
{
  "id": "L2-impi-target",
  "description": "Internal target (quoted): the app's own SyncReceiver declares <intent-filter><action android:name=\"com.example.app.SYNC_NOW\"/></intent-filter> at AndroidManifest.xml:82-85 - the broadcast is meant for internal handling but is deliverable to any app registering the action. Owner: com.example.app (proprietary).",
  "reference": "jadx/resources/AndroidManifest.xml:82-85",
  "level": 2
},
{
  "id": "impi-ok-001",
  "description": "Compliant: internal navigation uses an explicit intent.",
  "reference": "jadx/sources/com/example/app/Nav.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0372",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "I implicit intents, T targeting internal components, N findings (implicit + internal), C compliant (explicit/setPackage or external), U unverified. Any implicit intent for internal communication? <no -> pass/n-a / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 intent with (a) an L2 quoting an implicit construction (no component/package) AND (b) an L2 quoting internal-target evidence (same-app intent-filter / clear self-handling). A finding stated with "likely"/"may" instead of the quoted implicit+internal evidence is INVALID -> `unverified`.
- **Internal target required.** A legitimately external implicit intent (browser/share/view/dial) is Compliant. The finding is implicit dispatch meant for the app's own component.
- **setPackage(self) clears it.** An implicit action constrained with `setPackage(getPackageName())` delivers only within the app - Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (implicit? internal target?) resolved by reading, unresolved -> `unverified`.
- `pass`: internal communication uses explicit intents / setPackage, with L2 coverage.
- `n/a`: no component-to-component intent communication (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its implicit-intent + internal-target L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the implicit intent (no component/package) is quoted; (2) internal-target evidence (same-app intent-filter / self-handling) is quoted; (3) it is not a legitimate external/system intent; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the intent-dispatch search was performed (n/a state it), every implicit intent's target was read and quoted (unresolved -> `unverified`), no external/explicit/setPackage intent was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
