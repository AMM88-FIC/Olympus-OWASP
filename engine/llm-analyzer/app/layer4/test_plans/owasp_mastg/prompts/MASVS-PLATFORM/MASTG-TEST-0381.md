MASTG-TEST-0381

maswe_id       MASWE-0066
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          References to Insecure PendingIntent Creation - mutable / implicit PendingIntent (static)

What this test looks for
A `PendingIntent` executes a wrapped `Intent` later with the app's identity and permissions, so it must be created securely. Two issues: (1) MUTABILITY - a mutable PendingIntent lets the receiving app fill in unfilled fields of the base intent (action/data/component/extras), enabling redirection or injection; use `FLAG_IMMUTABLE`. (2) IMPLICIT base intent - a PendingIntent wrapping an implicit intent (no explicit target component) can be intercepted/redirected; the base intent should set `setClass()`/`setClassName()`/`setComponent()`. This is a static evaluation of every PendingIntent creation. Verdict: `pass` (PendingIntents are immutable where appropriate and wrap explicit intents), `fail` (>=1 PendingIntent is created mutable without justification, or without FLAG_IMMUTABLE on `minSdk < 31`, or wraps an implicit base intent), `n/a` (the app creates no PendingIntents), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `PendingIntent.getActivity`/`getActivities`/`getService`/`getForegroundService`/`getBroadcast`. If NONE appear -> `n/a` (no PendingIntents; state the search).

Failure conditions (per OWASP)
- A PendingIntent created WITHOUT `FLAG_IMMUTABLE` when `minSdkVersion < 31` (pre-Android-12 default is MUTABLE), unless a justified mutability need with other precautions.
- A PendingIntent created WITH `FLAG_MUTABLE` without a valid use case (valid cases: inline reply actions, Bubbles, certain notification actions that the system fills in).
- The base intent is IMPLICIT - no `setClass()`/`setClassName()`/`setComponent()` and only an action/category - allowing hijacking. (An implicit intent in a mutable PendingIntent is the most dangerous combination.)

Note on minSdk: on `minSdk >= 31` the platform requires an explicit `FLAG_MUTABLE`/`FLAG_IMMUTABLE`, so a missing flag won't compile; the mutability finding there is `FLAG_MUTABLE` without justification. On `minSdk < 31` a missing immutability flag defaults to mutable -> finding. State the `minSdkVersion`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `PendingIntent.get*(...)` call with its flags AND the base intent construction (explicit vs implicit). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the creation call and the intent build, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the flags (mutable / missing immutable) and/or (b) the implicit base intent. "probably mutable" with no quoted flags is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the flags or the base intent's explicitness can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Resolve `minSdkVersion` (manifest `<uses-sdk>` or `app_metadata.json`) - it changes the mutability rule. State it.
2. Enumerate PendingIntent creations: `grep -rEn "PendingIntent\.(getActivity|getActivities|getService|getForegroundService|getBroadcast)" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
3. For each, read the flags argument: decode `FLAG_IMMUTABLE (0x4000000)` / `FLAG_MUTABLE (0x2000000)` presence. Determine mutability per minSdk. Quote it.
4. For each, read the base intent: explicit (`setClass`/`setClassName`/`setComponent`/`new Intent(ctx, X.class)`) or implicit (action/category only). Quote it.
5. Decide: mutable-without-justification (or missing immutable on minSdk<31), and/or implicit base intent -> finding. Immutable + explicit -> Compliant. Mutable WITH a valid documented use case (inline reply) -> note, lower severity. Quote the basis.
6. Owner: app-declared (proprietary); a library creating PendingIntents on app data is reported.
7. Budget ~2-3 reads per PendingIntent (the get* call, the flags constant, the intent build). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
PendingIntent creation inside native code or a no-source SDK -> `unverified` (name the entry point). This test is PendingIntent CREATION flags + base-intent explicitness.

Output
List **all** PendingIntent creations - one L1 row per creation with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant immutable+explicit creations, but always break out every Finding and unverified creation individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the flags (mutable/missing-immutable) and/or the implicit base intent, plus minSdk and owner.
- Compliant: L1 row plus an L2 showing FLAG_IMMUTABLE + explicit base intent (or a justified mutable case).

```
{
  "id": "pi-001",
  "description": "Finding (mutable PendingIntent wrapping an implicit intent): A broadcast PendingIntent is created mutable with an implicit base intent, allowing a malicious app to fill in the component and redirect execution under the app's identity.",
  "reference": "jadx/sources/com/example/app/notify/Notifier.java",
  "level": 1
},
{
  "id": "L2-pi-flags",
  "description": "Mutable flag (quoted): PendingIntent.getBroadcast(ctx, 0, intent, PendingIntent.FLAG_MUTABLE) at Notifier.java:44 - FLAG_MUTABLE, no inline-reply use case; minSdkVersion=26 (so even default would be mutable).",
  "reference": "jadx/sources/com/example/app/notify/Notifier.java:44",
  "level": 2
},
{
  "id": "L2-pi-intent",
  "description": "Implicit base intent (quoted): Intent intent = new Intent(\"com.example.app.ACTION_SYNC\"); // no setClass/setComponent at Notifier.java:40-42 - implicit; combined with FLAG_MUTABLE a malicious app can set the target component. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/notify/Notifier.java:40-42",
  "level": 2
},
{
  "id": "pi-ok-001",
  "description": "Compliant: immutable PendingIntent wrapping an explicit intent.",
  "reference": "jadx/sources/com/example/app/notify/Alarm.java",
  "level": 1
},
{
  "id": "L2-pi-ok",
  "description": "Safe creation (quoted): PendingIntent.getActivity(ctx, 0, new Intent(ctx, MainActivity.class), PendingIntent.FLAG_IMMUTABLE) at Alarm.java:30 - immutable + explicit component.",
  "reference": "jadx/sources/com/example/app/notify/Alarm.java:30",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0381",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "minSdkVersion=<N>. P PendingIntent creations, M mutable-without-justification (or missing-immutable on minSdk<31), I implicit base intents, N findings, C compliant (immutable+explicit), U unverified. Any insecure PendingIntent? <no -> pass/n-a / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 PendingIntent with (a) an L2 quoting mutable flags without justification (or missing FLAG_IMMUTABLE on minSdk<31) AND/OR (b) an L2 quoting an implicit base intent. State the minSdk. A finding stated with "likely"/"may" instead of the quoted flags/intent is INVALID -> `unverified`.
- **minSdk gates the mutability rule.** minSdk<31: a missing immutability flag defaults to mutable -> finding. minSdk>=31: the flag is mandatory; the finding is `FLAG_MUTABLE` without a valid use case. Quote minSdk.
- **Justified mutability is Compliant/noted.** Inline-reply notification actions legitimately need FLAG_MUTABLE - note it, do not fail solely on that. But a mutable + IMPLICIT intent is a finding regardless.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (flags? explicit?) resolved by reading, unresolved -> `unverified`.
- `pass`: PendingIntents are immutable where appropriate and wrap explicit intents, with L2 coverage.
- `n/a`: no PendingIntent creations appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its flags/base-intent L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `PendingIntent.get*` call and its flags are quoted; (2) the base intent's explicit/implicit nature is quoted; (3) the minSdk is stated and the mutability rule applied correctly; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the PendingIntent search was performed (n/a state it), minSdk resolved, every creation's flags and base intent were read and quoted (unread -> `unverified`), no justified-mutable/immutable+explicit creation was miscounted, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
