MASTG-TEST-0374

maswe_id       MASWE-0066
masvs_v2_id    MASVS-CODE-4
platform       android
title          References to Implicit Intents Carrying Sensitive Extras (static)

What this test looks for
Sensitive data (auth tokens, passwords, session material, PII) placed as EXTRAS on an IMPLICIT intent is exposed: the system resolves the action to any app with a matching intent-filter, so a malicious app can receive the sensitive extras. Sensitive data must travel only via EXPLICIT intents or other secure IPC. This is a static, taint-style evaluation: sensitive value -> extra on an implicit intent. Verdict: `pass` (no sensitive data is placed on implicit intents), `fail` (>=1 implicit intent carries a sensitive extra), `n/a` (the app sends no implicit intents with extras), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `putExtra`/intent dispatch. If no implicit intents carry extras -> `pass`/`n/a` (state it).

Implicit intent (in scope)
An intent dispatched (`startActivity`/`startActivityForResult`/`sendBroadcast`/`startService`) with an action/category but NO explicit component/package (`setClass`/`setClassName`/`setComponent`/`setPackage`). An explicit intent, or one constrained with `setPackage(getPackageName())`, is out of scope (it delivers to a known target).

Sensitive extras (taint sources)
`putExtra(key, value)` where the value is a credential/password/token, session/auth material, API key, PII (name/email/phone/government ID), financial/payment data, health data, precise location, or an OTP. Determined from variable/key names and the source API. Non-sensitive extras (a screen id, a public URL, a flag) are not a finding.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the implicit intent (no component/package) AND the sensitive value placed in an extra. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the intent build, putExtra, and dispatch, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) an implicit intent and (b) a sensitive extra on it. "might leak a token" with no quoted putExtra is NOT evidence -> `unverified`. A non-sensitive extra is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the intent's implicitness or the extra's sensitivity can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate intents with extras: `grep -rEn "new Intent\(|putExtra|setAction|setComponent|setClass|setClassName|setPackage|startActivity|sendBroadcast|startService" jadx/sources/`.
2. For each dispatched intent, classify implicit (action-only, no component/package) vs explicit/setPackage. Focus on implicit ones with extras. Quote it.
3. For each implicit intent carrying extras, determine whether any extra value is sensitive (taint from a sensitive source). Quote the value + the putExtra. Non-sensitive -> Compliant.
4. Classify owner (proprietary vs library; OEM-aware; obfuscated -> proprietary).
5. Conclude per intent: Finding (implicit + sensitive extra, quoted); Compliant (explicit/setPackage, or only non-sensitive extras); Unverified (implicitness/sensitivity unresolved).
6. Budget ~2-4 reads per intent (the build, the putExtra source, the dispatch). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Intent construction inside native code or a no-source SDK -> `unverified` (name the entry point). Implicit intents used for internal communication (regardless of extras) is MASTG-TEST-0372; this test is SENSITIVE EXTRAS on implicit intents specifically.

Output
List **all** implicit intents carrying extras - one L1 row per intent with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant non-sensitive/explicit intents, but always break out every Finding and unverified intent individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the implicit intent and the sensitive extra, plus owner.
- Compliant: L1 row plus an L2 showing explicit/setPackage, or only non-sensitive extras.

```
{
  "id": "sxi-001",
  "description": "Finding (sensitive extra on an implicit intent): The app puts the user's auth token as an extra on an implicit ACTION_SEND intent, exposing it to any app that handles the action.",
  "reference": "jadx/sources/com/example/app/ShareHelper.java",
  "level": 1
},
{
  "id": "L2-sxi-intent",
  "description": "Implicit intent (quoted): Intent i = new Intent(Intent.ACTION_SEND); i.setType(\"text/plain\"); ... startActivity(i); at ShareHelper.java:30-40 - action only, no setComponent/setPackage.",
  "reference": "jadx/sources/com/example/app/ShareHelper.java:30-40",
  "level": 2
},
{
  "id": "L2-sxi-extra",
  "description": "Sensitive extra (quoted): i.putExtra(\"auth_token\", session.getAuthToken()); at ShareHelper.java:35 - auth token placed on the implicit intent; any matching app receives it. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/ShareHelper.java:35",
  "level": 2
},
{
  "id": "sxi-ok-001",
  "description": "Compliant: sensitive payload sent via an explicit intent to a known component.",
  "reference": "jadx/sources/com/example/app/SecureSend.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0374",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "I implicit intents with extras, S carrying sensitive extras, N findings, C compliant (explicit/setPackage or non-sensitive), U unverified. Any sensitive extra on an implicit intent? <no -> pass/n-a / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 intent with (a) an L2 quoting an implicit construction (no component/package) AND (b) an L2 quoting a sensitive extra placed on it. A finding stated with "likely"/"may" instead of the quoted implicit+sensitive-extra is INVALID -> `unverified`.
- **Implicit + sensitive both required.** An explicit intent (or setPackage(self)) carrying sensitive data is Compliant for THIS test; a non-sensitive extra on an implicit intent is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (implicit? sensitive extra?) resolved by reading, unresolved -> `unverified`.
- `pass`: no sensitive data is placed on implicit intents, with L2 coverage.
- `n/a`: the app sends no implicit intents with extras (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its implicit-intent + sensitive-extra L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the implicit intent (no component/package) is quoted; (2) the sensitive extra (value + putExtra) is quoted and its category named; (3) it is not explicit/setPackage; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the intent/putExtra search was performed (n/a state it), every implicit intent's extras and implicitness were read and quoted (unresolved -> `unverified`), no explicit/non-sensitive intent was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
