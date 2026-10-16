MASTG-TEST-0329

maswe_id       MASWE-0044
masvs_v2_id    MASVS-AUTH-2
platform       android
title          References to APIs Enforcing Authentication without Explicit User Action - setConfirmationRequired(false) (static)

What this test looks for
For sensitive operations (e.g. payments, sensitive-data access), biometric authentication should require an EXPLICIT confirmation step so the user deliberately authorizes the action - otherwise a passive biometric match (e.g. a face scan the user didn't intend as authorization) can trigger the operation. `BiometricPrompt.Builder.setConfirmationRequired(true)` is the secure default; setting it to `false` removes the explicit-confirmation requirement. This is a static evaluation of every BiometricPrompt guarding a sensitive operation. Verdict: `pass` (sensitive operations require confirmation - default or `true`), `fail` (>=1 sensitive operation is gated by a prompt with `setConfirmationRequired(false)`), `n/a` (the app uses no biometric authentication), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `BiometricPrompt`/`setConfirmationRequired`. If NONE appear -> `n/a` (no biometric auth; state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote `setConfirmationRequired(false)` AND the sensitive operation the prompt guards. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual builder call and the guarded operation, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) `setConfirmationRequired(false)` and (b) the sensitive operation it guards. "probably no confirmation" with no quoted call is NOT evidence -> `unverified`. The default (no call) is `true` -> Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the boolean argument or the guarded operation's sensitivity can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Sensitive operations (requiring explicit confirmation)
Payment / transaction authorization, transfers, sensitive-data access or export, changing security settings, approving a high-value action. Low-risk operations (e.g. a convenience unlock of a non-sensitive screen) may legitimately use `setConfirmationRequired(false)` - those are NOT findings (note them).

Procedure
1. Enumerate BiometricPrompt configs: `grep -rEn "BiometricPrompt|setConfirmationRequired|PromptInfo" jadx/sources/`. If no biometric auth -> short-circuit `n/a` (state the search).
2. For each prompt, read the `setConfirmationRequired` argument: `false` (candidate), `true`/absent/default (Compliant). Quote it.
3. For each `false`, trace the operation the prompt authorizes and whether it is a sensitive operation requiring explicit confirmation. Quote the operation. Low-risk -> Compliant (note).
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per prompt: Finding (`setConfirmationRequired(false)` guarding a sensitive op, quoted); Compliant (default/`true`, or low-risk op); Unverified (argument/op sensitivity unresolved).
6. Budget ~2-4 reads per prompt (the builder, the authenticate, the authorized operation). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Biometric config inside native code or a no-source SDK -> `unverified` (name the entry point). DEVICE_CREDENTIAL fallback is MASTG-TEST-0326; CryptoObject binding is MASTG-TEST-0327; enrollment invalidation is MASTG-TEST-0328; key validity duration is MASTG-TEST-0330. This test is the confirmation requirement.

Output
List **all** BiometricPrompt configurations guarding app operations - one L1 row per prompt with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant confirmation-required prompts by area, but always break out every Finding and unverified prompt individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting `setConfirmationRequired(false)` and the sensitive operation guarded, plus owner.
- Compliant: L1 row plus an L2 showing default/`true`, or a low-risk operation.
- Group: L1 summary plus an L2 naming references and the shared confirmation-required pattern.

```
{
  "id": "cf-001",
  "description": "Finding (no explicit confirmation on a sensitive operation): The payment-authorization prompt sets setConfirmationRequired(false), so a passive biometric match can authorize a payment without a deliberate confirm.",
  "reference": "jadx/sources/com/example/app/pay/PayPrompt.java",
  "level": 1
},
{
  "id": "L2-cf-config",
  "description": "No confirmation (quoted): new BiometricPrompt.PromptInfo.Builder().setTitle(\"Confirm payment\").setConfirmationRequired(false)... at PayPrompt.java:33-37 - explicit confirmation disabled.",
  "reference": "jadx/sources/com/example/app/pay/PayPrompt.java:33-37",
  "level": 2
},
{
  "id": "L2-cf-op",
  "description": "Sensitive operation guarded (quoted): on success -> paymentService.authorize(amount, payee) at lines 50-54 - authorizes a payment. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/pay/PayPrompt.java:50-54",
  "level": 2
},
{
  "id": "cf-ok-001",
  "description": "Compliant: sensitive-data prompt relies on the default (confirmation required).",
  "reference": "jadx/sources/com/example/app/auth/DataPrompt.java",
  "level": 1
},
{
  "id": "L2-cf-ok",
  "description": "Confirmation required (quoted): the PromptInfo.Builder does not call setConfirmationRequired(false) (default true) at DataPrompt.java:20-24.",
  "reference": "jadx/sources/com/example/app/auth/DataPrompt.java:20-24",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0329",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "B BiometricPrompt configs enumerated, S guarding sensitive operations, N findings (setConfirmationRequired(false) on a sensitive op), C compliant (default/true or low-risk), U unverified. Any biometric auth present? <no -> n/a / yes>. <one or two sentences naming each no-confirmation prompt and the operation it guards>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive operation with (a) an L2 quoting `setConfirmationRequired(false)` AND (b) an L2 quoting the sensitive operation it guards. A finding stated with "likely"/"may" instead of the quoted call is INVALID -> `unverified`.
- **Default is safe.** Absence of the call means `true` (confirmation required) -> Compliant. Only an explicit `false` is the concern.
- **Sensitive operation required.** `setConfirmationRequired(false)` is not inherently a vuln (per OWASP) - it is a finding only when it guards a sensitive operation. Low-risk prompts are Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is confirmation false? is the op sensitive?) resolved by reading, unresolved -> `unverified`.
- `pass`: every prompt guarding a sensitive operation requires confirmation (default/`true`), with L2 coverage.
- `n/a`: no biometric authentication appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its config + sensitive-operation L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) `setConfirmationRequired(false)` is quoted; (2) the sensitive operation it guards is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the BiometricPrompt search was performed (n/a / pass state it), every no-confirmation prompt's guarded operation was read and quoted (unread -> `unverified`), no low-risk prompt was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
