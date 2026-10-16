MASTG-TEST-0294

maswe_id       MASWE-0055
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          SecureFlagPolicy Not Used to Prevent Screenshots in Compose Dialogs (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0294 as a `status: placeholder` (no procedure body; note: "verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of Jetpack Compose dialogs"). This prompt implements the best-effort static detection: whether Jetpack Compose `Dialog` components that display sensitive content set `DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)` (so the dialog window gets FLAG_SECURE). A Compose `Dialog` hosts its OWN window, so the host activity's FLAG_SECURE does NOT automatically cover it - the dialog must opt in.

What this test looks for
A Compose `Dialog` (or `ModalBottomSheet`/`Popup` with its own window) showing sensitive content - a PIN/OTP entry, secret reveal, payment confirm - should set `securePolicy = SecureFlagPolicy.SecureOn` in its `DialogProperties`. The default is `SecureFlagPolicy.Inherit`, which inherits the parent window's flag; if the parent isn't secure, the dialog is captured. This is a static evaluation. Verdict: `pass` (every sensitive Compose dialog sets SecureOn, or its parent window reliably sets FLAG_SECURE and the policy inherits), `fail` (>=1 sensitive Compose dialog uses Inherit/SecureOff with a non-secure parent), `n/a` (the app uses no Compose dialogs with sensitive content - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `Dialog(`/`DialogProperties`/`SecureFlagPolicy`/`securePolicy`. If NO Compose dialog appears -> `n/a` (state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the Compose `Dialog` (and the sensitive content it shows) AND its `securePolicy`/`DialogProperties` (or the absence/Inherit with a non-secure parent). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` (decompiled Kotlin/Compose) where resolvable, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a sensitive Compose dialog and (b) a non-SecureOn policy (Inherit/SecureOff) with a parent that does not set FLAG_SECURE. "the dialog probably leaks" with no quoted properties is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** Compose decompiles awkwardly; if the dialog's content sensitivity or its `securePolicy` can't be resolved, the row is `unverified` (note Compose decompilation limits). `false_positive_risks` is out-of-APK only.

The policy values
- `SecureFlagPolicy.SecureOn` - the dialog window gets FLAG_SECURE -> Compliant.
- `SecureFlagPolicy.SecureOff` - never secure -> Finding (if sensitive).
- `SecureFlagPolicy.Inherit` (DEFAULT) - inherits the parent window; Compliant ONLY IF the parent activity reliably sets FLAG_SECURE (cross-ref MASTG-TEST-0291); otherwise Finding (if sensitive).

Procedure
1. Enumerate Compose dialogs: `grep -rEn "Dialog\(|DialogProperties|SecureFlagPolicy|securePolicy|ModalBottomSheet|Popup\(" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each dialog, determine what it shows and whether it is sensitive (PIN/OTP/secret/payment). Non-sensitive dialogs -> Compliant (note). Quote the content.
3. For each sensitive dialog, read its `DialogProperties.securePolicy`: SecureOn -> Compliant; SecureOff -> Finding; Inherit/absent -> check the parent activity's FLAG_SECURE (MASTG-TEST-0291). Parent secure -> Compliant; parent not secure -> Finding. Quote the policy + parent state.
4. Owner: app (proprietary).
5. Conclude per dialog: Finding (sensitive + non-SecureOn + non-secure parent, quoted); Compliant (SecureOn / Inherit-with-secure-parent / non-sensitive); Unverified (content/policy/parent unresolved).
6. Budget ~2-4 reads per dialog (the Dialog call, its properties, the parent window flags). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Compose AOT/decompiled code may obscure `securePolicy` -> `unverified` (note the limit; recommend dynamic). General FLAG_SECURE is MASTG-TEST-0291; Recents MASTG-TEST-0292; SurfaceView MASTG-TEST-0293. This test is Compose Dialog `SecureFlagPolicy`.

Output
List **all** Compose dialogs showing app content - one L1 row per dialog with its disposition. Always break out every Finding and unverified dialog individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the sensitive dialog (and content), its non-SecureOn policy, and the non-secure parent, plus owner.
- Compliant: L1 row plus an L2 quoting SecureOn / Inherit-with-secure-parent / non-sensitive content.

```
{
  "id": "cd-001",
  "description": "Finding (sensitive Compose dialog not secured): A PIN-entry Compose dialog uses the default Inherit policy while its host activity does not set FLAG_SECURE, so the dialog is captured in screenshots.",
  "reference": "jadx/sources/com/example/app/ui/PinDialogKt.java",
  "level": 1
},
{
  "id": "L2-cd-content",
  "description": "Sensitive dialog (quoted): Dialog(onDismissRequest=...) hosting the PIN TextField in PinDialog() at PinDialogKt.java:40-58 - collects the user's PIN.",
  "reference": "jadx/sources/com/example/app/ui/PinDialogKt.java:40-58",
  "level": 2
},
{
  "id": "L2-cd-policy",
  "description": "Non-secure policy + non-secure parent (quoted): the Dialog uses default DialogProperties (securePolicy = Inherit; no explicit SecureOn) at PinDialogKt.java:42, and the host MainActivity sets no FLAG_SECURE (MASTG-TEST-0291 grep clean). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/ui/PinDialogKt.java:42",
  "level": 2
},
{
  "id": "cd-ok-001",
  "description": "Compliant: secret-reveal dialog sets SecureOn.",
  "reference": "jadx/sources/com/example/app/ui/RevealDialogKt.java",
  "level": 1
},
{
  "id": "L2-cd-ok",
  "description": "Secure policy (quoted): Dialog(properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)) at RevealDialogKt.java:30 - dialog window gets FLAG_SECURE.",
  "reference": "jadx/sources/com/example/app/ui/RevealDialogKt.java:30",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0294",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "D Compose dialogs, S sensitive, P with SecureOn (or Inherit + secure parent), N findings (sensitive + SecureOff/Inherit-with-nonsecure-parent), U unverified (Compose decompilation limits). Any sensitive Compose dialog unsecured? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (set true where Compose decompilation obscures the policy); it does not change `pass`/`fail`.
- `fail`: >=1 Compose dialog with (a) an L2 quoting the dialog + its sensitive content AND (b) an L2 quoting a non-SecureOn policy (SecureOff, or Inherit/default) together with a non-secure parent. A finding stated with "likely"/"may" instead of the quoted policy is INVALID -> `unverified`.
- **Compose dialogs host their own window.** The host activity's FLAG_SECURE does NOT automatically cover an Inherit dialog unless the parent window actually sets it - verify the parent (MASTG-TEST-0291) before treating Inherit as Compliant.
- **Sensitive content required.** A non-sensitive Compose dialog is Compliant - note it.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (sensitive? securePolicy? parent secure?) resolved by reading, unresolved -> `unverified`.
- `pass`: every sensitive Compose dialog is secured (SecureOn, or Inherit + secure parent), with L2 coverage.
- `n/a`: no Compose dialogs with sensitive content (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or note Compose decompilation limits). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its dialog-content + non-SecureOn-policy + non-secure-parent L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the Compose dialog and its sensitive content are quoted; (2) the policy is SecureOff or Inherit/default AND the parent window is shown non-secure; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the Compose-dialog search was performed (n/a state it), every finding dialog's policy and parent FLAG_SECURE state were read and quoted (unresolved -> `unverified`), no SecureOn/secure-parent/non-sensitive dialog was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
