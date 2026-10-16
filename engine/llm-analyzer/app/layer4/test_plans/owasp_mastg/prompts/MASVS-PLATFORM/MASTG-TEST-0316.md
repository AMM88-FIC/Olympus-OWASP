MASTG-TEST-0316

maswe_id       MASWE-0053
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          App Exposing User Authentication Data in Text Input Fields - unmasked password/OTP fields (static)

What this test looks for
Text input fields that collect access codes (passwords, PINs) or verification codes (OTPs) must MASK the input (show dots, not plaintext) to protect against shoulder-surfing. This is a static evaluation of the masking configuration on such fields (XML `android:inputType="textPassword"`/`numberPassword`; Compose `SecureTextField` / `PasswordVisualTransformation`). Verdict: `pass` (all access/verification-code fields are masked), `fail` (>=1 such field is unmasked - plain `TextField`/non-password inputType, or `SecureTextField` with `TextObfuscationMode.Visible`), `n/a` (the app has no access/verification-code input fields - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): locate access/verification-code fields. If none -> `n/a` (state how concluded).

Masked (Compliant) vs unmasked (Finding)
- Masked (Compliant): XML `android:inputType="textPassword"`/`numberPassword`/`textWebPassword`; Compose `SecureTextField` (default `TextObfuscationMode.RevealLastTyped`) or with `Hidden`; classic Compose `TextField(visualTransformation = PasswordVisualTransformation())`.
- Unmasked (Finding for a code field): plain `EditText`/`TextField` with a non-password inputType collecting a password/OTP; `SecureTextField(textObfuscationMode = TextObfuscationMode.Visible)`; a field that programmatically switches to visible and stays visible.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code/layout it rests on.** Quote the field (and that it collects an access/verification code) AND its masking config. No quoted evidence -> `unverified`.
2. **Read from the actual layout/code, not the index.** Cite `jadx/resources/res/layout/<file>.xml:<line>` or `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a code field and (b) its unmasked config. "probably unmasked" with no quoted config is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If a field's purpose (code vs not) or its masking can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate input fields: `grep -rEn "EditText|inputType|TextField|SecureTextField|PasswordVisualTransformation|TextObfuscationMode" jadx/resources/res/layout/ jadx/sources/`.
2. For each field, determine whether it collects an ACCESS code (password/PIN) or VERIFICATION code (OTP) - from id/hint/label/binding. Quote the basis. Other fields -> out of scope.
3. For each code field, read its masking config and classify masked (Compliant) vs unmasked (Finding). Watch for `SecureTextField` set to `Visible`, or a default `TextField` used for a password. Quote it.
4. Owner: app (proprietary).
5. Conclude per code field: Finding (unmasked, quoted); Compliant (masked, quoted); Unverified (purpose/masking unresolved).
6. Budget ~2-3 reads per field. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Custom/game-engine text controls may be missed -> `unverified` (note expected false negatives). A field that toggles visibility via a "show password" button but defaults masked is Compliant (the user opts in) - note it; a field that is visible BY DEFAULT is a finding. Keyboard caching (a different concern) is MASTG-TEST-0258. Native/no-source input -> `unverified`.

Output
List **all** access/verification-code fields - one L1 row per field with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant masked fields, but always break out every Finding and unverified field individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the code field (and its purpose) and its unmasked config, plus owner.
- Compliant: L1 row plus an L2 quoting the masking config.

```
{
  "id": "mask-001",
  "description": "Finding (unmasked OTP field): The OTP entry uses a plain TextField with no obfuscation, so the verification code is shown in cleartext on screen.",
  "reference": "jadx/sources/com/example/app/ui/OtpScreenKt.java",
  "level": 1
},
{
  "id": "L2-mask-field",
  "description": "Code field (quoted): TextField(value = otp, onValueChange = {...}, label = { Text(\"Verification code\") }) at OtpScreenKt.java:44-50 - collects the OTP with a plain TextField (no PasswordVisualTransformation / not SecureTextField).",
  "reference": "jadx/sources/com/example/app/ui/OtpScreenKt.java:44-50",
  "level": 2
},
{
  "id": "mask-ok-001",
  "description": "Compliant: password field masked via textPassword.",
  "reference": "jadx/resources/res/layout/login.xml",
  "level": 1
},
{
  "id": "L2-mask-ok",
  "description": "Masked (quoted): <EditText android:id=\"@+id/password\" android:inputType=\"textPassword\"/> at res/layout/login.xml:24 - characters shown as dots.",
  "reference": "jadx/resources/res/layout/login.xml:24",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0316",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "F access/verification-code fields, M masked, N findings (unmasked / SecureTextField Visible / plain TextField for a code), U unverified. Any code field unmasked by default? <no -> pass / n-a if no code fields / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 code field with (a) an L2 quoting the field + that it collects an access/verification code AND (b) an L2 quoting an unmasked config (plain TextField/non-password inputType, or `SecureTextField` Visible). A finding stated with "likely"/"may" instead of the quoted config is INVALID -> `unverified`.
- **Default-masked is the bar.** A field masked by default with an opt-in "show" toggle is Compliant; a field visible by default is a finding.
- **Code fields only.** Non-code fields are out of scope.
- **Expected false negatives.** Custom controls may be missed - note this; don't over-claim coverage.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is it a code field? masked?) resolved by reading, unresolved -> `unverified`.
- `pass`: all access/verification-code fields are masked by default, with L2 coverage.
- `n/a`: no access/verification-code input fields (state how concluded).
- `unverified` rows name the deepest unresolved point (or custom-control limit). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its code-field + unmasked-config L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the field and that it collects an access/verification code are quoted; (2) its unmasked config is quoted; (3) it is not masked-by-default with an opt-in toggle; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm code fields were identified, every code field's masking config was read and quoted (unread -> `unverified`), no masked/non-code field was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
