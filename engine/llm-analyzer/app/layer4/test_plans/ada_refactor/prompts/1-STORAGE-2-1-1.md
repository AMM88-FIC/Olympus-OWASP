MASTG-TEST-XXXX

masvs_v1_id    MSTG-STORAGE-5
masvs_v2_id    MASVS-PLATFORM-2
platform       android
title          Keyboard cache not disabled on text inputs that process sensitive data (1.1.2.1)

What this test looks for
A sensitive text field whose IME caches typed input can leak that secret via the suggestion bar or keyboard storage. A field is compliant only if its **effective** `android:inputType` contains one of: `textNoSuggestions`, `textPassword`, `textVisiblePassword`, `numberPassword`, `textWebPassword`. The test fails if at least one sensitive field lacks all five. "Effective" = the type in force when the user can type: the layout XML value as overridden by any post-inflation `setInputType`/`setRawInputType` on that widget (code wins over XML).

Layout resources and source are ground truth. Any UI/inputType evidence index is a candidate list only — extractors miss programmatic overrides, custom `EditText` subclasses, non-default layout folders, `@string` hint indirection, and Compose. Confirm every finding/clean by reading `resources/res/layout*/`, the relevant `jadx/sources/` code, and `resources/res/values*/strings.xml` for hint references.

What counts as sensitive
In scope: passwords/passphrases, PINs, payment card number/expiry/CVV, bank account/IBAN, government IDs (DNI/NIF/NIE/SSN/passport), security-question answers, recovery seed/mnemonic phrases, user-entered API secrets/tokens, OTP secrets. Out of scope unless context says otherwise: usernames, emails, search boxes, free-text messages, addresses, phone numbers.
Signals (most to least reliable): `android:autofillHints` (`password`, `newPassword`, `creditCardNumber`, `creditCardSecurityCode`); an existing password `inputType`; the `android:id` token (`password|pwd|pin|cvv|card|iban|account|ssn|dni|nif|secret|seed|mnemonic|securityanswer|otp|token`); the `android:hint`/`contentDescription` or adjacent label (resolve `@string`; cover Spanish: `contraseña`, `clave`, `tarjeta`, `cuenta`, `DNI/NIF`, `código de seguridad`).

Procedure
1. Enumerate keyboard-input widgets — `EditText`, `AutoCompleteTextView`, `MultiAutoCompleteTextView`, `TextInputEditText`, and subclasses — from the UI evidence index if present, then confirm with `grep -rEl "EditText|AutoCompleteTextView|TextInputEditText" resources/res/layout*/`. For Compose apps, enumerate `TextField`/`OutlinedTextField`/`BasicTextField` call sites in `jadx/sources/`.
2. Keep only sensitive fields (Step 0). Record the non-sensitive count but no row needed. Empty working set after scanning all layouts + Compose → verdict `n/a`.
3. For each sensitive field, read the layout and record declared `inputType` (none declared → defaults to plain text `TYPE_CLASS_TEXT`, caching enabled).
4. Resolve the effective type: find where the widget is obtained (`findViewById`, view binding, `@BindView`) and `grep -rEn "setInputType|setRawInputType|setTransformationMethod" jadx/sources/`. Code after inflation overrides XML in both directions. Map constants: `TYPE_TEXT_VARIATION_PASSWORD`/`_VISIBLE_PASSWORD`/`TYPE_NUMBER_VARIATION_PASSWORD`/`TYPE_TEXT_VARIATION_WEB_PASSWORD`/`TYPE_TEXT_FLAG_NO_SUGGESTIONS` → the five accepted values. Any one present (even combined with other flags) is compliant.
5. Compose: compliant via `KeyboardOptions(keyboardType = KeyboardType.Password | NumberPassword)`. `PasswordVisualTransformation()` masks display only — not compliant by itself.
6. Classify each field compliant or non-compliant (a finding). Default-plain-text and masking-only cases are findings.

Defenses that do NOT satisfy this test
`setTransformationMethod(PasswordTransformationMethod)`, deprecated `android:password="true"`, Compose `PasswordVisualTransformation()`, `importantForAutofill="no"`, and `imeOptions=flagNoPersonalizedLearning` all mask or reduce risk but do not meet the `inputType` criterion. If a sensitive field relies only on these, it is a finding; name the observed mechanism in the L2 row. (`textVisiblePassword` IS accepted even though it doesn't mask.)

Out-of-scope / dynamic-only
Sensitive HTML `<input>` inside a `WebView`, or a field built by a third-party SDK with no decompiled source → do not FAIL; set `needs_dynamic_testing: true`. Runtime-only/server-driven fields → same. Budget ~2–4 reads per field; if override resolution exceeds budget, mark the field `unverified` naming the deepest unresolved site (`<ClassFQN>.<method>:<line>`).

Output
JSON object as below. evidence_table uses the L1/L2 pattern: one L1 row per sensitive field (or per overall conclusion for `n/a`), with L2 rows citing exact resource/source ranges.
- Finding: L2 for the sensitivity signal AND for the effective inputType (layout line and/or override line, with what it resolves to).
- Compliant field: L2 for the sensitivity signal AND the accepted inputType line.
- `n/a`: L2 for enumeration coverage AND why no field is sensitive.

```
{
  "id": "field-001",
  "description": "Finding: Password field R.id.etPassword (res/layout/activity_login.xml) collects a credential but declares no inputType and is never reconfigured in code, defaulting to TYPE_CLASS_TEXT (caching enabled).",
  "reference": "resources/res/layout/activity_login.xml",
  "level": 1
},
{
  "id": "L2-etPassword-sensitivity",
  "description": "Sensitivity: id 'etPassword', android:autofillHints=\"password\", hint @string/hint_password = 'Contraseña'.",
  "reference": "resources/res/layout/activity_login.xml:31-37",
  "level": 2
},
{
  "id": "L2-etPassword-inputtype",
  "description": "Effective inputType (Non-compliant): no android:inputType in layout; LoginActivity.onCreate uses binding.etPassword and never calls setInputType/setRawInputType, so runtime type is default TYPE_CLASS_TEXT. None of the five accepted values present.",
  "reference": "jadx/sources/com/example/app/LoginActivity.java:44-90",
  "level": 2
},
{
  "id": "scope-na",
  "description": "N/A example: no input field processes sensitive data; all enumerated widgets are search/username/email/message fields.",
  "reference": "resources/res/layout/",
  "level": 1
},
{
  "id": "L2-na-coverage",
  "description": "Coverage: all EditText/TextInputEditText widgets across res/layout*/ and res/xml/ read; no credential/payment/government-id signal in any id, hint (resolved via strings.xml), autofillHints, or label. No Compose TextField call sites in jadx/sources.",
  "reference": "resources/res/layout/",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "F fields enumerated, S sensitive, C compliant, N non-compliant, D dynamic-only, U unverified. <one or two sentences naming the field ids, layouts and classes that drove the verdict>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- `fail`: ≥1 sensitive field with an L2 sensitivity row AND an L2 row showing its effective inputType contains none of the five accepted values.
- `pass`: ≥1 sensitive field exists and every sensitive field has an L2-justified compliant effective inputType; none left unverified.
- `n/a`: L2 rows proving enumeration was performed and no field qualifies as sensitive.
- Display masking is not cache disabling — see "Defenses that do NOT satisfy."
- `unverified` rows name the deepest unresolved call site. WebView/SDK fields are not `unverified`; they set `needs_dynamic_testing`.
- `false_positive_risks` is for factors outside the static artifact only (OEM/third-party IMEs ignoring the flags, runtime config absent from resources/bytecode). In-APK gaps (truncated/unread/unresolved code) go in `unverified` rows.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, or if any `fail` field lacks its two L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.