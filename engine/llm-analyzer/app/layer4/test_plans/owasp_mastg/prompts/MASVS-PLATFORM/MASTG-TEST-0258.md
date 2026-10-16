MASTG-TEST-0258

maswe_id       MASWE-0053
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          References to Keyboard Caching Attributes in UI Elements - sensitive fields cached by the keyboard (static)

What this test looks for
Text input fields that handle sensitive data (passwords, PINs, OTPs, PII) must use NON-CACHING input types so the soft keyboard does not store the typed content in its personalization/learning dictionary (which could later surface as autocomplete suggestions). This is a static evaluation of input-type configuration on sensitive fields (XML `android:inputType`, programmatic `setInputType`, Compose `KeyboardOptions`). Verdict: `pass` (all sensitive fields use non-caching input types), `fail` (>=1 sensitive field uses a caching/visible input type), `n/a` (the app has no text input fields handling sensitive data - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): locate text input fields. If none handle sensitive data -> `n/a` (state how concluded).

Non-caching (Compliant) vs caching (Finding) input types
- Non-caching (Compliant): `textPassword`, `textVisiblePassword`, `numberPassword`, `textWebPassword` (XML); `InputType.TYPE_TEXT_VARIATION_PASSWORD`/`TYPE_NUMBER_VARIATION_PASSWORD`/`TYPE_TEXT_VARIATION_VISIBLE_PASSWORD` programmatically; flags including `TYPE_TEXT_FLAG_NO_SUGGESTIONS` (0x80000) or `textNoSuggestions`; Compose `KeyboardOptions(keyboardType = KeyboardType.Password/NumberPassword)` and/or `autoCorrect = false`.
- Caching (Finding for a sensitive field): plain `text`, `textEmailAddress`, `textPersonName`, `number` without the password/no-suggestions variation, or Compose `KeyboardType.Text` with autoCorrect enabled - the keyboard may learn/cache the value.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code/layout it rests on.** Quote the field (and what sensitive data it collects) AND its input type. No quoted evidence -> `unverified`.
2. **Read from the actual layout/code, not the index.** Cite `jadx/resources/res/layout/<file>.xml:<line>` or `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a sensitive field and (b) its caching input type. "probably caches" with no quoted inputType is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If a field's sensitivity or input type can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate input fields: layouts (`grep -rEn "EditText|inputType|TextField|SecureTextField|autoCorrect" jadx/resources/res/layout/ jadx/sources/`) and programmatic (`grep -rEn "setInputType|InputType\.|KeyboardOptions|KeyboardType" jadx/sources/`). 
2. For each field, determine whether it collects sensitive data (label/hint/id: password, pin, otp, ssn, card; or bound to a sensitive model). Quote the basis. Non-sensitive fields -> out of scope.
3. For each sensitive field, read its input type and classify non-caching (Compliant) vs caching (Finding). Quote the inputType/KeyboardOptions.
4. Owner: app (proprietary).
5. Conclude per sensitive field: Finding (caching input type, quoted); Compliant (non-caching, quoted); Unverified (sensitivity/inputType unresolved).
6. Budget ~2-3 reads per field (the layout/field, the binding, any programmatic setInputType). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Custom/game-engine input controls not based on standard classes may be missed -> `unverified` (note the expected false negatives). Visible-masking of codes is MASTG-TEST-0316 (a related but distinct concern). Native/no-source input -> `unverified`.

Output
List **all** sensitive input fields - one L1 row per field with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant non-caching fields, but always break out every Finding and unverified field individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the sensitive field (and data) and its caching input type, plus owner.
- Compliant: L1 row plus an L2 quoting the non-caching input type.

```
{
  "id": "kc-001",
  "description": "Finding (sensitive field with caching input type): The recovery-phrase field uses plain text input, so the keyboard may cache the seed words in its learning dictionary.",
  "reference": "jadx/resources/res/layout/recovery.xml",
  "level": 1
},
{
  "id": "L2-kc-field",
  "description": "Sensitive field (quoted): <EditText android:id=\"@+id/seedPhrase\" android:hint=\"Recovery phrase\" android:inputType=\"text\"/> at res/layout/recovery.xml:18-22 - collects the wallet seed phrase with inputType=\"text\" (caching, suggestions on).",
  "reference": "jadx/resources/res/layout/recovery.xml:18-22",
  "level": 2
},
{
  "id": "kc-ok-001",
  "description": "Compliant: password field uses textPassword.",
  "reference": "jadx/resources/res/layout/login.xml",
  "level": 1
},
{
  "id": "L2-kc-ok",
  "description": "Non-caching (quoted): <EditText android:id=\"@+id/password\" android:inputType=\"textPassword\"/> at res/layout/login.xml:24 - password type, not cached.",
  "reference": "jadx/resources/res/layout/login.xml:24",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0258",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "F sensitive input fields, C non-caching, N findings (caching input type), U unverified. Any sensitive field with a caching keyboard type? <no -> pass / n-a if no sensitive fields / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive field with (a) an L2 quoting the field + the sensitive data it collects AND (b) an L2 quoting a caching input type (plain text/number/email/personName, or Compose Text + autoCorrect, without a password/no-suggestions variation). A finding stated with "likely"/"may" instead of the quoted inputType is INVALID -> `unverified`.
- **Non-caching types are Compliant.** `*Password` variations and `textNoSuggestions`/`TYPE_TEXT_FLAG_NO_SUGGESTIONS` prevent caching. Quote the type.
- **Sensitive fields only.** Non-sensitive fields need no special type - do not flag.
- **Expected false negatives.** Custom/non-standard input controls may be missed - note this in the rationale; do not over-claim coverage.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the field sensitive? what input type?) resolved by reading, unresolved -> `unverified`.
- `pass`: all sensitive fields use non-caching input types, with L2 coverage.
- `n/a`: no text input fields handle sensitive data (state how concluded).
- `unverified` rows name the deepest unresolved point (or custom-control limit). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its field + caching-input-type L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the field and the sensitive data it collects are quoted; (2) its caching input type is quoted; (3) it is not a password/no-suggestions type; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm input fields were enumerated (layouts + programmatic + Compose), every sensitive field's input type was read and quoted (unread -> `unverified`), no non-sensitive/non-caching field was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
