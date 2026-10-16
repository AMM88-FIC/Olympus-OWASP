MASTG-TEST-XXXX

masvs_v1_id    MSTG-STORAGE-7
masvs_v2_id    MASVS-STORAGE-2
platform       android
title          Sensitive data is masked by default in the UI (and suppressed in notifications) (static)

What this test looks for
Sensitive data shown in the UI must be masked by default and revealed only by explicit user action; sensitive data must also be suppressed in notifications. Concretely: password/PIN/card/government-ID fields use a masking `inputType` (`textPassword`/`textVisiblePassword`/`numberPassword`/`textWebPassword`) - rendering dots/asterisks by default; any reveal is gated behind an explicit control (e.g. a show-password toggle); and notifications do not place sensitive values in visible text. This is a static, inventory-style evaluation over sensitive UI fields and notification builders. Verdict: `pass` (all sensitive fields masked by default + notification-suppressed; reveal only on explicit action), `fail` (some sensitive datum shown unmasked by default), `n/a` (the app shows no sensitive data in the UI), or `inconclusive`.

RELATIONSHIP TO THE KEYBOARD-CACHE TEST (do not confuse the two): that test accepts `textNoSuggestions` to disable the cache. THIS test does NOT - `textNoSuggestions` disables suggestions but shows the text in clear, so it does NOT satisfy masking. Only the four password-class inputTypes (`textPassword`, `textVisiblePassword`, `numberPassword`, `textWebPassword`) mask the displayed value. (Note: `textVisiblePassword` does disable the cache but is borderline for masking - some IMEs render it in clear; treat it as masking per the inputType family but flag it as weak if it is the sole protection on a high-sensitivity field.)

EVIDENCE DISCIPLINE (applies to every row)
1. **Every verdict-affecting disposition quotes the layout/code it rests on** - Finding, Compliant, dismissal alike. Quote the field's `android:inputType` (layout) or the `setInputType`/`setTransformationMethod` call (code), and the sensitivity signal (id/hint/autofillHints). A disposition with no quoted attribute/call is an assertion -> `unverified`.
2. **Read from the source, not an index.** Cite `resources/res/layout*/*.xml:<line>` or `jadx/sources/...:<line-range>` of the actual field/builder, not an index record or line 1.
3. **No finding by inference/hedge.** A masking finding requires quoting (a) the sensitivity signal establishing the field holds a secret, and (b) the field's effective inputType lacking all four password-class values (or showing a clear-text render). "likely a password field", "may be unmasked" are NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the field's effective inputType depends on code you cannot resolve, or a hint `@string` you cannot dereference, the row is `unverified`. `false_positive_risks` is out-of-APK only; in-APK facts you did not resolve go in `unverified` rows.

What counts as a sensitive field (same signals as the keyboard-cache test)
Passwords/PINs/passphrases, payment card number/expiry/CVV, government IDs (SSN, driver's license, passport, DNI/NIF/NIE), and similarly secret values shown in inputs or text. Signals (most to least reliable): `android:autofillHints` (`password`, `creditCardNumber`, `creditCardSecurityCode`); an existing password inputType; the `android:id` token (`password|pwd|pin|cvv|card|ssn|passport|license|dni|nif`); the `android:hint`/`contentDescription` or adjacent label (resolve `@string`; cover Spanish: `contrasena`, `clave`, `tarjeta`, `seguro social`, `pasaporte`, `licencia`). Username/email/search are NOT in scope.

Effective masking - how to judge a field
- Masked (Compliant): the field's EFFECTIVE inputType (layout value, as overridden by any `setInputType` in code) contains one of `textPassword`/`textVisiblePassword`/`numberPassword`/`textWebPassword`; OR a non-editable display uses `PasswordTransformationMethod` / shows masked characters. Quote it.
- Not masked (Finding): the effective inputType has none of those (default text, `textNoSuggestions` alone, `textVisiblePassword`-as-sole-protection caveat aside), OR a `TextView`/display shows the raw secret. `setTransformationMethod(PasswordTransformationMethod)` masks display and DOES count here (unlike the keyboard-cache test, masking display is exactly the goal) - but `setTransformationMethod(HideReturnsTransformationMethod)`/null after a toggle that is NOT gated by explicit user action is unmasked-by-default.
- Reveal control: a show/hide toggle is acceptable ONLY if the default state is masked and reveal requires an explicit user action (button/checkbox). A field that starts revealed (toggle defaults to visible) is a Finding.

Notification suppression (second pillar)
- N-Finding: a `Notification`/`NotificationCompat.Builder` whose `setContentText`/`setContentTitle`/`bigText`/`MessagingStyle` includes a sensitive value (password, card, code, government ID) in visible text. Hardening: `setVisibility(VISIBILITY_PRIVATE/SECRET)` + a redacted public version, or simply not putting the secret in the notification. Quote the builder line that places the sensitive value.

The good pattern (do not flag)
- Field with a password-class inputType (layout or code) -> masked -> Compliant; quote it.
- A show-password toggle whose default is masked and reveal is on explicit click -> Compliant (quote the default-masked state).
- Notifications that carry no secret, or use redacted public versions / VISIBILITY_PRIVATE with non-sensitive public text -> Compliant.
- Material `TextInputLayout` with `app:endIconMode="password_toggle"` on a password-inputType field -> Compliant (default masked + explicit reveal).

Procedure
1. Enumerate sensitive UI fields. Layout: scan `resources/res/layout*/` for `EditText`/`TextInputEditText`/`AutoCompleteTextView` and their `android:inputType`/`id`/`hint`/`autofillHints`. Code: `grep -rEn "setInputType|setTransformationMethod|InputType\.TYPE_.*PASSWORD|PasswordTransformationMethod" jadx/sources/`. Compose: `BasicTextField`/`TextField` with `visualTransformation = PasswordVisualTransformation()`. Keep only sensitive fields (signals above). If there are none and no sensitive display/notification, the verdict is `n/a`.
2. For each sensitive field, resolve the EFFECTIVE inputType (layout value overridden by any code `setInputType` on that widget; follow view-binding/`findViewById`). Quote the masking evidence or its absence.
3. For any reveal toggle, confirm the DEFAULT state is masked and reveal is explicit-action-gated (quote the default).
4. Enumerate notification builders: `grep -rEn "NotificationCompat\.Builder|new Notification|setContentText|setContentTitle|bigText|MessagingStyle|setVisibility" jadx/sources/`. Check whether any sensitive value is placed in visible notification text (quote it).
5. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
6. Conclude per field/notification: Finding (sensitive + not masked by default, or revealed by default, or sensitive value in notification - quoted); Compliant (masked / explicit-reveal-gated / notification-suppressed - quoted); Unverified (effective inputType or hint unresolved, owner unresolved); documented candidate (a masking handled by an out-of-APK design fact).
7. Budget ~1-3 reads per field (layout, code override, hint string) plus the notification builders. If the effective inputType, hint, or notification content can't be resolved within budget, mark it `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Fields rendered in a WebView (HTML `type=password`) or in native code can't be judged via Android inputType statically -> `unverified`/note. The static verdict is made on what was determinable.

Output
List **all** sensitive UI fields (and any sensitive-notification sites) - one L1 row per field/site with its masking disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant masked fields by functionality (e.g. "login/password fields, textPassword - 6") as one L1 row per group, but always break out every Finding, documented-candidate, and unverified field as its own individual L1 row. Never sample findings.
- Finding: L1 row plus L2 rows for the sensitivity signal (quoted) and the effective inputType lacking masking / the unmasked display / the default-revealed toggle / the sensitive notification text (quoted), plus owner.
- Compliant: L1 row plus L2 for the sensitivity signal and the masking inputType / explicit-reveal default / notification suppression (quoted).
- Group: L1 summary plus an L2 naming references and the shared masked pattern.

```
{
  "id": "ui-001",
  "description": "Finding: The credit-card-number field is shown unmasked by default - it is a sensitive field but its inputType is 'number' (no password class).",
  "reference": "resources/res/layout/activity_payment.xml",
  "level": 1
},
{
  "id": "L2-card-sensitivity",
  "description": "Sensitivity (quoted): android:id=\"@+id/etCardNumber\", android:autofillHints=\"creditCardNumber\", hint @string/card_number = 'Numero de tarjeta'. Payment card number.",
  "reference": "resources/res/layout/activity_payment.xml:40-46",
  "level": 2
},
{
  "id": "L2-card-mask",
  "description": "Not masked (quoted): android:inputType=\"number\" - none of textPassword/textVisiblePassword/numberPassword/textWebPassword. PaymentActivity never calls setInputType/setTransformationMethod on etCardNumber (grep clean), so the card number renders in clear by default.",
  "reference": "resources/res/layout/activity_payment.xml:44",
  "level": 2
},
{
  "id": "ui-pwd-group",
  "description": "Compliant group: 6 password/PIN fields masked by default (textPassword/numberPassword) with password-toggle reveal.",
  "reference": "resources/res/layout/",
  "level": 1
},
{
  "id": "L2-pwd-coverage",
  "description": "Good pattern: each field has android:inputType=\"textPassword\" (or numberPassword) and sits in a TextInputLayout with app:endIconMode=\"password_toggle\" (default masked, explicit reveal). Quoted activity_login.xml:30-38. References (6 fields).",
  "reference": "resources/res/layout/activity_login.xml:30-38",
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
  "rationale": "F sensitive fields enumerated, M masked-by-default, N findings (unmasked / default-revealed / notification-leak), U unverified; K notification sites checked. <one or two sentences naming the fields and dispositions>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive field/site with (a) an L2 row quoting the sensitivity signal AND (b) an L2 row quoting the effective inputType lacking all four password-class values (or the unmasked display / default-revealed toggle / sensitive notification text). A finding stated with "likely"/"may" instead of quoted sensitivity + quoted unmasked inputType is INVALID -> `unverified`.
- **`textNoSuggestions` does NOT mask** (unlike the keyboard-cache test) - a sensitive field whose only inputType flag is `textNoSuggestions` is a Finding here. Only the four password-class inputTypes (or a display `PasswordTransformationMethod`) mask.
- **Read the effective inputType (layout overridden by code) before flagging; quote it. Do not flag non-sensitive fields or library fields.** Resolve any code `setInputType`; a field masked in code but plain in layout (or vice versa) is judged on the effective state.
- **Reveal must default to masked.** A show/hide control is Compliant only if the default is masked and reveal is explicit-action-gated; a toggle defaulting to visible is a Finding.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is it sensitive? what is the effective inputType? what is in the notification?) resolved by reading, unresolved -> `unverified`. Reject "might be masked at runtime", "the field might not be sensitive".
- `pass`: sensitive UI exists and every sensitive field is masked by default (password-class inputType or display transformation), any reveal is explicit-action-gated, and no notification places a secret in visible text, with L2 coverage.
- `n/a`: the app shows no sensitive data in the UI (enumeration performed; state this).
- `unverified` rows name the deepest unresolved point (or WebView/native entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its sensitivity + unmasked-inputType L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the sensitivity signal is quoted (id/hint/autofillHints), (2) the effective inputType (layout overridden by code) is quoted and lacks all four password-class values - or the unmasked display / default-revealed toggle / sensitive notification text is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary), not a library field.
Hedge scan: "likely", "may", "appears", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`: confirm every sensitive field's effective inputType was read and quoted (unread -> `unverified`), `textNoSuggestions`-only was treated as unmasked, no non-sensitive field was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.