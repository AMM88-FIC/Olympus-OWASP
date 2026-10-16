MASTG-TEST-0287

maswe_id       MASWE-0006
masvs_v2_id    MASVS-STORAGE-1
platform       android
title          Storage of Unencrypted Sensitive Data via the SharedPreferences API (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0287 is a dynamic test (runtime hooking of SharedPreferences write methods plus inspection of the shared_prefs XML on the device). This static engine cannot hook at runtime, so this prompt performs the best-effort static equivalent: trace sensitive values to SharedPreferences write sinks in the decompiled code and check whether they are encrypted first. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the static verdict is indicative only and must be confirmed at runtime.

What this test looks for
Sensitive data must not be persisted via SharedPreferences in cleartext. `MODE_PRIVATE` only restricts other apps; it does not protect against device compromise, backup extraction, or rooted/physical access. This is a static taint evaluation: a sensitive source value reaching a SharedPreferences write sink without baseline-compliant encryption (or EncryptedSharedPreferences) in between is a finding. Verdict: `pass` (no sensitive value written unencrypted to SharedPreferences; or the app writes no secrets there), `fail` (>=1 sensitive value stored in cleartext or sub-baseline), `n/a` (the app does not use SharedPreferences at all), or `inconclusive`.

Source is ground truth. A SharedPreferences-call evidence index is a candidate list only; confirm every conclusion by reading the call site in `jadx/sources/` and tracing the stored value to its origin (wrapper preference helpers and reused Editor fields are common).

Sensitive data (taint sources)
Credentials/passwords/PINs, access/refresh tokens, JWTs, session ids, API keys/secrets, OTP seeds, recovery mnemonics, private keys; PII (government IDs, email/phone used as identity, precise location); financial/payment data; health data. Determined from the preference KEY name, the value's variable/field name, and the source API (Keystore reads, AccountManager, auth responses, sensitive input fields). Non-sensitive settings (theme, feature flags, last-screen, counters) are not findings.

SharedPreferences write sinks
`Context.getSharedPreferences(...)`, `PreferenceManager.getDefaultSharedPreferences(...)`, `Activity.getPreferences(...)` -> `SharedPreferences.Editor.putString`, `putStringSet`, `putInt/Long/Float/Boolean` (strings are the usual secret carrier), then `apply()`/`commit()`. Kotlin `edit { putString(...) }` (androidx core-ktx).

What makes it compliant
- EncryptedSharedPreferences (`androidx.security.crypto.EncryptedSharedPreferences` with a `MasterKey`/AndroidKeyStore) -> compliant.
- The value is encrypted to the crypto baseline BEFORE being put (AES-GCM, or AES-CBC + MAC, with a random IV and a Keystore-backed / properly-derived key) -> compliant. Quote the cipher.
- Sub-baseline (still a Finding): ECB (incl. `Cipher.getInstance("AES")`), static/hardcoded IV, hardcoded/derivable key, weak primitive (DES/3DES/RC4), homemade/XOR, or base64-only / plain hashing presented as "protection". Quote the failing transform/key.
- Plaintext (Finding): the sensitive value is put directly.

Procedure
1. Enumerate usage: `grep -rEn "getSharedPreferences|getDefaultSharedPreferences|EncryptedSharedPreferences|\.edit\(|putString|putStringSet" jadx/sources/`. If there is no SharedPreferences usage at all, verdict `n/a`.
2. For each `put*` with a dynamic (non-literal) value, trace the value to its origin and decide sensitivity (read the call site; follow helpers/fields once). If the stored value is base64/hex/encoded, decode it statically to check the underlying value - encoding is not encryption.
3. For each sensitive value, determine whether it is stored via EncryptedSharedPreferences or encrypted to the baseline before the put. Quote the relevant code.
4. Classify per write: Finding (plaintext / sub-baseline), Compliant (EncryptedSharedPreferences, baseline-encrypted, or non-sensitive), Unverified (sensitivity or cipher unresolved within budget).
5. Budget ~1-3 reads per write touching a plausibly sensitive value; unresolved -> `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Output
JSON object as below; evidence_table uses the L1/L2 pattern.
- Finding: L1 row plus L2 rows for the sensitive source (quoted, category named), the SharedPreferences write sink (quoted, key + put method), and the absent/sub-baseline encryption (quoted).
- Clean/PASS: L1 conclusion plus L2 rows for enumeration coverage and, for any sensitive value stored, the EncryptedSharedPreferences / baseline-encryption evidence.

```
{
  "id": "sp-001",
  "description": "Finding: the app stores the user's access token in cleartext via SharedPreferences. A session credential is persisted unencrypted in the app sandbox.",
  "reference": "jadx/sources/com/example/app/SessionStore.java",
  "level": 1
},
{
  "id": "L2-sp-source",
  "description": "Sensitive source (quoted): String token = authResponse.getAccessToken(); at SessionStore.java:39. Category: auth/session credential.",
  "reference": "jadx/sources/com/example/app/SessionStore.java:37-41",
  "level": 2
},
{
  "id": "L2-sp-sink",
  "description": "Sink (no encryption, quoted): getSharedPreferences(\"auth_prefs\", MODE_PRIVATE).edit().putString(\"accessToken\", token).apply() at lines 42-44 - token stored in plaintext; no EncryptedSharedPreferences, no Cipher between source and put.",
  "reference": "jadx/sources/com/example/app/SessionStore.java:42-45",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0287",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "P SharedPreferences write sites enumerated, S carrying sensitive values, N findings (plaintext/sub-baseline), C compliant (EncryptedSharedPreferences/baseline-encrypted), U unverified. SharedPreferences used? <no -> n/a / yes>. <one or two sentences>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- This is the static approximation of a dynamic test: ALWAYS emit `needs_dynamic_testing: true`. The static `pass`/`fail` stands on the demonstrated static flows; the flag marks that runtime confirmation of the on-disk shared_prefs content is still warranted.
- `fail`: >=1 SharedPreferences write with an L2 row quoting the sensitive source AND an L2 row quoting the put sink, with either no encryption or encryption quoted as failing the crypto baseline. A finding stated with "likely"/"may"/"if it were sensitive" instead of the quoted source+sink is INVALID -> `unverified`.
- `pass`: SharedPreferences is used and every sensitive value is stored via EncryptedSharedPreferences or baseline encryption (and non-sensitive writes are fine), with L2 coverage.
- `n/a`: no SharedPreferences usage of any kind (enumeration performed and empty).
- EncryptedSharedPreferences counts as compliant only if the value actually flows through it; encrypting one preference while writing the secret to a plain one is still a Finding on the plain write.
- `unverified` rows name the deepest unresolved point (or native/no-source-SDK entry point). Neither pass nor fail.
- `false_positive_risks` is for out-of-APK factors only (a key delivered/managed outside the APK, a value sensitive only by runtime context). In-APK gaps -> `unverified`.
- `inconclusive` if counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, or if any `fail` lacks its source + sink L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
