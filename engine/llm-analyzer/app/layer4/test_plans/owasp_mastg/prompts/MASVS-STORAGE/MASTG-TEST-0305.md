MASTG-TEST-0305

maswe_id       MASWE-0006
masvs_v2_id    MASVS-STORAGE-1
platform       android
title          References to Sensitive Data Stored Unencrypted via Jetpack DataStore (static)

What this test looks for
Sensitive data must not be persisted via Jetpack DataStore (Preferences DataStore or Proto DataStore) without encryption. DataStore writes its backing file in the app sandbox in cleartext by default; the file is private to the app but unprotected against device compromise, backup extraction, or rooted/physical access. This is a static taint evaluation: a sensitive source value written to a DataStore sink with no baseline-compliant encryption (no encrypting serializer) is a finding. Verdict: `pass` (no sensitive value stored unencrypted in DataStore; or values are encrypted / an encrypting serializer is used), `fail` (>=1 sensitive value stored unencrypted), `n/a` (the app uses no DataStore), or `inconclusive`.

Source is ground truth. Confirm by reading the DataStore declaration, the `edit { }` / serializer code, and the value's origin in `jadx/sources/`.

Sensitive data (taint sources)
Credentials/tokens/keys/secrets, OTP seeds, recovery mnemonics, private keys; PII (government IDs, email/phone used as identity, precise location); financial/payment data; health data. Determined from the preference KEY name, the stored value's variable/field name, and the source API. Non-sensitive settings (theme, flags, onboarding state) are not findings.

DataStore write sinks
- Preferences DataStore: `preferencesDataStore(name = ...)` / `RxPreferenceDataStoreBuilder`, a `DataStore<Preferences>`, keys via `stringPreferencesKey/intPreferencesKey/...`, writes via `dataStore.edit { it[KEY] = value }` (or `updateData`).
- Proto DataStore: a `DataStore<T>` built with `DataStoreFactory.create(serializer = ...)` and writes via `updateData { ... }`.

What makes it compliant
- An encrypting `Serializer` (Proto DataStore whose serializer encrypts/decrypts with the crypto baseline, e.g. Tink / AES-GCM, Keystore-backed key), or an EncryptedFile-backed DataStore -> compliant. Quote the serializer/cipher.
- The value is encrypted to the crypto baseline BEFORE being stored (AES-GCM / AES-CBC + MAC, random IV, Keystore-backed / properly-derived key) so DataStore holds ciphertext -> compliant. Quote the cipher.
- Sub-baseline (still a Finding): ECB, static/hardcoded IV, hardcoded/derivable key, weak primitive, homemade/XOR, base64-only. Quote the failing transform/key.
- Plaintext (Finding): the sensitive value is stored directly (plain Preferences/Proto DataStore).

Procedure
1. Enumerate DataStore usage: `grep -rEn "preferencesDataStore|DataStore<|DataStoreFactory|stringPreferencesKey|\.edit \{|updateData|PreferenceDataStore" jadx/sources/`. If there is no DataStore usage, verdict `n/a`.
2. For each write (`edit`/`updateData`), identify the key/field and the value; trace each value to its origin and decide sensitivity.
3. For each sensitive value, determine whether an encrypting serializer is used or the value was baseline-encrypted before storage. Quote the relevant code.
4. Classify per write: Finding (plaintext / sub-baseline), Compliant (encrypting serializer / baseline-encrypted value / non-sensitive), Unverified (sensitivity or cipher unresolved within budget).
5. Budget ~2-4 reads per write (the write, the value source, the serializer/crypto). Unresolved -> `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Output
JSON object as below; evidence_table uses the L1/L2 pattern.
- Finding: L1 row plus L2 rows for the sensitive source (quoted, category named), the DataStore write sink (quoted, key + edit/updateData), and the absent/sub-baseline encryption (quoted, incl. plain Preferences/Proto serializer).
- Clean/PASS: L1 conclusion plus L2 rows for enumeration coverage and, for any sensitive value, the encrypting-serializer / baseline-encryption evidence.

```
{
  "id": "ds-001",
  "description": "Finding: the app stores the user's API key in a plain Preferences DataStore. A secret is persisted unencrypted in the app sandbox.",
  "reference": "jadx/sources/com/example/app/SettingsRepository.java",
  "level": 1
},
{
  "id": "L2-ds-source",
  "description": "Sensitive source (quoted): val apiKey = response.apiKey at SettingsRepository.kt:48. Category: API key/secret.",
  "reference": "jadx/sources/com/example/app/SettingsRepository.java:46-50",
  "level": 2
},
{
  "id": "L2-ds-sink",
  "description": "Sink (plain DataStore, no encryption, quoted): dataStore.edit { it[stringPreferencesKey(\"api_key\")] = apiKey } at lines 52-54 - Preferences DataStore with no encrypting serializer and no Cipher between source and write; stored as cleartext.",
  "reference": "jadx/sources/com/example/app/SettingsRepository.java:52-55",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0305",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "W DataStore write sites enumerated, S carrying sensitive values, N findings, C compliant (encrypting serializer/baseline-encrypted), U unverified. DataStore used? <no -> n/a / yes>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false).
- `fail`: >=1 DataStore write with an L2 row quoting the sensitive source AND an L2 row quoting the write sink, with no encrypting serializer / no encryption or encryption quoted as failing the baseline. "Likely"/"may"/"if sensitive" instead of quoted source+sink is INVALID -> `unverified`.
- `pass`: DataStore is used and every sensitive value is protected by an encrypting serializer or baseline encryption (non-sensitive writes are fine), with L2 coverage.
- `n/a`: no DataStore usage of any kind (enumeration performed and empty).
- `unverified` rows name the deepest unresolved point (or native/no-source-SDK entry point). Neither pass nor fail.
- `false_positive_risks` is for out-of-APK factors only (a key delivered/managed outside the APK, a value sensitive only by runtime context). In-APK gaps -> `unverified`.
- `inconclusive` if counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, or if any `fail` lacks its source + sink L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
