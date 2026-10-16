MASTG-TEST-0207

maswe_id       MASWE-0006
masvs_v2_id    MASVS-STORAGE-1
platform       android
title          Storage of Unencrypted Sensitive Data in App-Sandbox Files (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0207 is a dynamic test (copy the app's private data directory before/after exercising the app and inspect the files created). This static engine cannot diff device storage, so this prompt performs the best-effort static equivalent: trace sensitive values to file-write sinks targeting the app sandbox in the decompiled code and check whether they are encrypted first. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the static verdict is indicative only and must be confirmed at runtime.

What this test looks for
Sensitive data must not be persisted to files in the app's internal sandbox in cleartext. The sandbox is private to the app, but that does not protect against device compromise, backup extraction, or rooted/physical access. This is a static taint evaluation: a sensitive source value reaching a sandbox file-write sink without baseline-compliant encryption (or EncryptedFile) in between is a finding. Verdict: `pass` (no sensitive value written unencrypted to a sandbox file; or the app writes no secrets to files), `fail` (>=1 sensitive value written in cleartext or sub-baseline), `n/a` (the app writes no files to the sandbox), or `inconclusive`.

Scope note: this test covers the app's PRIVATE sandbox (internal storage and app-scoped external dirs). Writes to shared/public external storage are covered by MASTG-TEST-0202/0200/0201; SharedPreferences by 0287; SQLite/Room by 0304/0306; DataStore by 0305. A file write here that is also a database/prefs file is attributed to the more specific test.

Sensitive data (taint sources)
Credentials/passwords/PINs, access/refresh tokens, JWTs, session ids, API keys/secrets, OTP seeds, recovery mnemonics, private keys; PII (government IDs, email/phone used as identity, precise location); financial/payment data; health data; serialized objects/databases carrying any of these. Determined from the value's variable/field name, the source API, and the file name/extension. Non-sensitive content (caches of public data, images the user chose, layout state) is not a finding.

Sandbox file-write sinks
`Context.openFileOutput(name, MODE_PRIVATE)`, `getFilesDir()`, `getCacheDir()`, `getDir(...)`, `getNoBackupFilesDir()`, app-scoped `getExternalFilesDir()`/`getExternalCacheDir()` -> `FileOutputStream`, `FileWriter`/`BufferedWriter`, `okio` sink, `java.nio.file.Files.write`, `RandomAccessFile`, `ObjectOutputStream`, or a JSON/serializer writing to such a path.

What makes it compliant
- EncryptedFile (`androidx.security.crypto.EncryptedFile` with a `MasterKey`/AndroidKeyStore) -> compliant.
- The data is encrypted to the crypto baseline BEFORE the write (AES-GCM, or AES-CBC + MAC, random IV, Keystore-backed / properly-derived key) -> compliant. Quote the cipher.
- Sub-baseline (still a Finding): ECB, static/hardcoded IV, hardcoded/derivable key, weak primitive (DES/3DES/RC4), homemade/XOR, or base64-only / plain hashing presented as "protection". Quote the failing transform/key.
- Plaintext (Finding): the sensitive value is written directly.

Encoding/compression is NOT protection (decode to reveal secrets)
If a written value is base64/hex/URL-encoded, escaped, wide-char, or XOR-masked, or wrapped in gzip/tar/zip, treat the encoded form as still-cleartext: statically decode/decompress it (read the transform) to determine whether the underlying value is sensitive. A sensitive value written as `Base64.encode(token)`, a hex string, or `gzip(jsonWithCreds)` is a Finding, not an opaque non-sensitive blob. Only encryption to the crypto baseline (above) actually protects.

Procedure
1. Enumerate sandbox file writes: `grep -rEn "openFileOutput|getFilesDir|getCacheDir|getNoBackupFilesDir|getExternalFilesDir|FileOutputStream|FileWriter|ObjectOutputStream|Files\.write|EncryptedFile" jadx/sources/`. If there are no sandbox file writes, verdict `n/a`.
2. For each write sink, trace what data is written and whether any is sensitive (taint from a sensitive source); if the written value is encoded/compressed (base64/hex/XOR/gzip/zip), decode it statically first to reveal the underlying value before judging sensitivity. Quote the value and the sink. Non-sensitive writes -> Compliant.
3. For each sensitive write, determine whether EncryptedFile is used or the data is encrypted to the baseline before the write; quote the relevant code.
4. Classify per write: Finding (plaintext / sub-baseline), Compliant (EncryptedFile, baseline-encrypted, non-sensitive), Unverified (sensitivity or cipher unresolved within budget).
5. Budget ~2-4 reads per sink (the write, the data source, the crypto). Unresolved -> `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Output
JSON object as below; evidence_table uses the L1/L2 pattern.
- Finding: L1 row plus L2 rows for the sensitive source (quoted, category named), the sandbox file-write sink (quoted), and the absent/sub-baseline encryption (quoted).
- Clean/PASS: L1 conclusion plus L2 rows for enumeration coverage and, for any sensitive value written, the EncryptedFile / baseline-encryption evidence.

```
{
  "id": "file-001",
  "description": "Finding: the app serializes the user's login credentials to a plaintext file in internal storage. A credential is persisted unencrypted in the app sandbox.",
  "reference": "jadx/sources/com/example/app/CredentialCache.java",
  "level": 1
},
{
  "id": "L2-file-source",
  "description": "Sensitive source (quoted): String json = gson.toJson(new Credentials(user, password)); at CredentialCache.java:54 - password is a credential.",
  "reference": "jadx/sources/com/example/app/CredentialCache.java:50-56",
  "level": 2
},
{
  "id": "L2-file-sink",
  "description": "Sink (no encryption, quoted): openFileOutput(\"creds.json\", MODE_PRIVATE).write(json.getBytes()) at lines 58-61 - written in cleartext; no EncryptedFile, no Cipher between source and write.",
  "reference": "jadx/sources/com/example/app/CredentialCache.java:58-62",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0207",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "F sandbox file-write sites enumerated, S carrying sensitive data, N findings (plaintext/sub-baseline), C compliant (EncryptedFile/baseline-encrypted), U unverified. Sandbox file writes present? <no -> n/a / yes>. <one or two sentences>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- This is the static approximation of a dynamic test: ALWAYS emit `needs_dynamic_testing: true`. The static `pass`/`fail` stands on the demonstrated static flows; the flag marks that runtime inspection of the on-disk sandbox is still warranted.
- `fail`: >=1 sandbox file write with an L2 row quoting the sensitive source AND an L2 row quoting the write sink, with either no encryption or encryption quoted as failing the crypto baseline. A finding stated with "likely"/"may"/"if it were sensitive" is INVALID -> `unverified`.
- `pass`: sandbox files are written and every sensitive value is protected via EncryptedFile or baseline encryption (non-sensitive writes are fine), with L2 coverage.
- `n/a`: no sandbox file writes of any kind (enumeration performed and empty).
- Do not double-count: a SharedPreferences/SQLite/Room/DataStore file is attributed to its specific test (0287/0304/0306/0305), not here.
- `unverified` rows name the deepest unresolved point (or native/no-source-SDK entry point). Neither pass nor fail.
- `false_positive_risks` is for out-of-APK factors only (a key delivered/managed outside the APK, data sensitive only by runtime context). In-APK gaps -> `unverified`.
- `inconclusive` if counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, or if any `fail` lacks its source + sink L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
