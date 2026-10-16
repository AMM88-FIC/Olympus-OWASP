MASTG-TEST-0304

maswe_id       MASWE-0006
masvs_v2_id    MASVS-STORAGE-1
platform       android
title          References to Sensitive Data Stored Unencrypted via SQLite (static)

What this test looks for
Sensitive data must not be persisted in a plain SQLite database in the app sandbox. The default Android SQLite APIs (`SQLiteOpenHelper`, `Context.openOrCreateDatabase`, `SQLiteDatabase`) write an UNENCRYPTED `.db` file; the file is private to the app but unprotected against device compromise, backup extraction, or rooted/physical access. This is a static taint evaluation: a sensitive source value written to a plain-SQLite sink with no baseline-compliant encryption (and no SQLCipher) is a finding. Verdict: `pass` (no sensitive data stored in a plain SQLite DB; or the app uses an encrypted DB / encrypts the values), `fail` (>=1 sensitive value stored in a plain SQLite DB), `n/a` (the app uses no SQLite), or `inconclusive`.

Source is ground truth. A DB-API evidence index is a candidate list only; confirm by reading the call site in `jadx/sources/` and tracing the inserted/updated value to its origin (DAO wrappers and ContentValues builders are common indirection).

Sensitive data (taint sources)
Credentials/tokens/keys/secrets, OTP seeds, recovery mnemonics, private keys; PII (government IDs, email/phone used as identity, precise location); financial/payment data; health data. Determined from the column name, the bound value's variable/field name, and the source API. Non-sensitive columns (timestamps, ui state, public catalog data) are not findings.

Plain-SQLite write sinks
A `SQLiteOpenHelper` subclass, `Context.openOrCreateDatabase(...)`, `SQLiteDatabase.openOrCreateDatabase(...)`/`openDatabase(...)` (package `android.database.sqlite`), then `insert`/`replace`/`update`/`execSQL`/`compileStatement` carrying a `ContentValues` or bound args with sensitive columns.

What makes it compliant
- SQLCipher: the database is opened via `net.sqlcipher.database.SQLiteDatabase` / `net.sqlcipher.database.SQLiteOpenHelper` with a passphrase (the whole DB file is encrypted) -> compliant. Quote the SQLCipher usage and that the passphrase is not hardcoded/derivable (a hardcoded passphrase is sub-baseline -> Finding).
- The sensitive value is encrypted to the crypto baseline BEFORE being inserted (AES-GCM / AES-CBC + MAC, random IV, Keystore-backed / properly-derived key) so the column holds ciphertext -> compliant. Quote the cipher.
- Sub-baseline (still a Finding): ECB, static/hardcoded IV, hardcoded key or hardcoded SQLCipher passphrase, weak primitive, homemade/XOR, base64-only. Quote the failing transform/key.
- Plaintext (Finding): the sensitive value is inserted directly into a plain `android.database.sqlite` DB.

Procedure
1. Enumerate SQLite usage: `grep -rEn "SQLiteOpenHelper|openOrCreateDatabase|SQLiteDatabase|net\.sqlcipher|execSQL|ContentValues" jadx/sources/`. Distinguish `android.database.sqlite` (plain) from `net.sqlcipher` (encrypted). Ignore Room-generated internals: `androidx.room` generated `*_Impl` classes and `androidx.sqlite`/`SupportSQLiteDatabase` call sites are Room's machinery - attribute those to MASTG-TEST-0306, not here. If there is no SQLite usage at all (and no Room - see 0306), verdict `n/a`.
2. For each insert/update/execSQL, identify the columns and bound values; trace each value to its origin and decide sensitivity.
3. For each sensitive value, determine whether the DB is SQLCipher-encrypted or the value was baseline-encrypted before insertion. Quote the relevant code (including the SQLCipher passphrase source).
4. Classify per write: Finding (plaintext / sub-baseline), Compliant (SQLCipher with non-hardcoded key, or baseline-encrypted column, or non-sensitive), Unverified (sensitivity or cipher unresolved within budget).
5. Budget ~2-4 reads per sink (the insert, the value source, the DB-open / crypto). Unresolved -> `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Output
JSON object as below; evidence_table uses the L1/L2 pattern.
- Finding: L1 row plus L2 rows for the sensitive source (quoted, category named), the plain-SQLite write sink (quoted, table/column + insert API), and the absent/sub-baseline encryption (quoted, incl. plain `android.database.sqlite` open).
- Clean/PASS: L1 conclusion plus L2 rows for enumeration coverage and, for any sensitive value stored, the SQLCipher / baseline-encryption evidence.

```
{
  "id": "sql-001",
  "description": "Finding: the app stores the user's auth token in a plain SQLite database. A session credential is persisted unencrypted in the app sandbox.",
  "reference": "jadx/sources/com/example/app/db/TokenDbHelper.java",
  "level": 1
},
{
  "id": "L2-sql-source",
  "description": "Sensitive source (quoted): cv.put(\"token\", session.getAccessToken()); at TokenDbHelper.java:71. Category: auth/session credential.",
  "reference": "jadx/sources/com/example/app/db/TokenDbHelper.java:68-72",
  "level": 2
},
{
  "id": "L2-sql-sink",
  "description": "Sink (plain DB, no encryption, quoted): class TokenDbHelper extends android.database.sqlite.SQLiteOpenHelper; db.insert(\"sessions\", null, cv) at line 73 - plain SQLite (not net.sqlcipher), token inserted as cleartext, no Cipher between source and insert.",
  "reference": "jadx/sources/com/example/app/db/TokenDbHelper.java:1-20,73",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0304",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "D SQLite write sites enumerated (plain vs SQLCipher), S carrying sensitive data, N findings, C compliant, U unverified. SQLite used? <no -> n/a / yes>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false).
- `fail`: >=1 plain-SQLite write with an L2 row quoting the sensitive source AND an L2 row quoting the insert sink on a plain `android.database.sqlite` DB, with either no encryption or encryption quoted as failing the baseline (incl. hardcoded SQLCipher passphrase). "Likely"/"may"/"if sensitive" instead of quoted source+sink is INVALID -> `unverified`.
- `pass`: SQLite is used and every sensitive value is in a SQLCipher DB (non-hardcoded passphrase) or stored as baseline-ciphertext (non-sensitive columns are fine), with L2 coverage.
- `n/a`: no SQLite usage of any kind (enumeration performed and empty). If the app uses Room, evaluate under MASTG-TEST-0306.
- SQLCipher counts as compliant only with a non-hardcoded, properly-managed passphrase; a hardcoded passphrase is a Finding.
- `unverified` rows name the deepest unresolved point (or native/no-source-SDK entry point). Neither pass nor fail.
- `false_positive_risks` is for out-of-APK factors only (passphrase delivered/managed outside the APK, a column sensitive only by runtime context). In-APK gaps -> `unverified`.
- `inconclusive` if counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, or if any `fail` lacks its source + sink L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
