MASTG-TEST-0306

maswe_id       MASWE-0006
masvs_v2_id    MASVS-STORAGE-1
platform       android
title          References to Sensitive Data Stored Unencrypted via Android Room (static)

What this test looks for
Sensitive data must not be persisted via the Android Room Persistence Library without an encryption layer. Room is a wrapper over SQLite; by default it writes an UNENCRYPTED `.db` file in the app sandbox, unprotected against device compromise, backup extraction, or rooted/physical access. This is a static taint evaluation: a sensitive field persisted by a plain Room database (no SQLCipher `SupportFactory`, no column-level encryption) is a finding. Verdict: `pass` (no sensitive data persisted by a plain Room DB; or Room is opened with SQLCipher / the sensitive fields are encrypted), `fail` (>=1 sensitive field stored by a plain Room DB), `n/a` (the app uses no Room), or `inconclusive`.

Source is ground truth. Confirm by reading the `@Entity` classes, the `@Dao` insert/update methods, and the `Room.databaseBuilder(...)` call in `jadx/sources/`.

Sensitive data (taint sources)
`@Entity` fields (columns) holding credentials/tokens/keys/secrets, OTP seeds, recovery mnemonics, private keys; PII (government IDs, email/phone used as identity, precise location); financial/payment data; health data. Determined from the field/column name and the values assigned to the entity before `@Insert`/`@Update`. Non-sensitive columns (timestamps, ui state, public data) are not findings.

Plain-Room write sinks
`@Database(entities = {...})` abstract class extending `RoomDatabase`, built via `Room.databaseBuilder(...)` / `Room.inMemoryDatabaseBuilder(...)`; `@Dao` methods annotated `@Insert`/`@Update`/`@Upsert` or `@Query` with an INSERT/UPDATE writing sensitive `@Entity` fields.

What makes it compliant
- SQLCipher-backed Room: `builder.openHelperFactory(new SupportFactory(passphrase))` (net.sqlcipher) so the whole DB file is encrypted -> compliant. Quote the factory wiring and that the passphrase is not hardcoded/derivable (a hardcoded passphrase is sub-baseline -> Finding).
- Column-level encryption: the sensitive `@Entity` field stores baseline ciphertext (encrypted via a `@TypeConverter` or before assignment, using AES-GCM / AES-CBC + MAC, random IV, Keystore-backed / properly-derived key) -> compliant. Quote the cipher.
- Sub-baseline (still a Finding): ECB, static/hardcoded IV, hardcoded key or hardcoded SQLCipher passphrase, weak primitive, homemade/XOR, base64-only. Quote the failing transform/key.
- Plaintext (Finding): the sensitive field is persisted by a plain Room DB with no SQLCipher and no column encryption.

Procedure
1. Enumerate Room usage: `grep -rEn "androidx\.room|@Database|@Entity|@Dao|Room\.databaseBuilder|@Insert|@Update|SupportFactory|net\.sqlcipher" jadx/sources/`. If there is no Room usage at all (raw SQLite -> see 0304), verdict `n/a`.
2. For each `@Entity`, identify sensitive fields. For each `@Dao` insert/update writing such fields, confirm the entity is persisted.
3. Determine how the database is opened: plain Room, SQLCipher `SupportFactory`, or with encrypted columns. Quote the `databaseBuilder` chain and any `openHelperFactory`.
4. Classify per sensitive entity/field: Finding (plain Room, no column encryption / sub-baseline), Compliant (SQLCipher with non-hardcoded passphrase, or baseline-encrypted column, or non-sensitive), Unverified (sensitivity or cipher unresolved within budget).
5. Budget ~2-4 reads (the entity, the DAO write, the databaseBuilder / crypto). Unresolved -> `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Output
JSON object as below; evidence_table uses the L1/L2 pattern.
- Finding: L1 row plus L2 rows for the sensitive `@Entity` field (quoted, category named), the `@Dao` write + plain `Room.databaseBuilder` (quoted, no SupportFactory), and the absent/sub-baseline encryption.
- Clean/PASS: L1 conclusion plus L2 rows for enumeration coverage and, for any sensitive field, the SQLCipher SupportFactory / column-encryption evidence.

```
{
  "id": "room-001",
  "description": "Finding: the app persists the user's refresh token in a plain Room database. A session credential is stored unencrypted in the app sandbox.",
  "reference": "jadx/sources/com/example/app/db/AppDatabase.java",
  "level": 1
},
{
  "id": "L2-room-entity",
  "description": "Sensitive field (quoted): @Entity class TokenEntity { @ColumnInfo(name=\"refresh_token\") String refreshToken; } written by @Insert void insert(TokenEntity t) in TokenDao. Category: auth/session credential.",
  "reference": "jadx/sources/com/example/app/db/TokenEntity.java:10-18",
  "level": 2
},
{
  "id": "L2-room-builder",
  "description": "Sink (plain Room, quoted): Room.databaseBuilder(ctx, AppDatabase.class, \"app.db\").build() at AppDatabase.java:33 - no openHelperFactory(SupportFactory), no net.sqlcipher, no @TypeConverter encrypting refreshToken; the token is stored in cleartext.",
  "reference": "jadx/sources/com/example/app/db/AppDatabase.java:30-35",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0306",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "E Room entities/DAO writes enumerated, S carrying sensitive fields, N findings, C compliant (SQLCipher/encrypted columns), U unverified. Room used? <no -> n/a / yes>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false).
- `fail`: >=1 sensitive `@Entity` field with an L2 row quoting the field AND an L2 row quoting the plain `Room.databaseBuilder` (no SupportFactory) / DAO write, with no column encryption or sub-baseline encryption. "Likely"/"may"/"if sensitive" instead of quoted evidence is INVALID -> `unverified`.
- `pass`: Room is used and every sensitive field is protected by SQLCipher `SupportFactory` (non-hardcoded passphrase) or baseline column encryption (non-sensitive columns are fine), with L2 coverage.
- `n/a`: no Room usage of any kind (enumeration performed and empty). Raw SQLite is evaluated under MASTG-TEST-0304.
- SQLCipher counts as compliant only with a non-hardcoded, properly-managed passphrase.
- `unverified` rows name the deepest unresolved point (or native/no-source-SDK entry point). Neither pass nor fail.
- `false_positive_risks` is for out-of-APK factors only (passphrase delivered/managed outside the APK, a field sensitive only by runtime context). In-APK gaps -> `unverified`.
- `inconclusive` if counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, or if any `fail` lacks its field + builder/DAO L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
