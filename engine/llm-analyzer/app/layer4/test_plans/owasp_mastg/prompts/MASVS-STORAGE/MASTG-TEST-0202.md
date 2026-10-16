MASTG-TEST-0202

maswe_id       MASWE-0007
masvs_v2_id    MASVS-STORAGE-2
platform       android
title          References to APIs and Permissions for Accessing External Storage - sensitive data written to shared storage unencrypted (static)

What this test looks for
Any sensitive data the app writes OUTSIDE its sandbox - external storage or public folders (Downloads, Pictures, shared MediaStore) - must be protected: either the app does not use external storage at all, or sensitive data written there is encrypted meeting the crypto baseline (section 1.2 - ENISA/strong primitives, proper mode/IV/key management). This is a static, taint-style evaluation: sensitive source -> external-storage write sink, with a crypto-baseline check on any encryption applied. Verdict: `pass` (no external storage used; OR sensitive data written there is encrypted to the baseline; analysis confirms no unencrypted sensitive data is written externally), `fail` (sensitive data is written to external storage unencrypted, or with crypto that fails the baseline), or `inconclusive`. (This control has no N/A.)

SHORT-CIRCUIT (decide first): if the manifest declares no external-storage use AND the code invokes no external/public storage write APIs (below), there is nowhere outside the sandbox to leak to -> PASS. NOTE: this cannot be a manifest-only check - on modern targetSdk, scoped-storage writes (MediaStore, getExternalFilesDir) often need no WRITE_EXTERNAL_STORAGE permission, so the absence of the manifest permission does NOT prove no external write. Verify the code too.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on** - Finding, Compliant, dismissal alike. Quote the sensitive value, the external-storage write sink it reaches, and (if encrypted) the cipher transform / key / IV. A disposition with no quoted code is an assertion -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual write site and the data source, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the sensitive value being written and (b) the external-storage sink, with no baseline-compliant encryption between them. "likely writes sensitive data", "may be unencrypted", "if the file held a secret" are NOT evidence -> `unverified`. A non-sensitive write, or a sensitive write encrypted to the baseline, is Compliant - not a hypothetical finding.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the data's sensitivity, the path's externality, or the cipher can't be resolved within budget, the row is `unverified` (deepest unresolved point named). `false_positive_risks` is out-of-APK only.

External-storage write sinks
`getExternalStorageDirectory()`, `getExternalFilesDir()`/`getExternalCacheDir()` (app-specific external - still external, world-readable on older devices / removable), `Environment.DIRECTORY_DOWNLOADS`/`DIRECTORY_PICTURES` etc., `MediaStore` inserts to shared collections, `FileOutputStream`/`FileWriter`/`okio` to a path under external/public storage, `DownloadManager`, `content://media` writes, public `File(Environment.getExternalStoragePublicDirectory(...), ...)`. (Writes to the app's internal sandbox - `getFilesDir()`/`getCacheDir()`/`openFileOutput(MODE_PRIVATE)`/`SharedPreferences` - are NOT external; out of scope here.)

Sensitive data (taint sources)
Credentials/passwords/tokens/keys, PII (name/email/phone/government IDs), financial/payment data, health data, precise location, auth/session material, and copies of internal databases/secrets. Determined from context (variable/field names, source API). Non-sensitive content (user-chosen media the user is exporting, public data) is not a finding.

Crypto-baseline check (when the data IS encrypted before writing)
Encryption only protects the write if it meets the section 1.2 baseline. Apply the same allow/deny logic as the symmetric-crypto test:
- Baseline-compliant: a strong primitive in a secure mode with proper IV/nonce and a non-hardcoded, properly-managed key - e.g. AES-GCM (or AES-CBC with random IV + MAC) with a key from AndroidKeyStore / proper KDF. -> the write is protected (Compliant).
- Baseline-FAILING (still a Finding even though "encrypted"): ECB mode (incl. `Cipher.getInstance("AES")` defaulting to ECB), static/hardcoded IV, hardcoded/derivable key, weak primitive (DES/3DES/RC4), or a homemade/XOR "encryption". Quote the transform/key/IV.

Failure modes
- ES1 - Unencrypted sensitive write: a sensitive value reaches an external-storage write sink with no encryption applied. Quote source + sink.
- ES2 - Sub-baseline encrypted write: a sensitive value is "encrypted" before an external write but the crypto fails the 1.2 baseline (ECB/static IV/hardcoded key/weak primitive/homemade). Quote source + sink + the failing transform/key.

Procedure
1. Manifest + code presence:
   (a) Permissions: obtain AndroidManifest.xml (jadx/resources/AndroidManifest.xml) and enumerate the declared storage permissions - `WRITE_EXTERNAL_STORAGE`, `READ_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE` (`grep -nE "WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE" jadx/resources/AndroidManifest.xml`). Report which are present (with the manifest line) as a required Observation deliverable. Absence does NOT prove no external write (scoped storage needs no permission), so this informs but does not gate the verdict.
   (b) Code sinks: enumerate external-storage write sinks in code (`grep -rEn "getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir|getExternalStoragePublicDirectory|DIRECTORY_(DOWNLOADS|PICTURES|DOCUMENTS)|MediaStore|DownloadManager|FileOutputStream|FileWriter" jadx/sources/`).
   If no external write sinks exist in code (regardless of manifest), short-circuit -> PASS (state both searches).
2. For each external write sink, trace what data is written and whether any is sensitive (taint from a sensitive source). Quote the value and the sink. Non-sensitive writes -> Compliant.
3. For each sensitive external write, determine whether the data is encrypted before the write and, if so, evaluate the cipher against the 1.2 baseline (transform/mode/IV/key). Unencrypted -> ES1; sub-baseline -> ES2; baseline-compliant -> Compliant. Quote the crypto.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A third-party SDK writing its own data externally is attributed; a sensitive leak via an SDK the app feeds is in scope.
5. Conclude per write: Finding (ES1/ES2 with source+sink quoted, and the failing crypto for ES2); Compliant (non-sensitive write, internal-only write, or baseline-encrypted sensitive write - quoted); Unverified (sensitivity / externality / cipher unresolved); documented candidate where baseline-compliance hinges on an out-of-APK key-management fact.
6. Budget ~2-4 reads per sink (the write, the data source, the crypto) plus 1-2 call-graph hops to trace a sensitive source. Unresolved within budget -> `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Writes inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a value is sensitive is read from context; indeterminate -> `unverified`. App-internal sandbox writes are out of scope (a separate storage test covers those). The static verdict rests on demonstrated sensitive-data-to-external-sink flows and the crypto applied.

Output
List **all** external-storage write sites carrying app data - one L1 row per write (or per data category) with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant writes by area (e.g. "user-exported media, non-sensitive - 5") as one L1 row per group, but always break out every Finding (ES1/ES2), documented-candidate, and unverified write individually. Never sample findings.
- Permissions: one L1 row listing the declared storage permissions found in the manifest (WRITE_EXTERNAL_STORAGE / READ_EXTERNAL_STORAGE / MANAGE_EXTERNAL_STORAGE, or "none"), with the manifest line - a required Observation deliverable.
- Finding ES1: L1 row plus L2 rows for the sensitive source (quoted) and the external write sink (quoted), no encryption between them, plus owner.
- Finding ES2: as ES1 plus an L2 quoting the failing crypto transform/key/IV against the baseline.
- Compliant: L1 row plus L2 showing the write is non-sensitive / internal-only / baseline-encrypted (quoted).
- Group: L1 summary plus an L2 naming references and the shared safe pattern.

```
{
  "id": "es-001",
  "description": "Finding (ES1 unencrypted sensitive write): The app writes the user's auth token in cleartext to a file in external storage (Downloads), readable by other apps / off-sandbox.",
  "reference": "jadx/sources/com/example/app/BackupHelper.java",
  "level": 1
},
{
  "id": "L2-token-source",
  "description": "Sensitive source (quoted): String token = session.getAuthToken(); at BackupHelper.java:40. Category: auth/session credential.",
  "reference": "jadx/sources/com/example/app/BackupHelper.java:38-42",
  "level": 2
},
{
  "id": "L2-token-extwrite",
  "description": "External write (quoted, ES1): File f = new File(Environment.getExternalStoragePublicDirectory(DIRECTORY_DOWNLOADS), \"backup.txt\"); new FileOutputStream(f).write(token.getBytes()) at lines 44-49 - token written in cleartext to public Downloads, no encryption. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/BackupHelper.java:44-50",
  "level": 2
},
{
  "id": "es-002",
  "description": "Finding (ES2 sub-baseline encrypted write): The app encrypts PII with AES/ECB before writing it to external storage - ECB fails the crypto baseline, so the data is not adequately protected.",
  "reference": "jadx/sources/com/example/app/ExportTask.java",
  "level": 1
},
{
  "id": "L2-pii-extwrite",
  "description": "Sensitive source + external write (quoted): profile.getEmail()+getPhone() -> bytes written to getExternalFilesDir()/export.bin at lines 60-72.",
  "reference": "jadx/sources/com/example/app/ExportTask.java:58-74",
  "level": 2
},
{
  "id": "L2-pii-crypto",
  "description": "Sub-baseline crypto (quoted, ES2): Cipher.getInstance(\"AES/ECB/PKCS5Padding\") with a hardcoded key SecretKeySpec(\"1234567890123456\".getBytes(),\"AES\") at lines 62-66 - ECB mode + hardcoded key both fail the section 1.2 baseline. Encryption does not protect the write.",
  "reference": "jadx/sources/com/example/app/ExportTask.java:60-68",
  "level": 2
},
{
  "id": "es-ok-group",
  "description": "Compliant group: 5 external writes of user-exported, non-sensitive media (photos the user chose to save).",
  "reference": "jadx/sources/com/example/app/export/",
  "level": 1
},
{
  "id": "L2-ok-coverage",
  "description": "Good pattern: each writes user-selected image bytes (not a secret) to MediaStore Pictures (quoted MediaExporter.java:30-55) - non-sensitive content the user is exporting. References (5 writes).",
  "reference": "jadx/sources/com/example/app/export/MediaExporter.java:30-55",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0202",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Declared storage permissions: <list or none>. E external write sinks enumerated, S carrying sensitive data, N findings (ES1 unencrypted / ES2 sub-baseline), C compliant, U unverified. External storage used? <no -> short-circuit pass / yes>. <one or two sentences naming the sensitive writes and their crypto>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive value with (a) an L2 row quoting the sensitive source AND (b) an L2 row quoting the external-storage write sink, with either no encryption (ES1) or encryption quoted as failing the 1.2 baseline (ES2 - ECB/static IV/hardcoded key/weak primitive/homemade). A finding stated with "likely"/"may"/"if it were sensitive" instead of the quoted source+sink is INVALID -> `unverified`.
- **Encryption only protects if it meets the baseline.** A sensitive external write encrypted with ECB / a hardcoded key / a static IV / a weak primitive is still a Finding (ES2) - "encrypted" is not sufficient; quote the failing transform/key. Baseline-compliant encryption (AES-GCM etc. with proper key/IV) is Compliant.
- **External vs internal; manifest is not sufficient alone.** App-internal sandbox writes (`getFilesDir`/`MODE_PRIVATE`/SharedPreferences) are out of scope. Absence of WRITE_EXTERNAL_STORAGE does NOT prove no external write (scoped storage) - confirm via the code sinks.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (key delivered/managed outside the APK making the cipher baseline-compliant, data sensitivity established outside the APK) - in-APK facts (is the data sensitive? is the path external? what is the cipher?) resolved by reading, unresolved -> `unverified`. Reject "might be encrypted elsewhere", "the file might not hold secrets".
- `pass`: no external write sinks in code (short-circuit), OR every sensitive external write is encrypted to the 1.2 baseline (and non-sensitive writes are fine), with L2 coverage; analysis confirms no unencrypted/sub-baseline sensitive data is written externally.
- (No N/A for this control.)
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its source + external-sink (+ failing-crypto for ES2) L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the sensitive source is quoted and the data category named; (2) the external-storage write sink is quoted (and it is external, not internal sandbox); (3) for ES1 no baseline encryption is applied between source and sink; for ES2 the failing crypto transform/key/IV is quoted against the baseline; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "if ... were", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`: confirm the external-sink search was performed (short-circuit pass states it), every sensitive external write's crypto was read and quoted (unread -> `unverified`), no internal-sandbox write was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.