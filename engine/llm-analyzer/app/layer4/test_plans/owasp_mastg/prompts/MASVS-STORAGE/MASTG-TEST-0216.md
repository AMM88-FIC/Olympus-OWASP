MASTG-TEST-0216

maswe_id       MASWE-0004
masvs_v2_id    MASVS-STORAGE-2
platform       android
title          Sensitive Data Not Excluded From Backup (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0216 is a dynamic test (perform a backup and restore on a device and inspect which files are actually restored). This static engine cannot run the backup daemon, so this prompt performs the best-effort static equivalent: evaluate the manifest + backup-rule XML against the app's sensitive data stores (the same analysis as MASTG-TEST-0262). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the static verdict is indicative only and must be confirmed at runtime.

What this test looks for
Android backs up app data (cloud Auto Backup / device-to-device transfer) unless the app opts out. This test checks, statically, that the app does NOT allow sensitive data to be backed up. It is a configuration evaluation over the AndroidManifest.xml plus the referenced backup-rule XML files, cross-referenced against where the app actually stores sensitive data. Verdict: `pass` (backup disabled; OR backup enabled but every sensitive store is excluded; OR the app stores nothing sensitive), `fail` (backup enabled and at least one sensitive store is not excluded), or `inconclusive`. (No N/A - every app has an effective backup posture.)

SHORT-CIRCUIT (decide first): if AndroidManifest.xml sets `android:allowBackup="false"` on <application>, backups are disabled -> PASS (quote the attribute).

Inputs (read these, do not infer)
1. AndroidManifest.xml (jadx/resources/AndroidManifest.xml): the <application> attributes `android:allowBackup` (absent => effectively true on most targetSdk), `android:fullBackupContent` (Android 11 and lower; references `@xml/<name>`), `android:dataExtractionRules` (Android 12+; references `@xml/<name>`), and any `android:backupAgent`.
2. The referenced rule files under res/xml/ (e.g. res/xml/backup_rules.xml, res/xml/data_extraction_rules.xml). Read their `<include>`/`<exclude>` entries. For data_extraction_rules, evaluate BOTH the `<cloud-backup>` and `<device-transfer>` sections - excluding from one but not the other still leaks via the other channel.

What counts as a sensitive data store (must be excluded)
SharedPreferences files holding secrets/tokens/credentials; databases (.db / SQLite / Room) containing PII or secrets; files under the app sandbox holding keys/tokens/PII; any DataStore used for sensitive data. Identify these from the code by cross-referencing the other MASVS-STORAGE tests (SharedPreferences 0287, files 0207, SQLite 0304, Room 0306, DataStore 0305). A backup config is only as good as whether it excludes the stores that actually hold secrets.

Evaluation (per the OWASP test)
FAIL if all of the following hold:
- effective `allowBackup` is true (explicitly, or by default because unset), AND
- neither a `fullBackupContent` rule (Android 11 and lower) nor a `dataExtractionRules` rule (Android 12+) excludes the sensitive stores - i.e. the attribute is missing, or the referenced XML does not `exclude` every sensitive store (for dataExtractionRules: in cloud-backup AND device-transfer).
PASS if `allowBackup="false"`, OR the rules exclude all sensitive stores, OR the app demonstrably stores nothing sensitive.

Evidence discipline
Quote the manifest attribute(s) and the exact `<exclude>`/`<include>` entries you rely on, with file + line. A disposition with no quoted config is an assertion -> `unverified`. If a referenced rule file cannot be located/read, that point is `unverified` (name it), not an assumption.

Procedure
1. Read AndroidManifest.xml; quote allowBackup, fullBackupContent, dataExtractionRules, backupAgent. Short-circuit PASS on allowBackup="false".
2. Resolve and read each referenced res/xml rule file; list the include/exclude entries and their scope (cloud-backup vs device-transfer for Android 12+).
3. Enumerate the app's sensitive data stores (sharedPreferences <name>, database <name>, file <path>/domain) from code evidence.
4. For each sensitive store, decide whether the rules exclude it from BOTH cloud backup and device transfer (Android 12+) or from fullBackupContent (Android 11 and lower). An unexcluded sensitive store -> Finding.
5. Key-value backup: if `android:backupAgent` (a `BackupAgent`/`BackupAgentHelper`) is declared, the backed-up file set is defined in that class's code (`onBackup` / `addHelper` / `FullBackupContent`), NOT the XML rules - the fullBackupContent/dataExtractionRules excludes may not govern it. Inspect the agent's backup logic for sensitive stores; if it cannot be resolved statically, mark the key-value-backup channel `unverified` (name the agent class). Do not assume the XML excludes cover it.
6. Conclude. Quote everything.

Output
JSON object as below; evidence_table uses the L1/L2 pattern.
- Finding: L1 row (a sensitive store is backed up) + L2 rows quoting the manifest flag and the missing/insufficient exclusion, plus the sensitive store (where it is written, why sensitive).
- Clean/PASS: L1 conclusion + L2 rows quoting `allowBackup="false"` (short-circuit) OR the exclusion entries covering each sensitive store, plus enumeration coverage.

```
{
  "id": "bkp-001",
  "description": "Finding: allowBackup is enabled and the credentials SharedPreferences file is not excluded from backup, so the user's stored auth token is included in cloud/device-transfer backups.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-manifest-flag",
  "description": "Manifest (quoted): <application android:allowBackup=\"true\" android:dataExtractionRules=\"@xml/data_extraction_rules\" ...> - backup enabled.",
  "reference": "jadx/resources/AndroidManifest.xml:24-31",
  "level": 2
},
{
  "id": "L2-missing-exclude",
  "description": "Rule gap (quoted): res/xml/data_extraction_rules.xml <cloud-backup> excludes only \"files/cache\"; the shared_prefs file \"auth_prefs.xml\" (which stores accessToken) is not excluded, and <device-transfer> has no exclude at all.",
  "reference": "res/xml/data_extraction_rules.xml:1-12",
  "level": 2
},
{
  "id": "L2-store-sensitive",
  "description": "Sensitive store (quoted): getSharedPreferences(\"auth_prefs\", MODE_PRIVATE).edit().putString(\"accessToken\", token) at SessionStore.java:40-44 - auth/session credential.",
  "reference": "jadx/sources/com/example/app/SessionStore.java:38-46",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0216",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "allowBackup=<value/default>; fullBackupContent/dataExtractionRules present? <...>. S sensitive stores enumerated, X excluded, N not excluded (findings). <one or two sentences naming the manifest flag, the rule file, and the unexcluded stores>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- This is the static approximation of a dynamic test: ALWAYS emit `needs_dynamic_testing: true`. The static counterpart is MASTG-TEST-0262.
- `fail`: effective allowBackup is true AND >=1 sensitive store is not excluded, with the manifest flag and the missing/insufficient exclusion quoted, and the sensitive store evidenced.
- `pass`: `allowBackup="false"` (quoted), OR every sensitive store is excluded from cloud-backup and device-transfer (Android 12+) / fullBackupContent (Android 11 and lower) (quoted), OR no sensitive store exists (enumeration shown).
- Unset `allowBackup` => treat as true (the platform default) and note the assumption.
- A declared `android:backupAgent` (key-value backup) defines its backed-up data in code, not the XML rules: evaluate the agent class, or mark that channel `unverified` if unresolved - clean XML excludes alone must not produce a `pass` while an unresolved custom backup agent exists.
- `unverified` rows name an unreadable rule file or an unresolved sensitive-store classification. Neither pass nor fail.
- `false_positive_risks` is for factors outside the APK only (server-side backup policy, MDM/enterprise restrictions, OEM backup behavior). In-APK gaps -> `unverified`.
- `inconclusive` if counts don't reconcile with L1 rows, if any false_positive_risk references in-APK config, or if any `fail` lacks its quoted manifest flag + missing exclusion.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
