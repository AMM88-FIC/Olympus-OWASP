MASTG-TEST-0355

maswe_id       MASWE-0064
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          References to Unauthorized Database Access through Content Providers (static)

What this test looks for
A content provider exported without adequate permission enforcement lets any app on the device query its underlying database (via `ContentResolver` or `adb shell content`), exposing sensitive data (PII, account details, internal config). This is a static evaluation of the manifest `<provider>` elements. Verdict: `pass` (no exported provider lacks adequate read/write permission protection for sensitive data), `fail` (>=1 provider is exported without `android:readPermission`/`android:writePermission`/`android:permission`, or with an inadequate protection level, exposing sensitive data), `n/a` (the app declares no exported content providers - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate `<provider>` elements. A provider is EXPORTED if `android:exported="true"`, or (legacy, `targetSdk < 17`) absent `android:exported` defaults to exported. If none are exported -> `n/a`/`pass` (state it).

Adequately protected vs not
Adequate: `android:readPermission` AND/OR `android:writePermission` (or the combined `android:permission`) with a `signature`/restricted protection level, scoped to the operations the provider supports. Inadequate: exported with NO read/write/permission attribute, OR a declared permission whose `protectionLevel` is `normal` (auto-granted to any app) or `dangerous` (user-grantable to any app). A provider with no `<provider>`-level protection but per-path `<path-permission>` covering all exposed data may be adequate - check.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the config it rests on.** Quote the `<provider>` element (export + read/write/permission + protectionLevel of any custom permission) and, where determinable, the sensitivity of the data it serves. No quoted config -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` (and the provider class for the data it serves), not an index record or line 1. `components.json`/`manifest_findings.json` may orient you; the verdict quotes the manifest.
3. **No finding by inference/hedge.** A finding requires quoting (a) the exported provider with no/inadequate permission. Data sensitivity strengthens severity; quote it where resolvable. "probably exposes data" with no quoted manifest entry is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If export/permission can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest: enumerate `<provider>` (`grep -nE "<provider|exported|readPermission|writePermission|android:permission|authorities|path-permission" jadx/resources/AndroidManifest.xml`). Determine which are exported and their read/write/permission attributes. Quote each.
2. For each exported provider, resolve the protection: missing read/write/permission -> finding; declared permission -> read its `<permission android:protectionLevel=...>` and classify (adequate signature/restricted vs inadequate normal/dangerous). Quote it.
3. For each exported, inadequately-protected provider, determine (where resolvable) whether the backing data is sensitive (read the provider class / `query` impl, the underlying table). Quote it. Note: per OWASP this fails on the missing/weak protection; data sensitivity affects severity.
4. Owner: app-declared (proprietary). A bundled library provider exported by the app is reported.
5. Conclude per provider: Finding (exported + missing/weak permission, quoted - note data sensitivity); Compliant (not exported / adequate read+write permission / fully covered by path-permissions); Unverified (export/permission unresolved).
6. Budget ~2-4 reads per provider (the manifest entry, the permission def, the provider class). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
FileProvider path oversharing is MASTG-TEST-0357; the dynamic query confirmation is MASTG-TEST-0356; activities/services/receivers are 0364/0365/0366. This test is exported CONTENT PROVIDERS guarding a database/data set.

Output
List **all** exported providers - one L1 row per provider with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group adequately-protected providers, but always break out every Finding and unverified provider individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the exported provider's missing/weak permission config (and data sensitivity where resolvable), plus owner.
- Compliant: L1 row plus an L2 showing not-exported / adequate read+write permission / path-permission coverage.

```
{
  "id": "prov-001",
  "description": "Finding (exported provider without permission): A content provider serving the user database is exported with no read/write permission, so any app can query PII.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-prov-manifest",
  "description": "Exported + unprotected (quoted): <provider android:name=\".UserProvider\" android:authorities=\"com.example.app.users\" android:exported=\"true\"/> at AndroidManifest.xml:60 - no android:readPermission/writePermission/permission.",
  "reference": "jadx/resources/AndroidManifest.xml:60",
  "level": 2
},
{
  "id": "L2-prov-data",
  "description": "Sensitive data (quoted): UserProvider.query maps content://com.example.app.users to the SQLite 'users' table (columns: email, phone, dob) at UserProvider.java:40-58 - any app can read user PII via ContentResolver. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/UserProvider.java:40-58",
  "level": 2
},
{
  "id": "prov-ok-001",
  "description": "Compliant: exported provider requires a signature read+write permission.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0355",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "P providers, E exported, A adequately protected (signature/restricted read+write), N findings (exported + missing/weak permission), C compliant, U unverified. Any exported provider without adequate protection? <no -> pass/n-a / yes -> fail>. <one or two sentences naming each finding and its data>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime query confirmation is MASTG-TEST-0356); it does not change `pass`/`fail`.
- `fail`: >=1 provider quoted as exported with NO `readPermission`/`writePermission`/`permission`, or with a declared permission whose `protectionLevel` is `normal`/`dangerous`. A finding stated with "likely"/"may" instead of the quoted manifest entry is INVALID -> `unverified`.
- **Read AND write.** A provider with only a read permission (writable by anyone), or only write (readable by anyone), is partially exposed - flag the unprotected direction. Quote both attributes.
- **Protection adequacy.** `signature`/restricted custom = adequate; `normal`/`dangerous`/none = not. Quote the `protectionLevel`.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (the data served is genuinely public) - in-APK facts (exported? permission? protectionLevel?) resolved by reading, unresolved -> `unverified`.
- `pass`: no exported provider lacks adequate read/write protection, with L2 coverage.
- `n/a`: no exported content providers (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK config, if a finding was dropped without evidence, or if any `fail` lacks its quoted exported+unprotected manifest entry.

Self-check before emitting (per finding)
For every Finding confirm: (1) the exported `<provider>` entry is quoted with its read/write/permission attributes; (2) the protection is missing or inadequate (`protectionLevel` quoted if a permission exists); (3) data sensitivity quoted where resolvable; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the manifest was read and exported providers enumerated, every provider's permission attributes and (where resolvable) data were read and quoted (unread -> `unverified`), no adequately-protected provider was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
