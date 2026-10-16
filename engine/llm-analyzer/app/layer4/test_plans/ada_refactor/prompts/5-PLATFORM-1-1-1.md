MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-2 (and MSTG-CODE-8 for injection)
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          Limit content-provider exposure and harden queries against injection (static)

What this test looks for
Exported content providers must be minimized (exposed only when necessary, and protected when exposed) and hardened against SQL injection. Two pillars: (A) EXPOSURE - the manifest shows minimal necessary exposure (a provider is not exported unnecessarily, and any exported provider is protected by an adequate permission and scoped URI grants); (B) INJECTION - the provider's query path uses parameterized queries / safe query building, not string concatenation of caller-supplied input. This is a static, inventory-style evaluation over the manifest and each provider's code. Verdict: `pass` (limited exposure AND injection hardening demonstrated), `fail` (a provider exported unnecessarily / without protection, OR an exposed provider injectable via SQLi), `n/a` (the app declares no content providers), or `inconclusive`.

Scope: EXPOSED (exported) providers. A provider that is not exported is not reachable by other apps - note it but it is out of scope for this test (its query path is not externally attacker-controlled).

EVIDENCE DISCIPLINE (applies to every row and both pillars)
1. **Every verdict-affecting disposition must quote the code/manifest it rests on - Finding, Compliant, AND dismissal alike.** A "Compliant" or "safe from SQLi" conclusion with no quoted query body is NOT acceptable; an asserted disposition with nothing quoted is downgraded to `unverified`. Specifically: you may NOT conclude a provider is SQLi-clean (or injectable) without quoting the relevant lines of its `query`/`insert`/`update`/`delete` body showing how `selection`/`projection`/`sortOrder`/URI segments are handled. "Uses parameterized queries" without the quoted call is an assertion, not evidence -> `unverified`.
2. **Read from the code, not the index.** The evidence index (`components.json`, etc.) locates candidates; it is not the basis for a disposition. Cite `jadx/sources/...:<line-range>` of the actual provider class body, not the index record or line 1 of the file.
3. **Unresolved determinacy is `unverified`, not a hedge.** Any question you cannot settle from this APK - a custom permission's protection level (it may be declared in a companion app), whether a path is sensitive, whether a method is reachable - makes the affected row `unverified` (deepest unresolved point named), NOT a confident Finding/Compliant with a caveat. `false_positive_risks` is for genuinely out-of-APK factors only; statements about in-APK or cross-APK facts you simply did not resolve are INVALID there and belong in `unverified` rows.

The good pattern (do not flag)
- A provider with `android:exported="false"` (explicit, or the default on `targetSdk >= 17`) and no intent-filter is not exposed -> out of scope, not a finding.
- An exported provider protected by a **signature**/`signatureOrSystem`-level permission (confirmed in the `<permission>` declaration) is minimally exposed -> Compliant on the exposure pillar.
- **Library providers configured per their design are Compliant**: `androidx.core.content.FileProvider` and subclasses (`exported="false"`, `grantUriPermissions="true"`, paths restricted via `<meta-data>`), `androidx.startup.InitializationProvider`, WorkManager's `androidx.work.impl.WorkManagerInitializer`/`...RemoteWorkManager`, lifecycle/process initializer providers, Firebase/Crashlytics init providers - these are the intended patterns, not findings.
- INJECTION good pattern: `SQLiteDatabase.query(table, projection, selection, selectionArgs, ...)` with `?` placeholders bound via `selectionArgs`; `rawQuery(sql, selectionArgs)` with placeholders; `SQLiteQueryBuilder` with `setStrict(true)` and/or a `setProjectionMap`; URI path segments validated against an allowlist / `UriMatcher` before use as table/column. These are hardened -> Compliant.

Source and manifest are ground truth. A provider/SQL evidence index is a candidate list only - confirm exported status, permissions, and every query/insert/update/delete/openFile body by reading `AndroidManifest.xml`, the `<permission>` declarations, and `jadx/sources/`. The `find_callers`/`find_callees` call graph gives *candidate* chains (useful for following helper query-builders), not confirmed flow.

Exposure failure modes (EXP)
- EXP1 - Exported & unprotected: `android:exported="true"` with no `android:permission`/`android:readPermission`/`android:writePermission`, or protected only by a permission DECLARED in this app at normal/dangerous level (broadly obtainable). Broadly accessible to any app. (A custom permission NOT declared in this app is `unverified`, not EXP1 - see the permission protection-level rule.)
- EXP2 - Implicit export: `exported` unset on `targetSdk <= 16` (providers default to exported=true there) -> possibly-unintended exposure. (On `targetSdk >= 17` an unset provider defaults to exported=false - not exposed.)
- EXP3 - Over-broad URI grants: `android:grantUriPermissions="true"` at the provider level with no `<grant-uri-permission>` path scoping / `<path-permission>`, on an exported provider - temporary grants to arbitrary paths.

Injection failure modes (SQLi) - on an EXPOSED provider
- SQLi1 - Concatenated SQL: `rawQuery`/`execSQL`/`query` where the caller-supplied `selection`, `projection`, `sortOrder`, or a URI path segment is concatenated into the SQL/where/table string instead of bound via `selectionArgs`.
- SQLi2 - Unconstrained query builder: `SQLiteQueryBuilder` used without `setStrict(true)` and without a `setProjectionMap`, passing caller `selection`/`projection` straight through.
- SQLi3 - URI segment as identifier: a URI path/last segment used directly as a table or column name without an allowlist / `UriMatcher` validation.

Permission protection-level rule
A custom permission counts as adequate protection only at signature/signatureOrSystem level - confirm with the `<permission android:protectionLevel=...>` declaration in this app's manifest (grep it). If the permission's level IS declared here: normal/dangerous -> inadequate (EXP1 Finding); signature/signatureOrSystem -> adequate (Compliant). If the permission is referenced but NOT declared in this app, its level cannot be determined statically (it may be declared by a companion app at signature level, or squattable at normal level) -> the exposure disposition is **`unverified`**, not a confident Finding and not a pass. Put the companion-app/squatting possibility in the `unverified` row's reasoning, NOT in `false_positive_risks`.

Procedure
1. Read `AndroidManifest.xml`: `targetSdkVersion`, every `<provider>` (authorities, `exported`, `permission`/`readPermission`/`writePermission`, `grantUriPermissions`, `<grant-uri-permission>`/`<path-permission>`, intent-filters), and all `<permission>` protectionLevels. Determine each provider's effective exported state (explicit, or the targetSdk default). If there are no `<provider>` declarations, the verdict is `n/a`.
2. For each EXPOSED provider, classify the class owner (proprietary vs library; package prefix is a hint only; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). Recognized library providers configured per their design are Compliant (good pattern).
3. **Read the provider class body for EVERY exported provider** - `query`, `insert`, `update`, `delete`, `openFile`, `call`, `bulkInsert`, and any helper query-builder/`getTable`/URI-routing methods (follow helpers once). For each one, determine whether caller-supplied input reaches a SQL string by concatenation (SQLi1-3) or is safely parameterized/validated, and QUOTE the relevant lines. The SQLi pillar must be evidenced separately for each exported provider with its own quoted body - you may not analyze one provider and assert the rest are "safe". Any exported provider whose query body you did not read and quote is `unverified` on the injection pillar (not silently Compliant). Do not conclude from the method's existence - read how the selection/projection/URI are used.
4. Cross exposure with injection: a provider is a Finding if EXP1-EX3 (over-exposed) OR (exposed AND SQLi1-3 in a body you read).
5. Conclude per provider: Finding (exported unnecessarily/unprotected, or exposed-and-injectable - with the body quoted for SQLi); Compliant (not exported / signature-protected / hardened / correctly-configured library provider); Unverified (export state, permission level, owner, or query body unresolved); documented candidate (see rules).
6. Budget ~2-4 reads per exposed provider (manifest entry, permission decl, query bodies) plus 1-2 call-graph hops for helpers. If the export state, permission level, owner, or a query body can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Provider logic fully inside native code or a no-source SDK can't be classified statically -> `unverified` (name the entry point). "Unnecessary" exposure is partly a design-intent question (the spec references a design document); statically, judge exposure by protection level and scoping - an exported provider with no adequate permission is over-exposed regardless of intent. The static verdict is made on what was determinable.

Output
List **all** EXPOSED content providers - one L1 row per provider with its exposure + injection disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant exposed providers by functionality (e.g. "signature-protected sync providers - 6") as one L1 row per group, but always break out every Finding, documented-candidate, and unverified provider as its own individual L1 row. Never sample findings. (Non-exported providers may be summarized in one line; they are out of scope.)
- Finding: L1 row plus L2 rows for the exposure evidence (manifest entry: exported/permission/grants, with the targetSdk default applied) and, for an injection finding, the query body quoted showing concatenation of caller input.
- Compliant: L1 row plus L2 for the protection (signature permission / not exported / library good-pattern) and the hardened query (parameterized/strict).
- Group: L1 summary plus an L2 naming references and the shared protection/hardening.

```
{
  "id": "cp-001",
  "description": "Finding (EXP1 exported & unprotected + SQLi1 concatenated selection): The NotesProvider is exported with no permission and concatenates the caller's selection into a rawQuery, allowing any app to read/inject the notes database.",
  "reference": "AndroidManifest.xml (provider .NotesProvider)",
  "level": 1
},
{
  "id": "L2-NotesProvider-exposure",
  "description": "Exposure: <provider android:name=\".db.NotesProvider\" android:authorities=\"com.example.app.notes\" android:exported=\"true\"> with NO android:permission/readPermission/writePermission and grantUriPermissions unset. targetSdk=31 so the export is explicit. Any installed app can call it.",
  "reference": "AndroidManifest.xml:88-92",
  "level": 2
},
{
  "id": "L2-NotesProvider-sqli",
  "description": "Injection (body read): NotesProvider.query builds String sql = \"SELECT * FROM notes WHERE \" + selection at line 54 and calls db.rawQuery(sql, null) at line 55 - the caller-supplied selection is concatenated, not bound via selectionArgs. SQL injection.",
  "reference": "jadx/sources/com/example/app/db/NotesProvider.java:48-60",
  "level": 2
},
{
  "id": "cp-fileprovider",
  "description": "Compliant: androidx FileProvider configured per design - not exported, scoped URI grants.",
  "reference": "AndroidManifest.xml (provider FileProvider)",
  "level": 1
},
{
  "id": "L2-fileprovider-coverage",
  "description": "Good pattern: <provider android:name=\"androidx.core.content.FileProvider\" android:exported=\"false\" android:grantUriPermissions=\"true\"> with <meta-data> pointing to res/xml/file_paths.xml (path-restricted). Library provider, intended configuration.",
  "reference": "AndroidManifest.xml:70-78",
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
  "rationale": "P providers declared, X exported/in-scope, N findings (by mode EXP1..EXP3/SQLi1..SQLi3), C compliant, U unverified, plus I non-exported (out of scope). targetSdk + permission posture: <summary>. <one or two sentences naming the providers, authorities and issues>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only where the query/exposure is runtime-driven (recorded `unverified`). It does not change `pass`/`fail`.
- `fail`: >=1 exposed provider with (a) an L2 row showing EXP1-EXP3 (exported with inadequate/absent permission, implicit export on targetSdk<=16, or over-broad grants) OR an L2 row showing SQLi1-SQLi3 with the query BODY quoted (caller input concatenated into SQL); plus the manifest exposure evidence. A SQLi finding requires the provider to be exposed AND the body read.
- **Read the body before flagging SQLi; do not flag library good-patterns.** A provider is a SQLi finding only if a query body you read concatenates caller input; parameterized/strict/validated bodies are Compliant. A correctly-configured `FileProvider`/library init provider is Compliant - do not flag it.
- **targetSdk default + permission level.** Apply the provider export default (exported=true on targetSdk<=16, false on >=17). A custom permission protects only at signature/signatureOrSystem level confirmed in this app's `<permission>` declaration. A no-permission or in-app-declared-normal/dangerous export is EXP1 (Finding); an export protected by a custom permission NOT declared in this app is `unverified` (level indeterminate), never a confident Finding or pass.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` is for out-of-APK factors only (design-documented necessity of an export, permission defined by a companion app at a confirmed level, runtime-built queries) - in-APK facts (is the selection concatenated? is the provider exported?) must be resolved by reading code/manifest, not hedged here.
- A bypass/over-exposure you cannot resolve (obfuscated routing, query built via reflection, owner/export unclear) is `unverified`, not a clean pass; a reflection/dynamic-dispatch doubt is an in-APK gap (`unverified`), never a `false_positive_risks` entry.
- `pass`: providers exist and every exposed provider is minimally exposed (not exported, or signature-protected, or a correctly-configured library provider) AND injection-hardened (parameterized/strict/validated), with L2 coverage and the targetSdk/permission posture summarized.
- `n/a`: no `<provider>` is declared (manifest read; state this).
- Documented exception: a design-documented justification that an export is necessary (still must be protection-scoped) is a documentation fact outside the APK - record a borderline still-protected export as a "documented candidate"; an unprotected export is a Finding regardless.
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped/out-of-scoped without evidence, or if any `fail` lacks its exposure + (for SQLi) body-quote L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) exposure is shown from the manifest with the targetSdk default applied and the permission level checked against the `<permission>` declaration; (2) for SQLi, you READ and quoted the query body showing caller-input concatenation (not the method's existence); (3) the class owner was decided from evidence (OEM-aware; obfuscated -> proprietary) and it is not a correctly-configured library provider. If any is missing, downgrade to `unverified` or Compliant.
Evidence-discipline gate (all rows): every Compliant/SQLi-clean row quotes the actual query body (`jadx/sources/...:lines`), not the index or line 1; an asserted-without-quote disposition becomes `unverified`. Every exported provider has its OWN quoted SQLi body; any exported provider whose body you did not read is `unverified` on the injection pillar - you may not pass it. An undeclared-custom-permission exposure is `unverified` (companion-app/squatting reasoning goes in that row, not `false_positive_risks`).
Before any `pass`: confirm no exported provider was concluded clean on either pillar without a quoted body, and no `false_positive_risks` entry describes an in-APK or cross-APK fact you simply did not resolve (convert those to `unverified`). Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.