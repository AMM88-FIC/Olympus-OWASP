MASTG-TEST-0357

maswe_id       MASWE-0064
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          References to Oversharing of File-Based Content Providers - FileProvider path too broad (static)

What this test looks for
A `FileProvider` (or custom file-serving provider) whose path configuration exposes too much of the filesystem lets external callers open private files through `content://` URIs. The danger is an overly-broad `<paths>` config (`<root-path>`, `path="/"`, `path="."`, `path=""`) combined with export and/or `FileProvider.getUriForFile()` called on attacker-controlled input. This is a static evaluation of the provider's manifest entry, its `<paths>` resource, and the code that builds URIs. Verdict: `pass` (FileProviders expose only narrow, intended directories with adequate access control), `fail` (>=1 FileProvider's path config allows access outside the intended shared directory, or builds URIs from attacker-controlled input without protection), `n/a` (the app uses no file-based content provider), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `FileProvider`/`androidx.core.content.FileProvider`/`getUriForFile`/`android.support.v4.content.FileProvider` and `<provider>` entries referencing `META-DATA` `android.support.FILE_PROVIDER_PATHS`. If NONE appear -> `n/a` (no file-based provider; state the search).

Overly-broad path configs (finding indicators)
In the `<paths>` XML (referenced by the provider's `<meta-data android:name="android.support.FILE_PROVIDER_PATHS">`):
- `<root-path .../>` - maps the device root `/`.
- any path element (`<files-path>`, `<external-path>`, `<cache-path>`, `<external-files-path>`, ...) with `path="/"`, `path="."`, `path=""`, or a path that resolves to a whole sensitive root (e.g. the entire `files/` containing secrets).
- `<external-path path="." />` exposing all external storage.
Narrow, named subdirectories (e.g. `<files-path name="images" path="shared_images/"/>`) are Compliant.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the config/code it rests on.** Quote the `<provider>` entry, the `<paths>` element(s), and any `getUriForFile(...)` call on untrusted input. No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>`, `jadx/resources/res/xml/<paths>.xml:<line>`, and `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the overly-broad path element (or attacker-controlled `getUriForFile`) and (b) the provider's export/access posture. "probably overshares" with no quoted `<paths>` is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the `<paths>` resource can't be read, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Locate FileProviders: `grep -rEn "FileProvider|getUriForFile|FILE_PROVIDER_PATHS" jadx/sources/ jadx/resources/`. Find the `<provider>` manifest entry and its `<meta-data>` -> the `<paths>` resource file. If none -> short-circuit `n/a` (state the search).
2. Read the `<paths>` resource: enumerate every path element. Flag overly-broad ones (`<root-path>`, `path="/"`/`.`/`""`, whole-root mappings). Quote them. Narrow named subdirs -> Compliant.
3. Read the code building URIs: is `getUriForFile(...)` called with attacker-controlled input (URI query params, intent extras, user input) without validating the resolved path stays within the intended dir? Quote it. Check the provider's export + `android:permission`/`grantUriPermissions` posture (a FileProvider sets `grantUriPermissions=true` by definition; the concern is the path scope + how URIs are granted).
4. Owner: app-declared (proprietary).
5. Conclude per provider: Finding (overly-broad path config, or attacker-controlled getUriForFile, quoted); Compliant (narrow named paths + controlled URI building); Unverified (paths/code unresolved).
6. Budget ~2-4 reads per provider (the manifest entry, the paths xml, the getUriForFile site). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Database-backed providers are MASTG-TEST-0355/0356. This test is FILE-based providers (FileProvider path oversharing). Provider/URI logic in native code -> `unverified`.

Output
List **all** file-based providers - one L1 row per provider with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group narrow-path providers, but always break out every Finding and unverified provider individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the overly-broad `<paths>` element (and/or attacker-controlled `getUriForFile`) and the provider posture, plus owner.
- Compliant: L1 row plus an L2 showing narrow named paths + controlled URI building.

```
{
  "id": "fp-001",
  "description": "Finding (FileProvider exposes the whole files directory): The provider's paths config maps the entire internal files/ root, so a content:// URI can reach any private file including secrets.",
  "reference": "jadx/resources/res/xml/file_paths.xml",
  "level": 1
},
{
  "id": "L2-fp-paths",
  "description": "Overly-broad path (quoted): <paths><files-path name=\"all\" path=\".\"/></paths> at res/xml/file_paths.xml:2-4 - path=\".\" maps the entire files/ directory (incl. token.dat, db files).",
  "reference": "jadx/resources/res/xml/file_paths.xml:2-4",
  "level": 2
},
{
  "id": "L2-fp-uri",
  "description": "Attacker-controlled URI (quoted): Uri u = FileProvider.getUriForFile(ctx, AUTH, new File(filesDir, request.getStringExtra(\"name\"))); grantUriPermission to the caller at ShareActivity.java:40-46 - the file name comes from an intent extra, so a caller can request any file under files/. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/ShareActivity.java:40-46",
  "level": 2
},
{
  "id": "fp-ok-001",
  "description": "Compliant: FileProvider exposes only a named shared_images subdirectory.",
  "reference": "jadx/resources/res/xml/file_paths.xml",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0357",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "F file-based providers, B with overly-broad paths (root-path / '.' / '/' / ''), I building URIs from attacker-controlled input, N findings, C compliant (narrow named paths), U unverified. Any FileProvider oversharing? <no -> pass/n-a / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 FileProvider with (a) an L2 quoting an overly-broad `<paths>` element (`<root-path>`, `path="/"`/`"."`/`""`, whole-root) OR a `getUriForFile(...)` on attacker-controlled input without path validation, AND (b) the provider posture quoted. A finding stated with "likely"/"may" instead of the quoted `<paths>`/code is INVALID -> `unverified`.
- **Path scope is the test.** Narrow, named subdirectories are Compliant; whole-root mappings are findings. `grantUriPermissions=true` is normal for a FileProvider - the concern is WHAT the paths expose and how URIs are derived.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (which paths? how are URIs built?) resolved by reading, unresolved -> `unverified`.
- `pass`: FileProviders expose only narrow intended dirs with controlled URI building, with L2 coverage.
- `n/a`: no file-based content provider (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK evidence, if a finding was dropped without evidence, or if any `fail` lacks its `<paths>`/getUriForFile + posture L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the overly-broad `<paths>` element (or attacker-controlled `getUriForFile`) is quoted; (2) the provider's export/permission posture is quoted; (3) the exposure reaches outside the intended shared directory; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the FileProvider search was performed (n/a state it), the `<paths>` resource was read and every path element quoted (unread -> `unverified`), the URI-building code was read where present, no narrow-path provider was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
