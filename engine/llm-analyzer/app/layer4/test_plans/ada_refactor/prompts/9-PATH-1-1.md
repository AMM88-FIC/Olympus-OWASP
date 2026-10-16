MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-2
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          Path traversal via untrusted URIs reaching exported IPC entry points

What this test looks for
A malicious app on the same device can craft a content URI whose `_display_name`, path segments, or query parameters contain path-traversal sequences. When the app under test accepts that URI through an exported component and uses the URI or its derived metadata to construct a file-system path without canonicalization, the attacker can write files outside the intended directory. The damaging form overwrites executable resources in the app's private data directory (`.so`, `.dex`, code-cache, shared-prefs), yielding code execution under the app's UID.

Source code is the ground truth. Evidence files are indices into the code, useful for finding candidates and constraining search but not authoritative. A finding or a clean must be confirmed by reading the source — extractors miss things (interface dispatch, obfuscated wrappers, activity-aliases). The verdict is only as strong as the source reads behind it.

Procedure

1. Enumerate exported proprietary components from `components.json`:
   ```
   match_evidence_records(
     file="components.json",
     filters={
       "exported.effective": "true",
       "name": "^(?!(androidx|com\\.google|com\\.facebook|com\\.bumptech|kotlin|kotlinx|okhttp3|okio|retrofit2|com\\.squareup|io\\.reactivex|com\\.amazon|com\\.adjust|com\\.appsflyer|com\\.crashlytics|io\\.branch|io\\.intercom|zendesk|com\\.zendesk|com\\.mixpanel|com\\.segment|com\\.onesignal|com\\.my\\.target|net\\.openid\\.appauth)\\.).+"
     },
     limit=100
   )
   ```

2. For each component, derive the handler method(s):
   - Activities and activity-aliases: `onCreate`, `onNewIntent`, `onActivityResult`. Aliases delegate to their `targetActivity`; analyze the target's handlers.
   - Services: `onStartCommand`, `onBind`, `onHandleIntent`.
   - Receivers: `onReceive`.
   - Providers: `query`, `insert`, `update`, `delete`, `openFile`, `openAssetFile`, `openTypedAssetFile`, `call`.

3. For each handler, walk the call tree forward with `find_callees(methods=[...], max_depth=8)`. The call graph identifies *candidate* sinks but does not confirm them. Reaching a sink in `transitive_callees_by_class.platform` means the handler's call tree visits that sink somewhere; it does not mean attacker input flows to it.

4. **Read the source.** For every in-scope component, read the handler source and follow the attacker-input value through every method call, field assignment, and helper invocation until it either (a) reaches a file-system sink as an argument, (b) is validated by a defense, or (c) terminates harmlessly (parameterized DB query, allowlist match, replaced by a constant). Use `read_file` with line ranges to read specific methods, not whole files. Follow callback patterns (`new MyCallback(this)` passed to RxJava `subscribe`, `Executor.submit`, etc.) manually by finding the callback class and reading its `apply` / `accept` / `run` / `onSuccess` method.

5. Classify each defense observed on the path:
   - Sufficient: `File.getCanonicalPath()` combined with a `startsWith(baseDir + File.separator)` containment check on the canonicalized result. Pay attention to return-value direction — a method that returns `true` when the path is *outside* the base is an exclusion check, not a containment check. Also sufficient: exact-string or strict regex allowlist applied before path construction, basename reduction that rejects on change.
   - Insufficient: `replaceAll("..")`, `replace("..", "")`, `contains("..")`, `startsWith` on the raw input rather than the canonicalized result, `startsWith` after `getAbsolutePath()` (does not resolve `..`), exception handlers that fail open.
   - None: direct concatenation with no validation between source and sink.

Budget approximately 3-5 source reads per high-priority component (activities and aliases with `content`/`file` scheme intent filters, providers with no permission), 1-2 per low-priority component (no intent filters or filters without content/file schemes). If the source walk exceeds the budget without reaching a sink, mark the row `unverified` with the deepest unresolved call site named.

Sinks to look for

In `transitive_callees_by_class.platform` from `find_callees`, then confirmed in source by argument-level data flow:

- File construction: `java.io.File.<init>`, `java.nio.file.Paths.get`
- File streams: `java.io.FileInputStream.<init>`, `java.io.FileOutputStream.<init>`, `java.io.RandomAccessFile.<init>`
- NIO file ops: `java.nio.file.Files.copy`, `Files.move`, `Files.write`, `Files.newOutputStream`, `Files.newInputStream`
- Content resolver file ops: `android.content.ContentResolver.openFileDescriptor`, `openInputStream`, `openOutputStream`
- Storage Access Framework: `androidx.documentfile.provider.DocumentFile.createFile`, `renameTo`, `delete`
- URI metadata extraction (the Dirty Stream entry point): `android.content.ContentResolver.query` with a projection containing `_display_name`, `_data`, `_size`, or other `OpenableColumns` — confirmed by reading the source's second argument to `query`.

Out-of-scope rule
A component whose `permission` attribute references a signature-level or signatureOrSystem-level permission is out of scope. Confirm the protection level with `grep` on AndroidManifest.xml for the `<permission>` declaration. Custom permissions whose declaration is absent from this app's manifest may be defined by other apps at any protection level; treat these as in-scope.

Output

Emit a JSON object with the structure shown below. The evidence_table follows the same L1/L2 pattern as other MASTG tests: one L1 row per finding/clean conclusion, plus one or more L2 rows naming the specific source ranges that justified it.

Findings require L2 rows for:
- The handler entry point (where attacker input is read)
- Each propagation step that's not obvious from the source already cited
- The sink (the specific line of the file-system call receiving attacker input)
- The defense observed (if any) and its insufficiency reason

Cleans require L2 rows for:
- The handler entry point
- The terminus (where the attacker input stops flowing toward a sink and why)

Example evidence_table structure (placeholder names — illustrating the L1/L2 pattern, not the answer to any specific APK):

```
{
  "id": "cmp-XXX",
  "description": "Finding: Exported activity com.example.app.SomeActivity is vulnerable to path traversal. It processes content URIs, extracts the '_display_name' field, and uses it directly in file path construction.",
  "reference": "components.json#cmp-XXX",
  "level": 1
},
{
  "id": "L2-SomeActivity-source-1",
  "description": "Source code confirmation (Entry point): The onCreate method reads getIntent().getData() and forwards it to the handleUri helper.",
  "reference": "jadx/sources/com/example/app/SomeActivity.java:42-58",
  "level": 2
},
{
  "id": "L2-SomeActivity-source-2",
  "description": "Source code confirmation (Propagation): The handleUri method passes the URI string to UriHelper.parseAndRoute via an RxJava callback (the callback class was identified and its apply method was read).",
  "reference": "jadx/sources/com/example/app/SomeActivity.java:78-95",
  "level": 2
},
{
  "id": "L2-SomeActivity-source-3",
  "description": "Source code confirmation (Source of taint): The UriHelper.parseAndRoute method queries the content resolver for the '_display_name' column and stores the result in wrapper.fileName, which is attacker-controlled.",
  "reference": "jadx/sources/a/b/c/UriHelper.java:23-45",
  "level": 2
},
{
  "id": "L2-SomeActivity-source-4",
  "description": "Source code confirmation (Sink): The FileOps.writeOut method constructs a new File using baseDir concatenated with the tainted wrapper.fileName, without canonicalization. This is the path traversal sink at line 67.",
  "reference": "jadx/sources/z/x/y/FileOps.java:60-75",
  "level": 2
},
{
  "id": "L2-SomeActivity-source-5",
  "description": "Source code confirmation (Insufficient Defense): The PathFilter.scrub method called at FileOps.writeOut:62 applies String.replaceAll(\"..\") which is a denylist defeated by percent-encoding, double-encoding, and Unicode normalization.",
  "reference": "jadx/sources/q/r/s/PathFilter.java:8-20",
  "level": 2
}
```

For an alias of an already-analyzed component, the row references the target's analysis rather than duplicating it:

```
{
  "id": "cmp-YYY",
  "description": "Finding: Exported activity-alias com.example.app.SomeActivityAlias targets the vulnerable com.example.app.SomeActivity (cmp-XXX). Same data flow; same finding.",
  "reference": "components.json#cmp-YYY",
  "level": 1
}
```

For a clean (showing that attacker input terminates without reaching a file sink):

```
{
  "id": "cmp-ZZZ",
  "description": "Clean: Exported provider com.example.app.AnotherProvider accepts attacker URIs in its query method but uses them only as parameterized SQLite selectionArgs. No file-system operations are reachable from this handler.",
  "reference": "components.json#cmp-ZZZ",
  "level": 1
},
{
  "id": "L2-AnotherProvider-source-1",
  "description": "Source code confirmation (Entry and terminus): The query method reads selectionArgs[0] and passes it as the third argument to SQLiteDatabase.query (parameterized binding). No File construction or file-stream APIs are called from this method or its helpers.",
  "reference": "jadx/sources/com/example/app/AnotherProvider.java:30-78",
  "level": 2
}
```

Full output object:

```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... rows as above ... ],
  "rationale": "N exported components enumerated, M findings, K clean, S out-of-scope, U unverified. <one or two sentences summarizing the chain in plain English, naming the specific classes and methods involved>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules

- A finding requires at least one L2 row citing the source line where attacker input reaches a sink. "Reaches a sink" means the tainted value is passed as an argument to a sink call — not merely that the handler's call tree visits a sink somewhere.
- A clean requires at least one L2 row citing where attacker input terminates without reaching a sink, and what specifically stops it.
- For any defense claimed sufficient, the L2 description must state what the defense's return value means and how it would behave on path-traversal input. A `getCanonicalPath` + `startsWith` defense that returns `true` when the path is *outside* the base directory is an exclusion check, not a containment check, and is not sufficient.
- An `unverified` row must name the deepest unresolved call site (`<ClassFQN>.<method>:<line>`).
- `false_positive_risks` is reserved for OEM-specific framework behavior, runtime config not in the bytecode, or hardware preconditions. Entries describing in-APK code (truncated analysis, unread methods) are invalid — those go in `unverified` rows.
- The verdict is `inconclusive` if the rationale's component count does not match `len(evidence_table)`'s L1 row count, if any `false_positive_risks` entry references in-APK code, or if any finding lacks the L2 rows specified above.

If you reach 39 tool iterations, you MUST provide an answer with the current information you have. A full iteration is comprised of:
- You make your tool calls
- You receive a response for all made tool calls from the user