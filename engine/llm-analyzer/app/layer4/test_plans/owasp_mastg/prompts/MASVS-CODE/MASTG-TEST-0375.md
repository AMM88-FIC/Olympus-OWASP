MASTG-TEST-0375

maswe_id       MASWE-0083
masvs_v2_id    MASVS-CODE-4
platform       android
title          Missing Validation of Data Returned from Implicit Intents (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0375 has a static AND a dynamic part; the engine implements the STATIC part directly and approximates the dynamic part. The dynamic test installs a malicious responder app and hooks file constructors to observe path traversal at runtime. This static engine cannot run an attacker app, so it performs the static analysis the test prescribes - find `onActivityResult` handlers that consume intent-returned data (URIs, filenames, metadata) and check whether the app validates/sanitizes it before using it in sensitive operations. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only providing a malicious intent response at runtime proves whether path traversal / arbitrary file access actually occurs.

What this test looks for
When the app requests data via an implicit intent (e.g. `GET_CONTENT`, `OPEN_DOCUMENT`, or a custom action), ANY app can respond, returning a malicious URI (`file://` instead of `content://`) or metadata (filenames with `../`). If the app trusts the returned data without validation and uses it in a sensitive operation (file I/O, dynamic code loading), it risks arbitrary file read/write or code execution. This is a static, taint-style evaluation: intent-result data -> sensitive operation WITHOUT validation. Verdict: `pass` (intent-result data is validated/sanitized before sensitive use, or never used sensitively), `fail` (>=1 intent-result value reaches a sensitive operation with no validation), `n/a` (the app starts no activities for result / consumes no returned intent data), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `onActivityResult`/`registerForActivityResult`/`startActivityForResult`. If NONE appear -> `n/a` (state the search). Runtime exploitation is still flagged via the forced `needs_dynamic_testing`.

Sensitive operations (where unvalidated intent-result data is dangerous)
File I/O on the returned URI/path (`new File(path)`, `FileInputStream`/`FileOutputStream`, `openInputStream(uri)` then copying to an internal path using a returned filename), dynamic code loading (`DexClassLoader`/`PathClassLoader` on a returned path), or building an internal destination path from a returned filename.

Required validation (Compliant)
- URI scheme check: confirm the URI is `content://` (the expected scheme) and reject `file://`/other schemes.
- Filename sanitization: reject `../` / path-traversal sequences; take only the basename.
- Canonical-path containment: resolve the final path and confirm it stays within the intended directory (`getCanonicalPath().startsWith(intendedDir)`).
Any one relevant check applied before the sensitive use is Compliant for that flow; the right check depends on how the data is used.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the intent-result consumption (`onActivityResult`/result callback), the sensitive operation it flows into, AND the validation (Compliant) or its absence (Finding). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) intent-returned data and (b) its use in a sensitive operation with no validation. "probably unsafe" with no quoted flow is NOT static evidence -> `unverified` (flag for the dynamic test).
4. **Unresolved determinacy is `unverified`, not a hedge.** If the data flow or the presence of validation can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate result handlers: `grep -rEn "onActivityResult|registerForActivityResult|ActivityResultLauncher|startActivityForResult|GET_CONTENT|OPEN_DOCUMENT|data\.getData\(|getStringExtra|getParcelableExtra" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each handler, identify the returned data (URI via `data.getData()`, filename/metadata from extras or `DocumentFile`/cursor) and trace it to any sensitive operation (file I/O, classloading, path building). Quote source + sink.
3. For each flow into a sensitive operation, check for the relevant validation (scheme check, `../` rejection, canonical-path containment) before use. Absent -> finding; present and adequate -> Compliant. Quote it.
4. Classify owner (proprietary vs library; OEM-aware; obfuscated -> proprietary).
5. Conclude per flow: Finding (intent-result data + sensitive op + no validation, quoted); Compliant (validated, or no sensitive use); Unverified (flow/validation unresolved -> confirm at runtime).
6. Budget ~3-5 reads per flow (the result handler, the data extraction, the sensitive op, any validation). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether a malicious response actually achieves traversal/arbitrary access is runtime-only - hence the forced `needs_dynamic_testing`. Flows through native code or a no-source SDK -> `unverified` (name the entry point). Sending sensitive data OUT via implicit intents is MASTG-TEST-0374; this test is validating data coming BACK.

Output
List **all** intent-result flows reaching sensitive operations - one L1 row per flow with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant validated/non-sensitive flows, but always break out every Finding and unverified flow individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the intent-result data, the sensitive operation, and the missing validation, plus owner.
- Compliant: L1 row plus an L2 quoting the scheme/traversal/canonical-path validation, or a non-sensitive use.

```
{
  "id": "ir-001",
  "description": "Finding (unvalidated intent-result used in file I/O): The app copies a file using a filename returned by a GET_CONTENT response without rejecting path traversal, enabling writes outside the intended directory.",
  "reference": "jadx/sources/com/example/app/ImportActivity.java",
  "level": 1
},
{
  "id": "L2-ir-source",
  "description": "Intent-result data (quoted): onActivityResult -> Uri uri = data.getData(); String name = queryDisplayName(uri); at ImportActivity.java:40-46 - URI + filename from whichever app responded.",
  "reference": "jadx/sources/com/example/app/ImportActivity.java:40-46",
  "level": 2
},
{
  "id": "L2-ir-sink",
  "description": "Sensitive op, no validation (quoted): File out = new File(getFilesDir(), name); copy(getContentResolver().openInputStream(uri), new FileOutputStream(out)); at lines 50-56 - 'name' is used directly to build the destination path; no '../' rejection, no canonical-path containment, no scheme check on uri. Owner: com.example.app (proprietary). Runtime confirmation required.",
  "reference": "jadx/sources/com/example/app/ImportActivity.java:50-56",
  "level": 2
},
{
  "id": "ir-ok-001",
  "description": "Compliant: returned filename sanitized to its basename and the resolved path is confined to the target dir.",
  "reference": "jadx/sources/com/example/app/SafeImport.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0375",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "F intent-result flows, S reaching a sensitive operation, V validated (scheme/traversal/canonical-path), N findings (unvalidated), U unverified. Any intent-result data used sensitively without validation? <no -> pass/n-a / yes -> fail>. <one or two sentences>; runtime malicious-response test confirms.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of (the dynamic part of) the test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that a malicious-response runtime test is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 flow with (a) an L2 quoting intent-returned data AND (b) an L2 quoting its use in a sensitive operation with no relevant validation. A finding stated with "likely"/"may" instead of the quoted flow is INVALID -> `unverified`.
- **Validation clears it.** A scheme check (content:// expected), `../` rejection / basename-only, or canonical-path containment applied before the sensitive use is Compliant for that flow.
- **Sensitive operation required.** Intent-result data used non-sensitively (just displayed) is Compliant. The finding needs a file-I/O / classloading / path-building sink.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (sensitive use? validation?) resolved by reading, unresolved -> `unverified`.
- `pass`: intent-result data is validated before sensitive use, or never used sensitively, with L2 coverage.
- `n/a`: the app consumes no returned intent data (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its intent-result + sensitive-op + missing-validation L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the intent-result data (URI/filename/metadata) is quoted; (2) the sensitive operation it flows into is quoted; (3) no relevant validation (scheme/traversal/canonical-path) gates the use; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the result-handler search was performed (n/a state it), every sensitive flow's validation state was read and quoted (unresolved -> `unverified`), no validated/non-sensitive flow was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
