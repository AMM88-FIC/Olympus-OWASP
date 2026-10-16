MASTG-TEST-0256

maswe_id       MASWE-0117
masvs_v2_id    MASVS-PRIVACY-3
platform       android
title          Missing Permission Rationale - no explanation before requesting permissions (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0256 as a `status: placeholder` (no procedure body; note: "checks if the app does not provide a rationale for requesting permissions"). This prompt implements the best-effort static detection: whether the app, when requesting runtime (dangerous) permissions, provides a rationale to the user - i.e. calls `shouldShowRequestPermissionRationale(...)` and shows an explanation - rather than requesting cold.

What this test looks for
For transparency, an app requesting runtime permissions should explain WHY before/when requesting (Android's rationale flow). This test checks whether the app handles permission rationale for the dangerous permissions it requests at runtime. Verdict: `pass` (the app requests runtime permissions with rationale handling), `fail` (the app requests dangerous permissions at runtime with NO rationale handling), `n/a` (the app requests no runtime permissions - declares none dangerous, or targets a pre-runtime-permission model only), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for runtime-permission request APIs. If the app requests no dangerous permissions at runtime -> `n/a` (state it).

Runtime-permission request + rationale APIs
- Request: `requestPermissions(...)`, `ActivityCompat.requestPermissions(...)`, `ActivityResultContracts.RequestPermission`/`RequestMultiplePermissions` (`registerForActivityResult`), Compose `rememberLauncherForActivityResult` for permissions, or accompanist-permissions.
- Rationale: `shouldShowRequestPermissionRationale(...)` / `ActivityCompat.shouldShowRequestPermissionRationale(...)`, and showing an explanatory UI (dialog/snackbar) before/after it returns true. Accompanist `PermissionState.status.shouldShowRationale`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the runtime permission request AND the rationale handling (compliant) or its absence (finding). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a runtime dangerous-permission request AND (b) that no `shouldShowRequestPermissionRationale` / rationale UI accompanies it. "probably no rationale" without searching is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the request/rationale flow can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate runtime permission requests: `grep -rEn "requestPermissions|RequestPermission|RequestMultiplePermissions|shouldShowRequestPermissionRationale|shouldShowRationale|registerForActivityResult" jadx/sources/`. If no runtime requests for dangerous permissions -> short-circuit `n/a` (state it).
2. For the dangerous permissions requested at runtime, check for rationale handling near the request (a `shouldShowRequestPermissionRationale` check and an explanatory UI). Quote it (compliant) or show its absence (finding).
3. Treat the app holistically: if it requests several dangerous permissions and handles rationale for them (or has a central rationale flow), Compliant; if it requests dangerous permissions cold with no rationale anywhere, finding.
4. Owner: app (proprietary).
5. Conclude: Finding (runtime dangerous request without rationale handling, quoted); Compliant (rationale handled); Unverified (flow unresolved).
6. Budget ~2-4 reads (the request sites, the rationale checks). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether the rationale TEXT is meaningful/accurate is a manual/runtime review; this static test checks for the PRESENCE of rationale handling around runtime requests. Permission minimization is MASTG-TEST-0254/0255. Request flows in native/no-source code -> `unverified`.

Output
A small table: whether runtime dangerous-permission requests are accompanied by rationale handling.
- Finding: L1 row plus L2 rows quoting the runtime permission request and the absence of rationale handling, plus owner.
- Compliant: L1 row plus an L2 quoting the `shouldShowRequestPermissionRationale` check + explanatory UI.

```
{
  "id": "rat-001",
  "description": "Finding (no permission rationale): The app requests ACCESS_FINE_LOCATION at runtime with no shouldShowRequestPermissionRationale check or explanation shown.",
  "reference": "jadx/sources/com/example/app/MapActivity.java",
  "level": 1
},
{
  "id": "L2-rat-req",
  "description": "Cold request (quoted): ActivityCompat.requestPermissions(this, new String[]{ACCESS_FINE_LOCATION}, RC_LOC); at MapActivity.java:40 - requested directly.",
  "reference": "jadx/sources/com/example/app/MapActivity.java:40",
  "level": 2
},
{
  "id": "L2-rat-norat",
  "description": "No rationale (quoted searches): grep for shouldShowRequestPermissionRationale / shouldShowRationale across jadx/sources/ returns no match; no explanatory dialog precedes the request. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/",
  "level": 2
},
{
  "id": "rat-ok-001",
  "description": "Compliant: the app shows a rationale before requesting contacts.",
  "reference": "jadx/sources/com/example/app/Perms.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0256",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R runtime dangerous-permission requests, H with rationale handling (shouldShowRequestPermissionRationale + UI), N findings (cold requests, no rationale), U unverified. Any request without rationale? <no -> pass / n-a if no runtime requests / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 runtime dangerous-permission request with (a) an L2 quoting the request AND (b) an L2 showing no rationale handling (no `shouldShowRequestPermissionRationale`, no explanatory UI). A finding stated with "likely"/"may" instead of the quoted request + empty rationale search is INVALID -> `unverified`.
- **Rationale handling clears it.** A `shouldShowRequestPermissionRationale` check with an explanatory UI (even a central one) is Compliant.
- **Runtime requests only.** A permission declared but never requested at runtime (or normal permissions) is out of scope for this rationale test.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: runtime requests are accompanied by rationale handling, with L2 coverage.
- `n/a`: the app requests no dangerous permissions at runtime (state it).
- `unverified` rows name the deepest unresolved point (or native entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references resolvable in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its request + no-rationale L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the runtime dangerous-permission request is quoted; (2) the rationale search is shown empty (no shouldShowRequestPermissionRationale / UI); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm runtime requests were enumerated, the rationale search was performed (unread -> `unverified`), no rationale-handled request was flagged, and no `false_positive_risks` entry describes a resolvable in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
