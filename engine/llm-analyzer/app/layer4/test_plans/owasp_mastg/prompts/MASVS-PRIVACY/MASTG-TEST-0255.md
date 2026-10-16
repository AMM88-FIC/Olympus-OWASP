MASTG-TEST-0255

maswe_id       MASWE-0117
masvs_v2_id    MASVS-PRIVACY-1
platform       android
title          Permission Requests Not Minimized - privacy-preserving alternative available (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0255 as a `status: placeholder` (no procedure body; note: "checks if the app requests permissions that have privacy-preserving alternatives"). This prompt implements the best-effort static detection: a declared dangerous permission for which Android offers a privacy-preserving alternative the app could use instead (a system picker / intent action / scoped API) that avoids holding the broad permission.

What this test looks for
The app should prefer privacy-preserving alternatives over broad dangerous permissions. This test flags declared dangerous permissions that have a well-known alternative, where the app holds the permission instead of using the alternative. Verdict: `pass` (no declared permission has an unused privacy-preserving alternative - the app already uses alternatives or genuinely needs the permission), `fail` (>=1 dangerous permission is declared where a privacy-preserving alternative would suffice and the app does not use it), `n/a` (the app declares no dangerous permissions with known alternatives), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate declared dangerous permissions (manifest / `permissions.json`). If none have a known alternative -> `n/a` (state it).

Permission -> privacy-preserving alternative (the mapping to apply)
- `CAMERA` -> `ACTION_IMAGE_CAPTURE` / `ACTION_VIDEO_CAPTURE` intent (delegate to the camera app; no CAMERA permission).
- `READ_EXTERNAL_STORAGE` / `READ_MEDIA_IMAGES`/`VIDEO` -> the Android Photo Picker (`ACTION_PICK_IMAGES` / `PickVisualMedia`) or Storage Access Framework (`ACTION_OPEN_DOCUMENT`) - no broad media permission.
- `WRITE_EXTERNAL_STORAGE` -> SAF / MediaStore scoped writes.
- `READ_CONTACTS` -> the contact picker (`ACTION_PICK` on Contacts) for a single contact - no READ_CONTACTS.
- `ACCESS_FINE_LOCATION` (when coarse suffices) -> `ACCESS_COARSE_LOCATION`, or a one-time location, or the system location picker.
- `RECORD_AUDIO` (for one-off capture) -> a capture intent where applicable.
- `READ_PHONE_STATE`/`READ_PHONE_NUMBERS` (for phone number) -> account/credential APIs instead.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the declared permission AND whether the app uses the broad API (finding) vs the alternative (compliant). No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` / `permissions.json` and `jadx/sources/...`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the declared dangerous permission with a known alternative AND (b) that the app uses the broad permission's API rather than the alternative. "could use the picker" without checking is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If usage can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate dangerous permissions with a known alternative (mapping above). Quote them. If none -> short-circuit `n/a`.
2. For each, check whether the app uses the BROAD permission's API (e.g. CAMERA via `camera2`/CameraX) or already uses the ALTERNATIVE (e.g. `ACTION_IMAGE_CAPTURE`, `PickVisualMedia`, SAF, contact picker). `grep` both. Quote it.
3. Flag a finding where the app holds the broad permission AND uses its API while a privacy-preserving alternative would suffice for the observed use. Where the broad API is genuinely needed (e.g. continuous in-app camera preview, real-time location tracking) -> Compliant (the alternative does not cover that use). Quote the rationale.
4. Owner: app (proprietary).
5. Conclude per permission: Finding (broad permission used where alternative suffices, quoted); Compliant (alternative used, or broad API genuinely required); Unverified (use unresolved).
6. Budget ~2-4 reads per permission (the declaration, the broad-API use, any alternative use). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether the broad API is truly required is partly product context - flag only where the observed use is the kind the alternative covers (one-off capture/pick). Unused dangerous permissions are MASTG-TEST-0254; rationale is MASTG-TEST-0256. Use in native code -> `unverified`.

Output
List **all** declared dangerous permissions that have a known alternative - one L1 row per permission with its disposition.
- Finding: L1 row plus L2 rows quoting the declared permission, the broad-API use, and the applicable alternative, plus owner.
- Compliant: L1 row plus an L2 showing the alternative is used, or the broad API is genuinely required.

```
{
  "id": "min-001",
  "description": "Finding (permission not minimized): The app holds CAMERA and launches its own in-app capture for a one-off profile photo, where ACTION_IMAGE_CAPTURE would avoid the permission.",
  "reference": "jadx/sources/com/example/app/profile/PhotoActivity.java",
  "level": 1
},
{
  "id": "L2-min-decl",
  "description": "Declared permission + broad use (quoted): <uses-permission android:name=\"android.permission.CAMERA\"/> (AndroidManifest.xml:10); PhotoActivity opens a CameraX preview only to take a single still for the avatar at PhotoActivity.java:40-58.",
  "reference": "jadx/sources/com/example/app/profile/PhotoActivity.java:40-58",
  "level": 2
},
{
  "id": "L2-min-alt",
  "description": "Privacy-preserving alternative (quoted): for a one-off photo, startActivityForResult(new Intent(MediaStore.ACTION_IMAGE_CAPTURE)) delegates to the camera app and needs no CAMERA permission. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/profile/PhotoActivity.java:40-58",
  "level": 2
},
{
  "id": "min-ok-001",
  "description": "Compliant: image selection uses the Android Photo Picker (no media permission).",
  "reference": "jadx/sources/com/example/app/Upload.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0255",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "P dangerous permissions with a known alternative, A using the alternative already, N findings (broad permission where alternative suffices), C compliant (alternative used / broad API required), U unverified. Any non-minimized permission? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 dangerous permission with (a) an L2 quoting the declaration + the broad-API use AND (b) an L2 naming the applicable privacy-preserving alternative for that use. A finding stated with "likely"/"may" instead of the quoted broad-API use is INVALID -> `unverified`.
- **Alternative must cover the use.** Flag only where the alternative actually suffices for the observed use (one-off capture/pick/coarse). A genuine continuous/real-time need is Compliant.
- **Already-using-the-alternative is Compliant.** If the app uses the picker/intent/coarse API, pass.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: no permission has an unused applicable alternative, with L2 coverage.
- `n/a`: no dangerous permissions with a known alternative (state it).
- `unverified` rows name the deepest unresolved point (or native entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references resolvable in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its broad-use + alternative L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the declared permission and its broad-API use are quoted; (2) the applicable privacy-preserving alternative is named and shown to cover the use; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm permissions with alternatives were enumerated, every flagged permission's broad-vs-alternative usage was read and quoted (unresolved -> `unverified`), no genuine-need/already-alternative permission was flagged, and no `false_positive_risks` entry describes a resolvable in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
