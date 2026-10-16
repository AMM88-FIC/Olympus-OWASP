MASTG-TEST-0254

maswe_id       MASWE-0117
masvs_v2_id    MASVS-PRIVACY-1
platform       android
title          Dangerous App Permissions - unjustified runtime-dangerous permissions (static)

What this test looks for
An app should request the MINIMUM permissions it needs. This test enumerates the dangerous (runtime) permissions the app declares and assesses whether each is JUSTIFIED by a feature actually present in the app. A declared dangerous permission with no corresponding feature/code use - or one that has a privacy-preserving alternative the app could use instead - is a finding. This is a static evaluation of the manifest permissions plus their code usage. Verdict: `pass` (every declared dangerous permission is justified by a used feature), `fail` (>=1 dangerous permission is declared without a justifying feature, or is plainly excessive), `n/a` (the app declares no dangerous permissions), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate declared permissions from the manifest / `permissions.json`. Keep only the DANGEROUS (runtime) ones. If none are dangerous -> `n/a` (state it).

Dangerous (runtime) permission groups
CAMERA; RECORD_AUDIO; location (ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, ACCESS_BACKGROUND_LOCATION); contacts (READ_CONTACTS, WRITE_CONTACTS, GET_ACCOUNTS); phone (READ_PHONE_STATE, READ_PHONE_NUMBERS, CALL_PHONE, READ_CALL_LOG, WRITE_CALL_LOG, PROCESS_OUTGOING_CALLS); SMS (SEND_SMS, RECEIVE_SMS, READ_SMS, RECEIVE_WAP_PUSH, RECEIVE_MMS); storage (READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE, READ_MEDIA_IMAGES/VIDEO/AUDIO); calendar (READ_CALENDAR, WRITE_CALENDAR); sensors (BODY_SENSORS, ACTIVITY_RECOGNITION); nearby devices (BLUETOOTH_SCAN, BLUETOOTH_CONNECT, BLUETOOTH_ADVERTISE, NEARBY_WIFI_DEVICES); POST_NOTIFICATIONS. (Normal/signature permissions like INTERNET are out of scope here.)

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the `<uses-permission>` (manifest/`permissions.json`) AND the code use that justifies it (or show no use). No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` / `permissions.json#<record>` and `jadx/sources/...` for the feature use, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the declared dangerous permission and (b) evidence the corresponding feature is absent (the APIs guarded by that permission are not used). "probably doesn't need camera" without searching the camera APIs is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If a permission's use can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate declared permissions (`grep -nE "uses-permission" jadx/resources/AndroidManifest.xml` / `permissions.json`). Filter to dangerous ones. Quote them. If none -> short-circuit `n/a`.
2. For each dangerous permission, search for the guarded API usage that would justify it (e.g. CAMERA -> `android.hardware.Camera`/`CameraX`/`camera2`; RECORD_AUDIO -> `AudioRecord`/`MediaRecorder`; location -> `FusedLocationProviderClient`/`LocationManager`; contacts -> `ContactsContract`; SMS -> `SmsManager`/SMS content URIs; READ_MEDIA_* -> media access; etc.). Quote the use (justified) or show its absence (finding).
3. For justified permissions, also consider a privacy-preserving alternative (e.g. CAMERA -> `ACTION_IMAGE_CAPTURE` intent; storage -> Photo Picker / SAF; location -> coarse instead of fine) - if the app uses the dangerous permission where an alternative would suffice, note it (a softer finding; cross-ref MASTG-TEST-0255).
4. Owner: app-declared (proprietary); a library that pulls in a permission via manifest merge is noted (the app still ships it).
5. Conclude per permission: Finding (declared dangerous + no justifying feature, quoted); Compliant (justified by a used feature); Unverified (use unresolved).
6. Budget ~2-4 reads per permission (the declaration, the guarded-API search). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether a permission is truly NEEDED is partly product context; this test flags declared-but-unused dangerous permissions (least privilege). Privacy-preserving alternatives are MASTG-TEST-0255; rationale is MASTG-TEST-0256; auto-reset is MASTG-TEST-0257. Permission use inside native code / dynamically -> `unverified`.

Output
List **all** declared dangerous permissions - one L1 row per permission with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group justified permissions, but always break out every Finding and unverified permission individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the declared dangerous permission and the absence of its justifying feature, plus owner.
- Compliant: L1 row plus an L2 quoting the feature/code use that justifies it.

```
{
  "id": "perm-001",
  "description": "Finding (unjustified dangerous permission): The app declares RECORD_AUDIO but uses no audio-capture API, so the microphone permission is unnecessary.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-perm-decl",
  "description": "Declared permission (quoted): <uses-permission android:name=\"android.permission.RECORD_AUDIO\"/> at AndroidManifest.xml:12 (permissions.json#RECORD_AUDIO).",
  "reference": "jadx/resources/AndroidManifest.xml:12",
  "level": 2
},
{
  "id": "L2-perm-nouse",
  "description": "No justifying feature (quoted searches): grep for AudioRecord / MediaRecorder / startRecording / MediaProjection audio across jadx/sources/ returns no match - no audio-capture feature uses RECORD_AUDIO. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/",
  "level": 2
},
{
  "id": "perm-ok-001",
  "description": "Compliant: CAMERA is justified by a QR-scanner feature using CameraX.",
  "reference": "jadx/sources/com/example/app/scan/Scanner.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0254",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "D dangerous permissions declared, J justified by a used feature, N findings (declared but unused/unjustified), U unverified. Any unjustified dangerous permission? <no -> pass / n-a if none / yes -> fail>. <one or two sentences naming each unjustified permission>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 dangerous permission with (a) an L2 quoting its declaration AND (b) an L2 showing no justifying feature (the guarded APIs are unused). A finding stated with "likely"/"may" instead of the quoted declaration + empty guarded-API search is INVALID -> `unverified`.
- **Justification by used feature.** A dangerous permission whose guarded APIs ARE used is Compliant. Do not flag a permission you did not search the guarded APIs for.
- **Privacy-preserving alternative is a softer note.** If a used dangerous permission could be replaced by an alternative (intent/picker/coarse), note it (cross-ref MASTG-TEST-0255) - it strengthens but is secondary to the unused-permission finding.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (a feature reachable only via native code / dynamically) - in-APK facts (declared? guarded APIs used?) resolved by reading, unresolved -> `unverified`.
- `pass`: every declared dangerous permission is justified by a used feature, with L2 coverage.
- `n/a`: no dangerous permissions declared (state it).
- `unverified` rows name the deepest unresolved point (or native entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references resolvable in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its declaration + no-feature L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the dangerous permission declaration is quoted; (2) the guarded-API search is shown empty (no justifying feature); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm permissions were enumerated and filtered to dangerous, every flagged permission's guarded APIs were searched (unread -> `unverified`), no permission with a used feature was flagged, and no `false_positive_risks` entry describes a resolvable in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
