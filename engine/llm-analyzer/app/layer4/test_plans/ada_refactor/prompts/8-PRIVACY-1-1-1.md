MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-1
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          App minimizes access to sensitive platform data and resources (least-privilege permissions) (static)

What this test looks for
The app should request only the permissions strictly necessary for its functionality (least privilege); any flagged permission must have a functionality justification. This is a static, inventory-style evaluation over the manifest permissions and the code that backs them. Verdict: `pass` (only necessary permissions requested; any flagged permission is justified by functionality visible in code or documented), `fail` (an unnecessary permission is requested without justification - in practice, a permission requested but never exercised by any code), or `inconclusive`. (This control has no N/A.)

STATIC / DYNAMIC BOUNDARY (read first - it shapes every disposition)
The spec's criteria include dynamic analysis of permission usage and third-party SDK behavior, and a "functionality justification" that is a design/product fact outside the APK. A STATIC pass cannot settle those. So:
- The only confident static FINDING is a permission REQUESTED in the manifest but NEVER exercised by any code reachable in the APK (a "dead"/unused permission - the clearest static signal that it is not necessary).
- A permission that IS exercised by code but whose business-necessity is debatable is NOT a confident static fail - it is a `documented candidate` (necessity is the design/dynamic question). Do not fabricate a necessity judgment the static artifact cannot support.
- Runtime-only behavior (when a permission is actually invoked, SDK runtime behavior) is recorded as `unverified` with `needs_dynamic_testing` as a non-binding flag; it does not, by itself, produce a fail.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on** - the manifest `<uses-permission>` line for the request, AND (for "used"/"unused") the code site that exercises the permission, or the search that found none. A disposition with no quoted manifest line + no code evidence is an assertion -> `unverified`.
2. **Read from the code, not the index.** A permissions index locates candidates; cite `AndroidManifest.xml:<line>` and `jadx/sources/...:<line-range>` of the actual API call that the permission gates.
3. **No finding by inference/hedge.** An "unused permission" finding requires showing the permission's gated APIs are not called anywhere (a documented search across the code), not a guess. "probably unused", "may not be needed", "seems excessive" are NOT evidence -> `unverified` or documented candidate. A permission shown to back a real API call is used (not an unused-permission finding).
4. **Unresolved determinacy is `unverified`, not a hedge.** If you cannot establish whether a permission's gated API is called (reflection, native, no-source SDK), the row is `unverified` (deepest unresolved point named). `false_positive_risks` is out-of-APK only.

Permission classification (do for each `<uses-permission>`)
- Protection level: normal / dangerous (runtime) / signature|signatureOrSystem|privileged. (Signature/privileged permissions are only grantable to apps signed with the platform/defining key - note them; they are often OEM/first-party context.)
- Backing: is there code in the APK that calls an API gated by this permission? (e.g. `ACCESS_FINE_LOCATION` -> `LocationManager`/`FusedLocationProviderClient`; `CAMERA` -> `Camera`/`camera2`/`CameraX`; `READ_CONTACTS` -> contacts `ContentResolver` query; `RECORD_AUDIO` -> `AudioRecord`/`MediaRecorder`; `READ/WRITE_EXTERNAL_STORAGE` -> storage APIs; `READ_PHONE_STATE` -> `TelephonyManager`; etc.)
- Attribution: is the backing code the app's proprietary code, or a third-party SDK? (prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A permission used ONLY by a third-party SDK is recorded as such (its necessity ties to the SDK's behavior - a dynamic/documentation question).

The good pattern (do not flag)
- A permission that backs a real API call in the app or a bundled SDK -> "used"; not an unused-permission finding (its necessity, if debatable, is a documented candidate, not a static fail).
- Permissions implied/required by a declared feature or a core function evident in code (camera app needs CAMERA) -> used + appropriate.
- Permissions auto-merged from library manifests that the library actually exercises -> used (by the SDK); attribute to the SDK.

Failure mode
- PM1 - Unused (unnecessary) permission: a `<uses-permission>` whose gated API(s) are not invoked anywhere in the APK by app code or any bundled SDK (a documented absence-of-use), and no functionality justification - the permission is not necessary. This is the confident static fail.

Procedure
1. Enumerate every `<uses-permission android:name="...">` from `AndroidManifest.xml` (and merged library manifests). Classify each by protection level. If there are none, the requested-surface is empty (state it; verdict `pass`).
2. For each permission, search the code for an invocation of an API the permission gates (use the permission->API mapping; grep for the relevant classes/methods). Record a quoted code site if found ("used"), or document the search that found none ("unused candidate").
3. For "used" permissions, attribute the call to proprietary code vs a third-party SDK (cite). Judge appropriateness only where code makes it evident; debatable necessity -> documented candidate (out-of-APK), not a fail.
4. For "unused candidate" permissions, confirm no gated API is reachable (including via known SDK usage). If genuinely unused -> PM1 Finding. If usage can't be determined (reflection/native/no-source SDK) -> `unverified`.
5. Conclude per permission: Finding (PM1, unused with the absence-of-use documented + manifest line quoted); Compliant (used, with the backing code quoted, or used-by-SDK attributed); Documented candidate (used but necessity debatable - out-of-APK justification); Unverified (usage undeterminable - reflection/native/SDK).
6. Budget ~1-3 reads per permission (manifest line, the grep for gated APIs, one call site). If usage can't be resolved within budget, mark it `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Actual runtime permission usage, SDK runtime behavior, and product-level necessity are dynamic/design facts a static pass cannot decide - those are `unverified`/documented candidate with `needs_dynamic_testing` flagged, never a fabricated static fail. Signature/privileged permissions in an OEM/first-party context are noted, not assumed abusive. The static verdict rests on the requested set and demonstrable code backing.

Output
List **all** requested permissions - one L1 row per permission with protection level, used/unused, attribution, and disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant "used" permissions by functional area (e.g. "storage/media permissions, used by app - 6") as one L1 row per group, but always break out every Finding (unused), documented-candidate, and unverified permission as its own individual L1 row. Never sample findings.
- Finding (PM1): L1 row plus L2 rows for the manifest request (quoted) and the documented absence of any gated-API call (the search performed, no call site found), plus attribution.
- Compliant: L1 row plus L2 for the manifest request and the backing code (quoted call site), with attribution (app vs SDK).
- Group: L1 summary plus an L2 naming references and the shared used/appropriate pattern.

```
{
  "id": "perm-001",
  "description": "Finding (PM1 unused permission): The app requests RECEIVE_SMS but no SMS-receiving API is invoked anywhere in the app or its SDKs - the permission is not necessary.",
  "reference": "AndroidManifest.xml (uses-permission RECEIVE_SMS)",
  "level": 1
},
{
  "id": "L2-RECEIVE_SMS-request",
  "description": "Requested (quoted): <uses-permission android:name=\"android.permission.RECEIVE_SMS\"/> at AndroidManifest.xml:31. Protection level: dangerous (runtime).",
  "reference": "AndroidManifest.xml:31",
  "level": 2
},
{
  "id": "L2-RECEIVE_SMS-unused",
  "description": "Absence of use (documented): grep across jadx/sources for SmsManager/SmsMessage/SMS_RECEIVED receivers/getMessagesFromIntent found no SMS-receiving API invocation in app code or bundled SDKs. No functionality backs the permission; not necessary.",
  "reference": "jadx/sources/ (no SMS-receive call site)",
  "level": 2
},
{
  "id": "perm-used-group",
  "description": "Compliant group: 6 storage/media permissions backed by real API calls in app code.",
  "reference": "AndroidManifest.xml (storage/media uses-permission)",
  "level": 1
},
{
  "id": "L2-used-coverage",
  "description": "Used (quoted): READ_MEDIA_IMAGES backs MediaStore queries in GalleryRepository.load (jadx/.../GalleryRepository.java:55-70); CAMERA backs CameraX in CaptureActivity (CaptureActivity.java:40-60); etc. Each gated API invoked by proprietary code. References (6 permissions).",
  "reference": "jadx/sources/com/example/app/data/GalleryRepository.java:55-70",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R permissions requested (normal/dangerous/signature breakdown), U used (app vs SDK), N unused findings (PM1), D documented candidates, V unverified. <one or two sentences naming the unused/flagged permissions>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is static and final on the requested set + demonstrable code backing. `needs_dynamic_testing` is a non-binding flag for runtime/SDK-behavior aspects; it does not change `pass`/`fail`.
- `fail`: >=1 permission with (a) an L2 row quoting the `<uses-permission>` request AND (b) an L2 row documenting that no gated API is invoked anywhere in the APK (the search performed, no call site), with attribution - i.e. a genuinely unused permission (PM1). A finding stated with "probably unused"/"seems excessive" instead of a documented absence-of-use is INVALID -> `unverified` or documented candidate.
- **Used permissions are not findings; do not fabricate necessity.** A permission backing a real API call is Compliant; if its business-necessity is debatable, that is a documented candidate (out-of-APK), NOT a static fail. Necessity/SDK-behavior is the dynamic/design part the static pass cannot decide.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; signature/privileged permissions noted, not assumed abusive; `false_positive_risks` out-of-APK only (functionality justification, runtime/SDK usage, a feature that uses the permission only on certain devices) - in-APK facts (is the gated API called?) resolved by reading, unresolved -> `unverified`. Reject "might be used at runtime" as a basis to flag, and "might be unused" as a basis to fail.
- `pass`: only necessary permissions requested - i.e. every requested permission is backed by code (used), or any flagged one is a justified documented candidate; no genuinely-unused permission. State the protection-level breakdown.
- (No N/A for this control.)
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` (PM1) lacks its manifest-request + documented-absence-of-use L2 rows.

Self-check before emitting (per finding)
For every PM1 Finding confirm: (1) the `<uses-permission>` is quoted from the manifest; (2) the absence of any gated-API call is DOCUMENTED (the search performed across app code and bundled SDKs, no call site found) - not "probably unused"; (3) attribution considered (a permission used only by an SDK is "used", not unused). If usage is undeterminable (reflection/native/no-source SDK) -> `unverified`, not a fail.
Necessity check: confirm no permission was failed merely because its necessity is debatable while it IS used - that is a documented candidate, not a fail.
Hedge scan: "probably", "likely", "seems", "may", "might" as a basis for a finding -> `unverified`/documented candidate.
Before any `pass`/`fail`: confirm every requested permission was checked for a backing call (unresolved -> `unverified`), counts reconcile (no sampling), and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.