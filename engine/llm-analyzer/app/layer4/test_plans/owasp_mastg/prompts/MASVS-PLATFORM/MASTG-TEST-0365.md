MASTG-TEST-0365

maswe_id       MASWE-0062
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          Exported And Unprotected Services That Expose Sensitive Functionality (static)

What this test looks for
An exported service without an appropriate `android:permission` can be started or bound by any third-party app, letting it invoke the service's functionality - returning sensitive data, performing a security-relevant action, or exposing a bound-service interface that triggers sensitive operations without authorization. This is a static evaluation of the manifest + each exported service's code. Verdict: `pass` (no exported service exposes sensitive functionality without adequate protection), `fail` (>=1 exported, inadequately-protected service exposes sensitive functionality), `n/a` (the app declares no exported services exposing sensitive functionality - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate exported services from the manifest (`android:exported="true"`, or an `<intent-filter>` with no explicit `exported`). If none are exported -> `n/a`/`pass` (state it).

Adequately protected vs not
Adequate: `android:permission` with a `signature` protection level (or a restricted custom permission), OR a runtime caller check inside the service (`checkCallingPermission`/`enforceCallingPermission`/`checkCallingOrSelfPermission`) before sensitive work. Inadequate: no permission and no runtime check, or a `normal`/`dangerous` permission (broadly grantable).

Sensitive functionality
Returning sensitive data, performing a security-relevant action (e.g. changing a password/PIN), or a started/bound interface that lets callers trigger sensitive operations or access sensitive data.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the `<service>` manifest entry (export + permission) AND the service code (`onStartCommand`/`onBind`/AIDL stub) exposing sensitive functionality, plus any runtime caller check. No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` and `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the exported+unprotected manifest entry (and no runtime check) and (b) the sensitive functionality. "probably does something sensitive" with no quoted code is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If export/permission/body can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest: enumerate `<service>` elements and their `android:exported`, `<intent-filter>`, `android:permission` (`grep -nE "<service|exported|permission|intent-filter" jadx/resources/AndroidManifest.xml`). Determine which are exported. Quote each.
2. For each exported service, check `android:permission` (+ its `protectionLevel`) AND read the service code for a runtime caller-permission check (`enforceCallingPermission`/`checkCallingPermission`). Classify protection. Quote it.
3. For each exported, inadequately-protected service, read `onStartCommand`/`onBind`/the AIDL interface impl to determine whether it exposes sensitive functionality. Quote the code. None -> Compliant (note).
4. Owner: app-declared (proprietary); a library service exported by the app is reported.
5. Conclude per service: Finding (exported + inadequate + sensitive functionality, quoted); Compliant (not exported / adequately protected / runtime-checked / benign); Unverified (unresolved).
6. Budget ~2-4 reads per service (manifest entry, permission def, onBind/onStartCommand). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Service logic inside native code or a no-source SDK -> `unverified` (name the entry point). Activities are MASTG-TEST-0364; receivers MASTG-TEST-0366; providers MASTG-TEST-0355/0357. This test is exported SERVICES.

Output
List **all** exported services - one L1 row per service with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group benign exported services, but always break out every Finding and unverified service individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the exported+unprotected manifest entry and the sensitive functionality in the code (and the absence of a runtime check), plus owner.
- Compliant: L1 row plus an L2 showing not-exported / adequate permission / runtime caller check / benign.

```
{
  "id": "svc-001",
  "description": "Finding (exported service performs a security-relevant action): An exported, unprotected bound service lets any app reset the user's PIN via its AIDL interface, with no permission or caller check.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-svc-manifest",
  "description": "Exported + unprotected (quoted): <service android:name=\".PinService\" android:exported=\"true\"/> at AndroidManifest.xml:70 - exported, no android:permission.",
  "reference": "jadx/resources/AndroidManifest.xml:70",
  "level": 2
},
{
  "id": "L2-svc-code",
  "description": "Sensitive functionality, no caller check (quoted): PinService.Stub.resetPin(newPin) writes the new PIN to the keystore at PinService.java:40-52; no enforceCallingPermission/checkCallingPermission anywhere in onBind or the stub. A third-party app can bind and reset the PIN. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/PinService.java:40-52",
  "level": 2
},
{
  "id": "svc-ok-001",
  "description": "Compliant: exported sync service enforces a signature permission and checks the caller at runtime.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0365",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S services, E exported, P adequately protected (signature/restricted/runtime-checked), N findings (exported + inadequate + sensitive functionality), C compliant, U unverified. Any exported service exposing sensitive functionality without protection? <no -> pass/n-a / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 service with (a) an L2 quoting an exported manifest entry with no/inadequate permission AND no runtime caller check AND (b) an L2 quoting sensitive functionality. A finding stated with "likely"/"may" instead of the quoted manifest+code is INVALID -> `unverified`.
- **Runtime check counts.** A `enforceCallingPermission`/`checkCallingPermission` guarding the sensitive work makes it Compliant even without a manifest permission - quote it.
- **Protection adequacy.** `signature`/restricted custom = adequate; `normal`/`dangerous`/none = not. Quote the `protectionLevel`.
- **Sensitive functionality required.** A benign exported service is Compliant - note it.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: no exported service exposes sensitive functionality without adequate protection, with L2 coverage.
- `n/a`: no exported services exposing sensitive functionality (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK evidence, if a finding was dropped without evidence, or if any `fail` lacks its manifest + sensitive-functionality L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the exported+unprotected manifest entry is quoted; (2) the sensitive functionality in the service code is quoted; (3) no adequate manifest permission AND no runtime caller check guards it; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the manifest was read and exported services enumerated, every finding's service body was read for sensitive functionality AND a runtime check (unread -> `unverified`), no benign/checked service was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
