MASTG-TEST-0382

maswe_id       MASWE-0075
masvs_v2_id    MASVS-CODE-2
platform       android
title          Use of Enforced Updating APIs - app-update enforcement (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0382 is a dynamic test (capture version-related traffic and hook update APIs at runtime to confirm the app actually enforces an update and the enforcement can't be bypassed). This static engine cannot run the app or capture traffic, so this prompt performs the best-effort static equivalent - detect whether the app IMPLEMENTS an update-enforcement mechanism (Google Play In-App Updates `AppUpdateManager`, or a custom backend version check) and whether it appears to gate access before update. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only runtime testing proves enforcement actually blocks access and survives cancellation/backgrounding/version-spoofing.

What this test looks for
An app requiring enforced updates should, at runtime, check the version (via `AppUpdateManager`/In-App Updates, or a backend `minVersion` check) BEFORE granting access to protected functionality, and enforce it non-bypassably. Statically, the proxy is the PRESENCE and shape of an update-enforcement mechanism. Verdict: `pass` (the app implements an update-enforcement mechanism that gates access), `fail` (no update-enforcement mechanism is present, or one exists but plainly does not gate access / is trivially bypassable in code), `n/a` (enforced updating is genuinely out of scope for this app - state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the update-enforcement APIs below. If NONE appear AND no backend version check exists -> static evidence of no enforcement -> lean `fail` (still forced-dynamic). If a mechanism appears, assess its gating.

Update-enforcement mechanisms
- **Google Play In-App Updates**: `AppUpdateManager`, `getAppUpdateInfo()`, `startUpdateFlowForResult(...)` with `AppUpdateType.IMMEDIATE` (immediate = blocking) or `FLEXIBLE`, `UpdateAvailability.UPDATE_AVAILABLE`/`DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS`, handling in `onResume`/`onActivityResult`.
- **Custom backend version check**: read `BuildConfig.VERSION_NAME`/`VERSION_CODE` or `PackageManager.getPackageInfo(...).versionCode`, send to a backend, receive a `minVersion`/`update_required` policy, and block on it.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the update mechanism (AppUpdateManager calls / version-check + backend gate) OR show its absence via searches. No quoted evidence -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No verdict by inference/hedge.** A `pass` requires quoting a gating mechanism; a `fail`-on-absence requires shown-empty searches. "probably enforces updates" is NOT static proof -> `unverified` (flag for the dynamic test).
4. **Unresolved determinacy is `unverified`, not a hedge.** If a mechanism exists but its gating can't be resolved statically, the row is `unverified` (the hook confirms it). `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate mechanisms: `grep -rEn "AppUpdateManager|getAppUpdateInfo|startUpdateFlowForResult|AppUpdateType|UpdateAvailability|DEVELOPER_TRIGGERED_UPDATE|BuildConfig\.VERSION|getPackageInfo|versionCode|minVersion|update_required|forceUpdate" jadx/sources/`. State the searches.
2. If a mechanism exists, read where it runs (app entry: splash/`onResume`/first activity) and whether it gates access (blocks the UI / finishes the activity / shows a non-dismissible update screen until updated) - especially `IMMEDIATE` flows and `DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS` re-triggering. Quote it.
3. If no mechanism exists, conclude `fail` (state the search). If a mechanism exists but clearly does not gate (e.g. only a dismissible toast), note it (`fail`/`unverified` per evidence).
4. Owner: app (proprietary); a library handling updates is reported.
5. Conclude: pass (gating mechanism quoted) / fail (absent, or non-gating) / unverified (gating unresolved -> confirm at runtime).
6. Budget ~2-5 reads (the update calls, the entry point, the gate). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether enforcement actually blocks access and resists cancellation/backgrounding/version-spoofing is runtime-only - hence the forced `needs_dynamic_testing`. Update logic in native code or a no-source SDK -> `unverified` (name the entry point).

Output
List the update-enforcement mechanism(s) found - one L1 row per mechanism (or its absence) with disposition.
- Pass: L1 row plus L2 quoting the mechanism and its gating (entry point + block).
- Fail (absent): L1 row plus L2 showing the searches returned nothing.
- Fail (non-gating): L1 row plus L2 quoting the mechanism and why it does not gate.

```
{
  "id": "upd-001",
  "description": "Finding (no update enforcement): the app implements no In-App Updates flow and no backend version check, so it cannot enforce updates.",
  "reference": "jadx/sources/",
  "level": 1
},
{
  "id": "L2-upd-absent",
  "description": "Absence (quoted searches): grep for AppUpdateManager / getAppUpdateInfo / startUpdateFlowForResult / minVersion / update_required across jadx/sources/ returns no match; version is only read for display. Owner: com.example.app (proprietary). Runtime confirmation required.",
  "reference": "jadx/sources/",
  "level": 2
},
{
  "id": "upd-ok-001",
  "description": "Pass: the app runs an immediate In-App Update flow at startup and blocks until updated.",
  "reference": "jadx/sources/com/example/app/SplashActivity.java",
  "level": 1
},
{
  "id": "L2-upd-ok",
  "description": "Gating mechanism (quoted): appUpdateManager.getAppUpdateInfo().addOnSuccessListener(info -> { if (info.updateAvailability()==UPDATE_AVAILABLE && info.isUpdateTypeAllowed(IMMEDIATE)) appUpdateManager.startUpdateFlowForResult(info, IMMEDIATE, this, RC); }); and onResume re-checks DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS at SplashActivity.java:40-60 - blocks access until updated. Runtime confirms non-bypassability.",
  "reference": "jadx/sources/com/example/app/SplashActivity.java:40-60",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0382",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Update mechanism: <In-App Updates / backend version check / none>. Gates access before protected functionality? <yes -> pass / no or absent -> fail / unresolved -> unverified>. <one or two sentences>; runtime confirms enforcement & bypass-resistance.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `fail`: no update-enforcement mechanism is present (shown via searches), OR a present mechanism plainly does not gate access (quoted). A verdict asserted without quoted evidence / shown-empty searches is INVALID -> `unverified`.
- **Gating is the test.** A version check that only logs or shows a dismissible prompt is not enforcement. An immediate In-App Update flow at entry, or a backend `update_required` gate that blocks, is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (enforcement is backend-driven and not visible in the APK) - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: an update-enforcement mechanism that gates access is quoted.
- `n/a`: only with a stated justification that enforced updating is out of scope for this app.
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale doesn't reconcile with the rows, if any false_positive_risk references in-APK code, or if a `fail` lacks its shown-empty searches / non-gating quote.

Self-check before emitting
Confirm: (1) for pass, the mechanism and its access-gating are quoted; (2) for fail-on-absence, the searches are shown empty; (3) a mere version read (for display) was not mistaken for enforcement.
Hedge scan: "likely", "may", "appears", "probably", "might" in evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the update-API search was performed and shown, the gating was read where a mechanism exists (unresolved -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
