MASTG-TEST-0319

maswe_id       MASWE-0112
masvs_v2_id    MASVS-PRIVACY-3
platform       android
title          Runtime Use of SDK APIs Known to Handle Sensitive User Data (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0319 is a dynamic test (hook data-collection SDK methods at runtime and observe the actual argument VALUES + backtraces to confirm sensitive user data is shared). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0318 (sensitive data reaching known SDK data-collection APIs), attributed to the call site. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only hooking the SDK methods confirms the runtime values actually contain sensitive data.

What this test looks for
At runtime no sensitive user data should be passed to third-party data-collection SDKs without disclosure/consent. Statically, the proxy is the same sensitive-data -> SDK-collection-API flow as MASTG-TEST-0318. Verdict: `pass` (no sensitive user data flows to data-collection SDK APIs), `fail` (>=1 SDK data-collection API receives sensitive data), `n/a` (no data-collection SDKs bundled), or `inconclusive`.

SHORT-CIRCUIT (decide first): identify bundled data-collection SDKs (`detected_libraries.json`/`third_party_sdks.json`). If none -> `n/a` (state it). Runtime values are still flagged via the forced `needs_dynamic_testing`.

Known SDK sinks & sensitive sources
As in MASTG-TEST-0318: FirebaseAnalytics/Crashlytics/Meta/Adjust/AppsFlyer/Branch/Amplitude/Mixpanel/Segment/Braze data-collection methods (`logEvent`/`setUserId`/`setUserProperty`/`identify`/`track`/`setCustomKey`); sensitive sources = PII, financial, health, auth identifiers, precise location, tracking identifiers combined with PII.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the SDK data-collection call AND the sensitive value passed to it, attributed to the call site. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the SDK collection API and (b) the sensitive value passed in. "probably sends PII at runtime" with no quoted argument is NOT static evidence -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`, not a hedge.** If the runtime value can't be resolved statically (built dynamically), the row is `unverified` (the hook resolves it). `false_positive_risks` is out-of-APK only.

Procedure
1. Identify SDKs + data-collection calls: `detected_libraries.json` + `grep -rEn "FirebaseAnalytics|Crashlytics|AppEventsLogger|Adjust|AppsFlyer|Branch|Amplitude|Mixpanel|Segment|Braze|logEvent|setUserId|setUserProperty|identify\(|track\(" jadx/sources/`. If none -> short-circuit `n/a` (state it).
2. For each call, trace the argument and whether it is sensitive. Quote value + call. Attribute to `<ClassFQN>.<method>:<line>` (the static analogue of the dynamic backtrace). Non-sensitive -> Compliant; dynamically-built value -> `unverified` (hook confirms).
3. SDK attribution: name the third-party recipient.
4. Conclude per call: Finding (sensitive value -> SDK API, quoted + attributed); Compliant (non-sensitive); Unverified (value runtime-built -> confirm via hook).
5. Budget ~2-4 reads per call. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The actual runtime values + backtraces are the dynamic test's strength - hence the forced `needs_dynamic_testing`. Whether the sharing is declared (privacy policy / Play Data Safety) is out-of-APK (cross-ref MASTG-TEST-0206). SDK calls in native/no-source code -> `unverified`.

Output
List **all** SDK data-collection calls carrying app data - one L1 row per call with its disposition.
- Finding: L1 row plus L2 rows quoting the SDK call and the sensitive value, attributed to the call site, plus the SDK.
- Compliant: L1 row plus an L2 showing a non-sensitive event.

```
{
  "id": "sdkr-001",
  "description": "Finding (PII shared with an attribution SDK): The app sends the user's phone number to AppsFlyer as an event parameter.",
  "reference": "jadx/sources/com/example/app/Tracking.java",
  "level": 1
},
{
  "id": "L2-sdkr-call",
  "description": "SDK data-collection call (quoted): AppsFlyerLib.getInstance().logEvent(ctx, \"register\", mapOf(\"phone\" to user.getPhone())); at Tracking.java:50 - phone (PII) -> AppsFlyer; attributed to com.example.app.Tracking.onRegister:50. SDK: com.appsflyer (third-party). Hook confirms the runtime value.",
  "reference": "jadx/sources/com/example/app/Tracking.java:50",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0319",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K data-collection SDKs, C collection calls, S passing sensitive data, N findings, U unverified (runtime-built values). Any sensitive user data shared with an SDK? <no -> pass / n-a if no such SDK / yes -> fail>. <one or two sentences>; hook confirms runtime values.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that hooking the SDK methods is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 SDK data-collection call with (a) an L2 quoting the call AND (b) an L2 quoting a sensitive value passed to it, attributed to the call site. A finding stated with "likely"/"may" instead of the quoted call+value is INVALID -> `unverified`.
- **Sensitivity required / SDK attribution** as in MASTG-TEST-0318. A non-sensitive event is Compliant.
- **Call-site attribution.** Name `<ClassFQN>.<method>:<line>` - the static analogue of the dynamic backtrace.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (disclosed/consented sharing) - in-APK facts resolved by reading, unresolved/runtime-built -> `unverified`.
- `pass`: no sensitive user data flows to data-collection SDK APIs, with L2 coverage.
- `n/a`: no data-collection SDKs detected (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references resolvable in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its SDK-call + sensitive-value L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the SDK data-collection call is quoted; (2) the sensitive value is quoted and its category named; (3) the finding is attributed to a precise call site and the SDK named; (4) ownership handled (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm data-collection SDKs were identified, every SDK call's argument sensitivity was read and quoted (runtime-built -> `unverified`), no non-sensitive event was flagged, and no `false_positive_risks` entry describes a resolvable in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
