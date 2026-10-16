MASTG-TEST-0318

maswe_id       MASWE-0112
masvs_v2_id    MASVS-PRIVACY-3
platform       android
title          References to SDK APIs Known to Handle Sensitive User Data (static)

What this test looks for
Third-party SDKs (analytics, advertising, crash reporting, attribution) expose APIs that collect/transmit user data. This test detects calls to such SDK data-collection APIs and whether sensitive user data is passed to them - i.e. the app shares sensitive data with a third party. This is a static, taint-style evaluation: sensitive data -> known SDK data-collection sink. Verdict: `pass` (no sensitive user data is passed to data-collection SDK APIs), `fail` (>=1 SDK data-collection API receives sensitive user data), `n/a` (the app bundles no known data-collection SDKs), or `inconclusive`. (Per OWASP this detects POTENTIAL sharing; runtime confirmation is MASTG-TEST-0319.)

SHORT-CIRCUIT (decide first): identify bundled data-collection SDKs (`detected_libraries.json` / `third_party_sdks.json` / package prefixes). If none -> `n/a` (state it).

Known data-collection SDK sinks (examples - identify the app's actual SDKs)
- Firebase/Google Analytics: `FirebaseAnalytics.setUserId(...)`, `setUserProperty(...)`, `logEvent(name, Bundle)`.
- Crashlytics: `setUserId`, `setCustomKey`, `log`.
- Facebook/Meta: `AppEventsLogger.logEvent(...)`, `setUserData(...)`, `setUserID(...)`.
- Adjust/AppsFlyer/Branch/Singular (attribution): `trackEvent`, `setUserId`, `logEvent`, `addUserToList`.
- Ad SDKs (AdMob/AppLovin/Unity Ads/IronSource): targeting/user-data setters.
- Amplitude/Mixpanel/Segment/Braze: `identify`, `track`, `setUserId`, `setUserProperties`.
Identify the SDK's data-collection entry points from its package and the methods above.

Sensitive user data (taint sources)
PII (name, email, phone, government IDs, precise location), financial/payment data, health data, authentication/account identifiers, device identifiers used to track (advertising ID combined with PII), and any data the user entered that is sensitive. Non-sensitive analytics (a screen name, a non-identifying event with no PII) is not a finding.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the SDK data-collection call AND the sensitive value passed to it. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the SDK call and the data source, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the SDK data-collection API and (b) the sensitive value passed in. "probably sends PII to analytics" with no quoted argument is NOT evidence -> `unverified`. A non-sensitive event is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the SDK call's argument sensitivity can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Identify SDKs + their data-collection APIs: from `detected_libraries.json`/`third_party_sdks.json` and `grep -rEn "FirebaseAnalytics|Crashlytics|AppEventsLogger|Adjust|AppsFlyer|Branch|Amplitude|Mixpanel|Segment|Braze|logEvent|setUserId|setUserProperty|identify\(|track\(" jadx/sources/`. If no data-collection SDK -> short-circuit `n/a` (state it).
2. For each SDK data-collection call, trace what is passed (the event payload / user id / property) and whether any is sensitive (taint from a sensitive source). Quote the value + the call. Non-sensitive -> Compliant.
3. Classify owner: the SDK is third-party, but the app feeding it sensitive data is the app's privacy issue - report it (attribute the SDK).
4. Conclude per call: Finding (sensitive value -> SDK collection API, quoted); Compliant (non-sensitive event); Unverified (argument sensitivity unresolved).
5. Budget ~2-4 reads per call (the SDK call, the argument source, 1-2 hops). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Runtime confirmation of the actual values sent is MASTG-TEST-0319. Whether the sharing is DECLARED (privacy policy / Play Data Safety) is out-of-APK - this test flags the sharing; declaration review is separate (cross-ref MASTG-TEST-0206). SDK calls in native/no-source code -> `unverified`.

Output
List **all** SDK data-collection calls carrying app data - one L1 row per call with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group non-sensitive events by SDK, but always break out every Finding and unverified call individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the SDK data-collection call and the sensitive value passed, plus the SDK.
- Compliant: L1 row plus an L2 showing the event is non-sensitive.

```
{
  "id": "sdk-001",
  "description": "Finding (PII shared with an analytics SDK): The app passes the user's email to FirebaseAnalytics as a user property, sharing PII with the third party.",
  "reference": "jadx/sources/com/example/app/Analytics.java",
  "level": 1
},
{
  "id": "L2-sdk-call",
  "description": "SDK data-collection call (quoted): firebaseAnalytics.setUserProperty(\"email\", user.getEmail()); at Analytics.java:40 - email (PII) sent to Firebase Analytics. SDK: com.google.firebase.analytics (third-party).",
  "reference": "jadx/sources/com/example/app/Analytics.java:40",
  "level": 2
},
{
  "id": "sdk-ok-001",
  "description": "Compliant: a non-identifying screen_view event with no PII.",
  "reference": "jadx/sources/com/example/app/Analytics.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0318",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K data-collection SDKs detected, C SDK collection calls, S passing sensitive data, N findings, U unverified. Any sensitive user data shared with an SDK? <no -> pass / n-a if no such SDK / yes -> fail>. <one or two sentences naming the SDK(s) and data>. Runtime confirmation: MASTG-TEST-0319.",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime confirmation is MASTG-TEST-0319); it does not change `pass`/`fail`.
- `fail`: >=1 SDK data-collection call with (a) an L2 quoting the call AND (b) an L2 quoting a sensitive value passed to it. A finding stated with "likely"/"may" instead of the quoted call+value is INVALID -> `unverified`.
- **Sensitivity required.** A non-identifying analytics event (no PII) is Compliant. The finding needs sensitive data reaching the SDK.
- **SDK attribution.** Name the third-party SDK; the app feeding it sensitive data is the privacy issue reported here.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (the sharing is disclosed/consented - a declaration fact outside the APK) - in-APK facts (which SDK? what value?) resolved by reading, unresolved -> `unverified`.
- `pass`: no sensitive user data is passed to data-collection SDK APIs, with L2 coverage.
- `n/a`: no known data-collection SDKs detected (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references resolvable in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its SDK-call + sensitive-value L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the SDK data-collection call is quoted; (2) the sensitive value passed to it is quoted and its category named; (3) the SDK is named; (4) ownership handled (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm data-collection SDKs were identified, every SDK call's argument sensitivity was read and quoted (unread -> `unverified`), no non-sensitive event was flagged, and no `false_positive_risks` entry describes a resolvable in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
