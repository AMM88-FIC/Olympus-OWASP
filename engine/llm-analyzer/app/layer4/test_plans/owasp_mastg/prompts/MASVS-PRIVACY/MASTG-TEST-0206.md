MASTG-TEST-0206

maswe_id       MASWE-0108
masvs_v2_id    MASVS-PRIVACY-3
platform       android
title          Undeclared PII in Network Traffic - PII sent over the network (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0206 is a dynamic test (intercept the app's decrypted network traffic and check whether PII you entered is transmitted but NOT declared in the app's privacy policy / Play Data Safety section). This static engine cannot capture traffic OR read the privacy policy / store declarations, so it performs the best-effort static equivalent - identify PII that FLOWS to network sinks (the data that would appear in a capture). The "undeclared" half (comparing against the privacy policy / Data Safety) is OUT OF THE APK and cannot be decided here. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only a traffic capture plus a privacy-policy / Data-Safety review confirms whether transmitted PII is undeclared.

What this test looks for
PII transmitted over the network must be declared in the app's privacy disclosures. Statically, the proxy is PII reaching a network transmission sink (an HTTP client, socket, or a data-collection SDK). This prompt surfaces the PII-to-network flows; the declaration comparison is deferred to runtime + policy review. Verdict: `pass` (no PII is sent to a network sink - none transmitted), `fail` (>=1 PII value is transmitted to a network/SDK sink; flagged for declaration review), `n/a` (the app sends no network traffic with app data), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for network sinks and PII sources. If no PII reaches a network sink -> `pass`/`n/a` (state the searches). Whether any transmitted PII is undeclared is confirmed at runtime + policy review (forced dynamic).

PII (taint sources)
Name, email, phone, government IDs, precise location, date of birth, financial/payment data, health data, contacts, device/advertising identifiers used for tracking, and other personal data the user provides.

Network transmission sinks
HTTP clients (`HttpURLConnection`, OkHttp/Retrofit request bodies/params/headers, Apache HttpClient, Volley, ws/grpc), raw sockets, AND third-party data-collection SDKs (FirebaseAnalytics/Crashlytics/Meta/Adjust/AppsFlyer/Amplitude/etc.; cross-ref MASTG-TEST-0318) - anything that puts the value on the wire.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the PII source AND the network sink it reaches. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the source and sink, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the PII value and (b) its placement into a network transmission. "probably sends the email" with no quoted sink is NOT static evidence -> `unverified` (flag for the capture).
4. **Unresolved determinacy is `unverified`, not a hedge.** If the PII flow to a sink can't be resolved, the row is `unverified`. The DECLARATION status is out-of-APK and belongs in `false_positive_risks` / the dynamic step, never an in-APK assertion.

Procedure
1. Enumerate network sinks + PII: `grep -rEn "HttpURLConnection|OkHttp|Retrofit|\.url\(|RequestBody|addHeader|Volley|new Socket|logEvent|setUserProperty|setUserId|identify\(|track\(" jadx/sources/`; and PII sources (user-entered fields, `getEmail`/`getPhone`/location/account). If no PII reaches a sink -> short-circuit (state the searches).
2. For each network/SDK sink, trace whether a PII value flows into it (request body/param/header/event payload). Quote source + sink. Non-PII payloads -> Compliant.
3. Group transmitted PII by recipient (first-party backend vs third-party SDK/domain) - third-party transmission especially warrants declaration review.
4. Owner: app (proprietary); SDK transmissions attributed to the SDK.
5. Conclude per flow: Finding (PII -> network/SDK sink, quoted; declaration review required); Compliant (no PII transmitted); Unverified (flow unresolved -> confirm via capture).
6. Budget ~2-4 reads per flow. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The DECLARATION check (privacy policy / Play Data Safety) is OUT OF THE APK - it cannot be decided statically; record it as a `false_positive_risks`/dynamic factor. The actual on-the-wire confirmation is the dynamic test's job - hence the forced `needs_dynamic_testing`. SDK-specific sharing detail is MASTG-TEST-0318/0319. Transmission in native/no-source code -> `unverified`.

Output
List **all** PII-to-network flows - one L1 row per flow with its disposition.
- Finding: L1 row plus L2 rows quoting the PII source and the network/SDK sink, plus the recipient (first-party vs third-party) and owner.
- Compliant: L1 row plus an L2 showing the transmission carries no PII.

```
{
  "id": "pii-001",
  "description": "Finding (PII transmitted over the network): The app sends the user's precise location and email in an analytics event to a third-party SDK; declaration must be verified against the privacy policy / Data Safety.",
  "reference": "jadx/sources/com/example/app/Track.java",
  "level": 1
},
{
  "id": "L2-pii-source",
  "description": "PII (quoted): Location loc = fused.getLastLocation(); String email = user.getEmail(); at Track.java:40-44 - precise location + email.",
  "reference": "jadx/sources/com/example/app/Track.java:40-44",
  "level": 2
},
{
  "id": "L2-pii-sink",
  "description": "Network sink (quoted): amplitude.logEvent(\"loc\", json(lat, lng, email)); at Track.java:48 - PII transmitted to Amplitude (third-party). Owner: com.example.app -> com.amplitude (third-party). Capture + privacy-policy/Data-Safety review required to confirm it is undeclared.",
  "reference": "jadx/sources/com/example/app/Track.java:48",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0206",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "N network/SDK sinks carrying app data, P transmitting PII (F first-party, T third-party). N findings (PII on the wire), U unverified. Any PII transmitted? <no -> pass / n-a if no traffic / yes -> fail (declaration review required)>. <one or two sentences>. Declaration vs privacy policy / Data Safety is out-of-APK; confirm at runtime.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ "Whether the transmitted PII is DECLARED in the privacy policy / Play Data Safety is outside the APK and must be verified out-of-band", ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that a capture + declaration review is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 flow with (a) an L2 quoting a PII value AND (b) an L2 quoting its placement into a network/SDK transmission sink. A finding stated with "likely"/"may" instead of the quoted source+sink is INVALID -> `unverified`.
- **Declaration is out-of-APK.** Do NOT assert in-APK that the transmission is "undeclared" - that requires the privacy policy / Data Safety. Flag the PII transmission and record the declaration check as a dynamic/`false_positive_risks` factor.
- **PII required.** A network call carrying no PII is Compliant. Group by recipient; third-party transmission especially warrants review.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (the declaration status; user consent) - in-APK facts (is it PII? is it sent?) resolved by reading, unresolved -> `unverified`.
- `pass`: no PII reaches a network/SDK sink, with L2 coverage.
- `n/a`: the app sends no network traffic with app data (state the searches).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if a false_positive_risk asserts a resolvable in-APK fact (vs the out-of-APK declaration), if a finding was dropped without evidence, or if any `fail` lacks its PII-source + network-sink L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the PII value is quoted and its category named; (2) its placement into a network/SDK transmission is quoted; (3) the recipient (first/third-party) is named; (4) the declaration check is deferred (not asserted in-APK); (5) ownership handled (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the network-sink + PII searches were performed, every flow's PII and sink were read and quoted (unresolved -> `unverified`), no non-PII transmission was flagged, the declaration check is recorded as out-of-APK, and no `false_positive_risks` entry asserts a resolvable in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
