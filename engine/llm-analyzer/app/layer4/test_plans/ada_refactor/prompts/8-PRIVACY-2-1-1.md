MASTG-TEST-XXXX

masvs_v1_id    MSTG-STORAGE-12
masvs_v2_id    MASVS-PRIVACY-3
platform       android
title          App is transparent about data collection and use (privacy policy / store label / undeclared transmission) (static)

What this test looks for
The app must clearly disclose what data it collects, stores, and shares - including any collection users would not expect. Three criteria: (1) a valid privacy policy exists; (2) the practices declared in the store Data Safety Section match the privacy policy; (3) no data types are transmitted over the network that are not declared. Verdict: `pass` (valid privacy policy whose statements match the store label, and all collected/transmitted data is explicitly declared), `fail` (the policy is missing, it diverges from the store label, or undeclared data types are transmitted), or `inconclusive`. (This control has no N/A.)

WHERE THE FACTS COME FROM (read first - it shapes every disposition)
Two of the three criteria live OUTSIDE the APK: the privacy policy text and the Play Store Data Safety label. A static APK pass cannot retrieve them. They must be PROVIDED to this run as artifacts (a privacy-policy document/URL contents, the Data Safety label export, and/or the app's declared data-type list). The in-APK contribution this pass produces itself is the NETWORK DATA-TYPE INVENTORY: which categories of data the code actually transmits over the network, to cross against the declared set.
- Policy existence (criterion 1) and policy<->store-label match (criterion 2) are judged from the PROVIDED documents; if a document is not provided, that criterion is `unverified` (do not assume presence or absence, and never invent policy/label text from memory).
- Undeclared transmission (criterion 3) is judged by comparing the in-APK transmitted-data inventory against the PROVIDED declared set; with no declared set provided, the inventory is still produced but the "undeclared" determination is `unverified`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes its evidence** - for transmission, the code site that sends the data over the network (the value/field + the network call); for policy/label, the specific provided-document passage (cited as the provided artifact, not invented). A disposition with no quoted code/document is an assertion -> `unverified`.
2. **Read from the code/document, not an index.** Cite `jadx/sources/...:<line-range>` for a transmission site; cite the provided policy/label artifact for a disclosure. Never recall policy or label contents from memory.
3. **No finding by inference/hedge.** An undeclared-transmission finding requires quoting (a) the data value/category and (b) the network sink it is sent to, AND showing the category is absent from the provided declared set. "likely collects", "may transmit", "probably undeclared" are NOT evidence -> `unverified`. A policy/label-mismatch finding requires quoting both sides (the policy statement and the differing label entry).
4. **Unresolved determinacy is `unverified`, not a hedge.** Missing provided document, untraceable transmission, or indeterminate data category -> `unverified` (deepest unresolved point named). `false_positive_risks` is out-of-APK only.

Data categories (for the network inventory)
Personal/identifier data sent over the network: precise/approximate location; contacts; SMS/call log; identifiers (Android ID, advertising ID, IMEI/IMSI/serial, account email/username); device/usage telemetry tied to a person; photos/media/files; health/financial data; credentials. Categorize each transmitted value to the granularity the store Data Safety taxonomy uses (Location, Personal info, Financial info, Contacts, etc.).

Network transmission sinks
HTTP/socket clients (OkHttp/Retrofit/HttpURLConnection/Volley/Ktor/gRPC), analytics/ads SDK send APIs, `WebView.postUrl`, sockets. A "transmission" is a data value of a category above reaching one of these sinks (directly or via a payload object/JSON body).

Failure modes
- PV1 - Missing privacy policy: no valid privacy policy is present in the provided artifacts (criterion 1). (Judged from provided documents; absent document -> `unverified`, not an assumed PV1.)
- PV2 - Policy/store-label mismatch: a data practice declared in the store Data Safety label diverges from the privacy policy (or vice versa) - e.g. the label omits a category the policy admits collecting, or they disagree on sharing/third-party transfer (criterion 2). Quote both sides from the provided artifacts.
- PV3 - Undeclared transmitted data type: the code transmits a data category over the network that is NOT in the provided declared set (Data Safety label / policy) (criterion 3). Quote the transmission site and show the category's absence from the declared set.

Procedure
1. Build the in-APK network data-type inventory: enumerate transmission sinks (`grep -rEn "OkHttpClient|Retrofit|HttpURLConnection|Volley|\\.newCall\\(|postUrl|Socket\\(|analytics|track\\(|logEvent" jadx/sources/`), and for each, trace what data category (from the list) is included in the request (payload object/JSON/query params). Quote the value/field and the network call. Attribute to app code vs third-party SDK.
2. Load the PROVIDED artifacts: privacy policy text, store Data Safety label / declared data-type set. If a needed artifact is not provided, mark the dependent criterion `unverified` (do not assume).
3. Criterion 1 (PV1): from the provided artifacts, is a valid privacy policy present? Quote the relevant passage or record its provided-absence. No artifact -> `unverified`.
4. Criterion 2 (PV2): compare each declared practice in the store label against the privacy policy; quote any divergence (category present in one, absent/contradicted in the other).
5. Criterion 3 (PV3): for each transmitted category in the in-APK inventory, check whether it is declared in the provided declared set. Transmitted-but-not-declared -> PV3 Finding (quote the transmission + show the absence). No declared set provided -> `unverified` for the undeclared determination (inventory still reported).
6. Conclude: Finding (PV1/PV2/PV3 with the quoted code/document evidence); Compliant (policy present + matches label + every transmitted category declared - quoted); Unverified (missing provided artifact, untraceable transmission, indeterminate category); documented candidate where a borderline declaration interpretation is an out-of-APK doc question.
7. Budget the transmission tracing to ~2-4 reads per distinct sink/payload plus document comparison. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The privacy policy and store Data Safety label are not in the APK; this test depends on them being provided and never invents their contents. Whether a transmitted value is "personal" can require context; indeterminate -> `unverified`. Third-party SDK transmissions are included in the inventory (they count toward collection) and attributed. The static verdict rests on the in-APK transmission inventory crossed against the provided declared set, plus the provided policy/label comparison.

Output
List the disclosure findings and the network data-type inventory - one L1 row per transmitted data category (with declared/undeclared status) and per policy/label issue. <=20 -> one L1 row each. >20 (collapse) -> group declared-and-matching categories by area as one L1 row per group, but always break out every Finding (PV1/PV2/PV3), documented-candidate, and unverified item individually. Never sample findings.
- Finding PV3: L1 row plus L2 rows for the transmission (data value/category + network sink quoted, attributed) and the absence from the provided declared set.
- Finding PV1/PV2: L1 row plus L2 quoting the provided policy/label evidence (missing policy, or the two diverging statements).
- Compliant: L1 row plus L2 showing the transmitted category is declared (cite the provided declared set) / the policy present and matching.
- Group: L1 summary plus an L2 naming the categories and the matching declarations.

```
{
  "id": "pv-001",
  "description": "Finding (PV3 undeclared transmitted data): The app transmits the device advertising ID to an analytics endpoint, but 'Advertising ID / identifiers' is not declared in the provided Data Safety label or privacy policy.",
  "reference": "jadx/sources/com/example/app/analytics/Tracker.java",
  "level": 1
},
{
  "id": "L2-adid-transmit",
  "description": "Transmission (quoted): Tracker.send builds JSON {\"adid\": AdvertisingIdClient.getAdvertisingIdInfo(ctx).getId(), ...} and posts it via OkHttp to https://collect.example-analytics.com at lines 60-74. Category: identifiers (advertising ID). Attributed to bundled analytics SDK invoked by app code.",
  "reference": "jadx/sources/com/example/app/analytics/Tracker.java:58-78",
  "level": 2
},
{
  "id": "L2-adid-undeclared",
  "description": "Absence from declared set: the provided Data Safety label (artifact: data_safety_label) lists Location and App activity, but no 'Device or other IDs / advertising ID' category; the provided privacy policy (artifact: privacy_policy) does not mention advertising identifiers. Transmitted but undeclared.",
  "reference": "(provided artifact) data_safety_label; privacy_policy",
  "level": 2
},
{
  "id": "pv-declared-group",
  "description": "Compliant group: 3 transmitted categories (approx. location, app activity, crash logs) all declared in the provided label and policy.",
  "reference": "jadx/sources/com/example/app/ (transmission sites)",
  "level": 1
},
{
  "id": "L2-declared-coverage",
  "description": "Declared & transmitted: approximate location -> LocationRepository.report (jadx/.../LocationRepository.java:40-55) is declared as 'Location/Approximate location' in the provided label and described in the policy; etc. Each transmitted category present in the declared set. References (3 categories).",
  "reference": "jadx/sources/com/example/app/loc/LocationRepository.java:40-55",
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
  "rationale": "Policy present? <yes/no/unverified>. Label<->policy match? <match/mismatch/unverified>. T transmitted categories inventoried (app vs SDK), D declared, N undeclared findings (PV3), plus PV1/PV2 as applicable, U unverified. <one or two sentences naming the undeclared categories / mismatches>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict rests on the provided privacy policy / store label plus the in-APK transmission inventory. `needs_dynamic_testing` is a non-binding flag for runtime-only transmissions; it does not change `pass`/`fail`.
- **Policy and label facts come only from provided artifacts, never from memory.** PV1/PV2 require quoting the provided documents; a missing artifact makes the dependent criterion `unverified`, never an assumed pass or fail.
- `fail`: >=1 of: PV1 (no valid policy in provided artifacts), PV2 (a quoted policy<->label divergence), or PV3 (a transmitted category quoted at its network sink AND shown absent from the provided declared set). A finding stated with "likely"/"may"/"probably undeclared" instead of the quoted transmission + documented absence is INVALID -> `unverified`.
- **An undeclared-transmission finding needs the transmission quoted and the absence shown.** A transmitted category that IS in the declared set is Compliant. Third-party SDK transmissions count (and are attributed).
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (a declaration interpretation, a category transmitted only under a runtime condition, label wording nuance) - in-APK facts (is the category transmitted?) resolved by reading, unresolved -> `unverified`. Reject "might be declared somewhere", "the policy may cover it".
- `pass`: a valid privacy policy is present (provided), its statements match the store label, and every in-APK transmitted category is in the declared set - all with quoted evidence.
- (No N/A for this control.)
- `unverified` rows name the deepest unresolved point (untraced transmission, or the missing provided artifact). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, if any policy/label claim was asserted without the provided artifact, or if any `fail` lacks its required quoted L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) PV3 - the transmission is quoted (data value/category + network sink) AND the category's absence from the PROVIDED declared set is shown; PV1/PV2 - the provided policy/label artifact is quoted (not recalled from memory); (2) the data category is determinable, not guessed; (3) attribution (app vs SDK) recorded for a transmission.
Provided-artifact check: confirm no policy/label claim rests on memory; a missing artifact -> the criterion is `unverified`, not an assumed verdict.
Hedge scan: "likely", "may", "probably", "seems", "might" as a basis for a finding -> `unverified`.
Before any `pass`/`fail`: confirm the transmission inventory was built from quoted sinks, the declared-set comparison used the provided artifact, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.