MASTG-TEST-0028
masvs_v1_id	MSTG-PLATFORM-3
masvs_v2_id	MASVS-PLATFORM-1
platform	android
title	Testing Deep Links
masvs_v1_levels	L1, L2

Overview
This test evaluates two concerns: (a) which deep-link routes the app exposes and whether `http`/`https` routes are configured for App Links verification; (b) for each handler that reads data from a deep-link `Intent`, whether that data is validated before reaching sensitive sinks (WebView load, file access, network request, database query, intent construction).

Static Analysis

Manifest analysis. Enumerate every `<intent-filter>` containing `<action android:name="android.intent.action.VIEW"/>`, `<category android:name="android.intent.category.BROWSABLE"/>`, and `<data>` children. The cross-product of `scheme` × `host` × `path` within a single `<intent-filter>` produces all valid routes, including unintended combinations.

For each filter containing an `http`/`https` `<data>` element, verify `android:autoVerify="true"`. App Links without `autoVerify` are not verified.

On `targetSdkVersion < 31`, any non-verifiable `http`/`https` filter breaks verification for all the app's App Links.

Code analysis. For every Activity reachable via a deep-link `<intent-filter>`, inspect `onCreate` and `onNewIntent` for reads of `getIntent().getData()`, `intent.data`, `intent.getDataString()`, and `intent.extras`. Trace the resulting values to their downstream sinks: `WebView.loadUrl`/`loadData`/`loadDataWithBaseURL`, `File`/`FileInputStream`/`Files.newInputStream`, HTTP client builders, `SQLiteDatabase.rawQuery`/`SQLiteQueryBuilder`, outbound `startActivity`/`sendBroadcast`, and authentication-gated functionality reached without an auth check.

Description
The app shall use verified links and sanitize all link input data.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0028.

Verification
The analysis shall demonstrate that (a) all `http`/`https` deep links are configured for verification (`android:autoVerify="true"`) and (b) every deep-link handler validates or sanitizes data read from the launching `Intent` before that data reaches a sensitive sink.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every deep-link route that is unverified or whose handler is unhardened against attacker-controlled URI input. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `<intent-filter>` declaring an `http`/`https` `<data>` element without `android:autoVerify="true"`
- Each `<intent-filter>` whose `<data>` cross-product produces unintended routes (multiple `scheme`/`host` declarations combining into developer-unintended combinations)
- Each handler call site reading deep-link URI data and passing it to `WebView.loadUrl`/`loadData`/`loadDataWithBaseURL` without an allow-list filter on scheme/host or HTML-escaping
- Each handler call site passing deep-link URI data into a `File` constructor or file-stream API without canonicalization and base-directory containment
- Each handler call site passing deep-link URI data into an HTTP client builder as the request URL or as part of base-URL composition without an allow-list of permitted hosts
- Each handler call site passing deep-link URI data into a SQL query without parameterization
- Each handler call site constructing an outbound `Intent` (`startActivity`/`sendBroadcast`/`startService`) where the component, action, or data field is derived from the deep-link URI without validation
- Each authentication-protected screen or operation reachable via a deep-link route without an auth check at the entry point

Two records describing the same handler call site at the same line are duplicates and count as one. The same sink reached from two distinct routes counts as two rows. The rationale should group findings by surface (manifest: `autoVerify` gaps, cross-product routes; code: WebView XSS, file traversal, SSRF, SQL injection, intent redirection, auth bypass).
