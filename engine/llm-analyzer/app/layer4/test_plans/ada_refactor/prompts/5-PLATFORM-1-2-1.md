MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-3
masvs_v2_id    MASVS-PLATFORM-1 (and MASVS-CODE-4 for input sanitization)
platform       android
title          Use verified App Links and sanitize all link input (deep links / app links) (static)

What this test looks for
Two pillars: (A) VERIFICATION - http/https links the app handles should be verified App Links (`android:autoVerify="true"` + Digital Asset Links), so another app cannot hijack them; on modern targetSdk this is auto-enforced by the system. (B) SANITIZATION - data carried by ANY deep/app link (scheme, host, path, query params, embedded intents/extras) is untrusted attacker input and must be validated/sanitized before reaching a sink. This is a static, inventory-style evaluation over the manifest link intent-filters and each link handler's code. Verdict: `pass` (links verified or sanitization documented, AND link input is sanitized in every handler), `fail` (unverified hijackable links without a verification process, OR link input reaching a sink without sanitization), `n/a` (the app declares no links/deep links), or `inconclusive`.

EVIDENCE DISCIPLINE (applies to every row and both pillars)
1. **Every verdict-affecting disposition must quote the code/manifest it rests on - Finding, Compliant, and dismissal alike.** You may NOT conclude a link handler is sanitized (or vulnerable) without quoting the handler lines showing how the link data (`getData`/`getQueryParameter`/`getPathSegments`/intent extras) is validated and where it flows. "Input is sanitized" / "validates the URL" without the quoted code is an assertion -> `unverified`.
2. **Read from the code, not the index.** An evidence index locates candidates; cite `jadx/sources/...:<line-range>` of the actual handler body (`onCreate`/`onNewIntent`/the routed method), not the index record or line 1.
3. **Unresolved determinacy is `unverified`, not a hedge.** Anything you cannot settle from this APK - whether `assetlinks.json` is correctly hosted (it lives on the domain, not in the APK), whether a path is sensitive, whether a handler is reachable - makes the row `unverified` (deepest unresolved point named), NOT a confident disposition with a caveat. `false_positive_risks` is for genuinely out-of-APK factors only; in-APK facts you did not resolve belong in `unverified` rows.
4. **A finding may not rest on inference or hedge words.** A SAN finding requires you to QUOTE the actual tainted chain - all three of: (a) the source read (literal `getData()` / `getQueryParameter(...)` / `getPathSegments()` / `getParcelableExtra(...)` call), (b) the propagation if any, and (c) the SINK call (literal `startActivity(` / `loadUrl(` / `rawQuery(` / `new File(` / `Intent.parseUri(` etc.) receiving that value. If your evidence uses "likely", "may", "appears", "suggesting", "probably", "seems", or "is used to" instead of quoted source-to-sink code, you have NOT evidenced a finding -> the disposition is `unverified` (deepest unresolved point = the unread/unquoted method), NOT a Finding. A line-RANGE reference with paraphrase is not a quote; paste the relevant lines.
   WRONG (do not produce this): "launchByDeepLink parses a string likely from the deep link URI and uses it to populate intent extras, without validation." -> hedged, no quoted source/sink chain -> this is `unverified`, not a Finding.
   RIGHT: "onNewIntent: `Uri u = getIntent().getData();` (line 41) `String t = u.getQueryParameter(\"target\");` (43) `Intent i = new Intent(); i.setClassName(this, t);` (45) `startActivity(i);` (47) - tainted query param sets the launched component, no allowlist -> SAN4 Finding." (source, propagation, and sink all quoted.)

Scope
In scope: every component declaring a link intent-filter - `<intent-filter>` with `<action android:name="android.intent.action.VIEW"/>`, `<category android:name="android.intent.category.BROWSABLE"/>`, and a `<data>` element (scheme http/https or a custom scheme). These are reachable from the browser/other apps, so the link data is attacker-controlled. The SANITIZATION pillar applies to ALL such handlers, including verified App Links (verification authenticates the source/domain, not the data).

The good pattern (do not flag)
- VERIFICATION: an http/https VIEW+BROWSABLE filter with `android:autoVerify="true"` is a verified App Link -> Compliant on the verification pillar (the assetlinks hosting is a domain fact - see below). On modern targetSdk the system auto-verifies these.
- SANITIZATION: the handler validates link data before any sink - host/path checked against an allowlist or `UriMatcher`, scheme/host asserted, query params type/format-validated, an embedded intent NOT blindly `startActivity`'d, the URL not passed raw to `WebView.loadUrl`. Quote the validating code -> Compliant.
- A custom-scheme deep link CANNOT be verified by assetlinks (that mechanism is http/https only) - do NOT raise a "not autoVerify" finding against a custom scheme; custom-scheme links rely entirely on the sanitization pillar.

Verification failure modes (LV)
- LV1 - Unverified web link: an http/https VIEW+BROWSABLE intent-filter WITHOUT `android:autoVerify="true"` - hijackable by any app registering the same host - and no documented verification process. (targetSdk is recorded; modern targetSdk auto-verifies only when autoVerify is set, so absence of autoVerify is the defect.)
- LV2 - assetlinks not confirmable: `autoVerify="true"` is set but whether `/.well-known/assetlinks.json` is correctly hosted/served cannot be checked from the APK -> `unverified` for the hosting sub-question (the in-APK autoVerify flag is Compliant; the hosting is a domain fact). Do not fail solely on this.

Sanitization failure modes (SAN) - link data reaching a sink without validation
Source (tainted): `getIntent().getData()`, `Uri.getQueryParameter(...)`, `getPathSegments()`/`getLastPathSegment()`, `getIntent().getStringExtra/getParcelableExtra` populated from the link, the raw URI string.
- SAN1 - WebView load: tainted URL/param passed to `WebView.loadUrl`/`loadData`/`loadDataWithBaseURL` (open redirect, local-file/JS load, XSS).
- SAN2 - SQL: tainted value concatenated into a query/selection (SQLi).
- SAN3 - File path: tainted path/segment used to build a `File`/stream without canonicalization (path traversal).
- SAN4 - Intent redirection: an `Intent` parsed from the link (e.g. `Intent.parseUri`, `getParcelableExtra("intent")`) passed to `startActivity`/`startService`/`sendBroadcast` without component/allowlist checks (intent redirection to non-exported/internal components).
- SAN5 - Other dangerous sinks: tainted value to `Runtime.exec`, `DexClassLoader`/reflection, an auth/token flow, or a returned redirect, without validation.

Procedure
1. Read `AndroidManifest.xml`: `targetSdkVersion`, and every component with a link intent-filter (action VIEW + category BROWSABLE + data). Record scheme(s), host(s), path patterns, and `android:autoVerify`. If there are no link intent-filters, the verdict is `n/a`.
2. For each link-handling component, classify VERIFICATION: http/https + autoVerify -> verified (Compliant; hosting is LV2/`unverified`); http/https without autoVerify -> LV1; custom scheme -> not applicable (sanitization-only).
3. **Read the handler body** (`onCreate`, `onNewIntent`, `onStart`, and any routed/helper method) for EVERY link-handling component. Trace the link data from the source to each use, and QUOTE the lines showing either validation/sanitization (Compliant) or a tainted flow to a SAN1-SAN5 sink (Finding). You may not conclude a handler is sanitized without a quoted body; an unread handler is `unverified` on the sanitization pillar (not silently Compliant).
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A library component's own link handling configured per its design is the library's; focus on proprietary handlers and any app-declared link filter.
5. Conclude per link/handler: Finding (LV1 unverified web link with no documented process, OR a SAN1-SAN5 tainted flow with the body quoted); Compliant (verified + sanitized, both quoted); Unverified (handler body unread, assetlinks hosting (LV2), owner, or sensitivity unresolved); documented candidate (verification/sanitization process claimed but only confirmable by an out-of-APK design doc - see rules).
6. Budget ~2-4 reads per link handler (manifest filter, handler body, sink helpers) plus 1-2 call-graph hops. If the handler body, the flow, the owner, or verification can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
The "App Link Verification Tester" is a dynamic/runtime tool and `assetlinks.json` is hosted on the domain (not in the APK); static analysis confirms the in-APK parts (autoVerify flag, handler sanitization) and routes the hosting/runtime parts to `unverified` with `needs_dynamic_testing` as a non-binding flag. Link handling fully inside native code or a no-source SDK -> `unverified`. The static verdict is made on what was determinable.

Output
List **all** app/deep links - one L1 row per link-handling component (or per distinct link), each stating the scheme/host and its verification + sanitization disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant links by functionality (e.g. "verified https product links - 9") as one L1 row per group, but always break out every Finding, documented-candidate, and unverified link as its own individual L1 row. Never sample findings.
- Finding: L1 row plus L2 rows for the verification defect (manifest filter showing no autoVerify) and/or the sanitization defect (the handler body quoted showing tainted link data reaching a SAN sink), plus owner.
- Compliant: L1 row plus L2 for autoVerify (verification) and the quoted validating code (sanitization).
- Group: L1 summary plus an L2 naming references and the shared verified+sanitized pattern.

```
{
  "id": "link-001",
  "description": "Finding (SAN1: link param to WebView; inferred: in-app web view deep link): DeepLinkActivity loads the 'url' query parameter from an incoming link directly into a WebView without validation, enabling open redirect / arbitrary content load.",
  "reference": "AndroidManifest.xml (activity .DeepLinkActivity)",
  "level": 1
},
{
  "id": "L2-DeepLink-filter",
  "description": "Link filter: <activity .DeepLinkActivity> has VIEW+BROWSABLE with <data android:scheme=\"https\" android:host=\"go.example.com\"/> and android:autoVerify=\"true\" (verified). targetSdk=33.",
  "reference": "AndroidManifest.xml:120-130",
  "level": 2
},
{
  "id": "L2-DeepLink-san",
  "description": "Sanitization (body read, SAN1): onCreate does String u = getIntent().getData().getQueryParameter(\"url\"); webView.loadUrl(u); at lines 41-47 - the tainted 'url' param is loaded with no scheme/host allowlist. Tainted link data reaches WebView.loadUrl.",
  "reference": "jadx/sources/com/example/app/DeepLinkActivity.java:38-50",
  "level": 2
},
{
  "id": "L2-DeepLink-owner",
  "description": "Owner: com.example.app (first-party application-id) -> proprietary (obfuscated/undecidable would also default proprietary).",
  "reference": "jadx/sources/com/example/app/DeepLinkActivity.java:1",
  "level": 2
},
{
  "id": "link-verified-group",
  "description": "Compliant group (verified https deep links): 9 links validated against a host/path allowlist before use.",
  "reference": "AndroidManifest.xml (verified links)",
  "level": 1
},
{
  "id": "L2-verified-coverage",
  "description": "Good pattern: each filter is https + autoVerify=\"true\"; LinkRouter.route checks uri.getHost() against ALLOWED_HOSTS and matches the path via UriMatcher before dispatch (quoted LinkRouter.java:30-72), no raw data to WebView/SQL/File/Intent. References (9 filters) AndroidManifest.xml:90-118.",
  "reference": "jadx/sources/com/example/app/LinkRouter.java:30-72",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "L link filters enumerated, V verified (autoVerify), N findings (by mode LV1/SAN1..SAN5), C compliant, U unverified. targetSdk: <n>. <one or two sentences naming the components, schemes/hosts and issues>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag; set true only for the runtime parts (assetlinks hosting, the App Link Verification Tester) recorded as `unverified`. It does not change `pass`/`fail`.
- `fail`: >=1 link with (a) an L2 row showing LV1 (http/https VIEW+BROWSABLE without autoVerify and no documented process) OR a SAN1-SAN5 tainted flow with the handler BODY quoted - showing all three of the source read (`getData`/`getQueryParameter`/...), the propagation, and the sink call (`startActivity`/`loadUrl`/`rawQuery`/`new File`/...); plus the manifest filter evidence and owner. A sanitization finding stated with "likely"/"may"/"appears to"/"suggesting" instead of quoted source-to-sink code is INVALID -> `unverified`.
- **Read the body before concluding sanitization; quote it.** A handler is SAN-clean only if a body you read validates the link data before sinks (allowlist/UriMatcher/scheme-host checks) - quote it. An unread handler is `unverified` on sanitization, never silently Compliant. A SAN finding requires the tainted-flow lines quoted.
- **Custom schemes are not LV1.** Do not flag a custom-scheme deep link for lacking autoVerify (assetlinks is http/https only); judge it on sanitization alone.
- **autoVerify vs assetlinks.** In-APK `autoVerify="true"` satisfies the verification pillar's checkable part; the `assetlinks.json` hosting is a domain fact -> `unverified` (LV2), not a fail.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` is out-of-APK only (assetlinks hosting, a documented sanitization process, runtime-built routing) - in-APK facts (is the param validated? is autoVerify set? are the redirected-to activities sensitive?) must be resolved by reading code/manifest, not hedged here; an unresolved in-APK question is an `unverified` row. In particular, entries like "might be mitigated by other controls not visible in the snippet", "the redirected-to activities might not be sensitive", "might be a deliberate choice by the developer", or "might just be a regular deep link" are INVALID `false_positive_risks` - they are in-APK questions you must resolve by reading (and if you cannot, the affected row is `unverified`, not a Finding-plus-hedge or a pass-plus-hedge).
- `pass`: links exist and every link is verified (autoVerify on http/https; custom schemes exempt from verification) or has a documented process, AND every handler sanitizes link input (quoted), with L2 coverage and targetSdk recorded.
- `n/a`: no link intent-filter is declared (manifest read; state this).
- Documented process clause: the spec allows a documented validation/sanitization design doc (esp. for older targetSdk). That document is outside the APK - if a handler's sanitization is not visible in code but a process is claimed, record the link as a "documented candidate" with a matching `false_positive_risks` entry; it counts toward `fail` unless the assessor confirms the doc. Visible in-code sanitization is judged directly (do not defer to a doc when the code is readable).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped/out-of-scoped without evidence, or if any `fail` lacks its filter + (for SAN) quoted-body L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) for LV1, the manifest filter is http/https VIEW+BROWSABLE with autoVerify absent (and it is not a custom scheme); (2) for SAN, you READ and quoted all three of the source read, the propagation, and the sink call in the handler body, with no validation between them; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge-word scan: search your own SAN findings and rationale for "likely", "may", "appears", "suggesting", "probably", "seems", "is used to", "without validation" (when not backed by a quoted absence-of-check). Any SAN finding whose evidence contains these instead of a quoted source-to-sink chain is downgraded to `unverified`.
Evidence-discipline gate (all rows): every Compliant/sanitized row quotes the validating handler body (not the index or a bare line range); every link handler has its own quoted sanitization disposition; an unread handler is `unverified`.
Before any `pass` or `fail`: confirm no SAN row rests on inference, and no `false_positive_risks` entry describes an in-APK fact you did not resolve (convert to `unverified`) - reject specifically "not visible in the snippet", "might not be sensitive", "might be a deliberate choice", "might just be a regular deep link". Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.