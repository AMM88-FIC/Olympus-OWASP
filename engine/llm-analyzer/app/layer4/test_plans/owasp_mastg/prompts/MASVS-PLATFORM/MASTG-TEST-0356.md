MASTG-TEST-0356

maswe_id       MASWE-0064
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          Runtime Verification of Unauthorized Database Access through Content Providers (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0356 is a dynamic test (at runtime, query the app's exported content providers with `ContentResolver` / `adb shell content` and see whether sensitive rows come back without holding a permission). This static engine cannot query a running provider, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0355 (manifest `<provider>` export + read/write permission protection), extended to read the provider's `query`/`openFile` implementation for the data it would return. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only a live query proves what data is actually returned and whether a misconfigured protection level is auto-granted at runtime.

What this test looks for
At runtime no third-party app should be able to read sensitive data from the app's content providers without an adequate permission. Statically, the proxy is an exported provider with no/weak read or write permission whose backing data is sensitive (MASTG-TEST-0355), plus reading the `query` impl to characterize the exposed rows. Verdict: `pass` (no exported provider exposes sensitive data without adequate protection), `fail` (>=1 exported, inadequately-protected provider would return sensitive data), `n/a` (no exported content providers), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate `<provider>` elements (`android:exported="true"`, or legacy default-exported). If none exported -> `n/a`/`pass` (state it). Runtime accessibility is still flagged via the forced `needs_dynamic_testing`.

Adequately protected vs not
Adequate: `android:readPermission`/`writePermission`/`permission` with `signature`/restricted level. Inadequate: missing, or `normal`/`dangerous` (auto/broadly grantable - a malicious app obtains it and the restriction is effectively bypassed).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the `<provider>` config (export + permission + protectionLevel) AND the `query`/`openFile` impl returning sensitive data. No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` and `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the exported+unprotected provider and (b) the sensitive data it serves. "probably returns PII" with no quoted query is NOT static evidence -> `unverified` (flag for the live query).
4. **Unresolved determinacy is `unverified`, not a hedge.** If export/permission/query can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest: enumerate exported `<provider>` and read/write/permission attributes (`grep -nE "<provider|exported|readPermission|writePermission|android:permission|authorities" jadx/resources/AndroidManifest.xml`). Quote each. If none exported -> short-circuit (state it).
2. For each exported provider, classify protection (missing/`normal`/`dangerous` -> inadequate; `signature`/restricted -> adequate). Quote it.
3. For each inadequately-protected provider, read `query`/`openFile`/`getType` to determine the data returned and its sensitivity. Quote it. Sensitive -> finding; clearly public -> Compliant.
4. Owner: app-declared (proprietary).
5. Conclude per provider: Finding (exported + inadequate + sensitive data, quoted); Compliant (adequate/not-exported/public); Unverified (query/protection unresolved -> confirm with a live query).
6. Budget ~2-4 reads per provider. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether the runtime permission is actually auto-granted, and what rows return, is the dynamic test's job - hence the forced `needs_dynamic_testing`. FileProvider path oversharing is MASTG-TEST-0357. Provider logic in native code -> `unverified`.

Output
List **all** exported providers - one L1 row per provider with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group adequately-protected providers, but always break out every Finding and unverified provider individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the exported+unprotected config and the sensitive data the query returns, plus owner.
- Compliant: L1 row plus an L2 showing adequate protection / not-exported / public data.

```
{
  "id": "provrt-001",
  "description": "Finding (provider returns sensitive data without protection): An exported provider with a normal-level permission (auto-granted to any app) returns stored account tokens.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-provrt-manifest",
  "description": "Inadequate protection (quoted): <provider android:authorities=\"com.example.app.tokens\" android:exported=\"true\" android:readPermission=\"com.example.app.READ\"/> with <permission android:name=\"com.example.app.READ\" android:protectionLevel=\"normal\"/> at AndroidManifest.xml:62 + 20 - normal level is auto-granted to any requesting app.",
  "reference": "jadx/resources/AndroidManifest.xml:62",
  "level": 2
},
{
  "id": "L2-provrt-data",
  "description": "Sensitive data returned (quoted): TokenProvider.query returns the oauth_tokens table (access_token, refresh_token) at TokenProvider.java:40-55 - any app obtains the normal permission and reads tokens. Owner: com.example.app (proprietary). Live query confirmation required.",
  "reference": "jadx/sources/com/example/app/TokenProvider.java:40-55",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0356",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "P providers, E exported, A adequately protected, N findings (exported + inadequate + sensitive data), C compliant, U unverified. Any exported provider exposing sensitive data without adequate protection? <no -> pass/n-a / yes -> fail>. <one or two sentences>; live query confirms returned rows.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that a live query is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 provider with (a) an L2 quoting an exported config with missing or `normal`/`dangerous` protection AND (b) an L2 quoting the sensitive data its query returns. A finding stated with "likely"/"may" instead of the quoted config+query is INVALID -> `unverified`.
- **normal/dangerous is bypassable.** A `normal` permission is auto-granted; a `dangerous` one is user-grantable to any app - both inadequate for a trust boundary. Quote the `protectionLevel`.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: no exported provider exposes sensitive data without adequate protection, with L2 coverage.
- `n/a`: no exported content providers (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK evidence, if a finding was dropped without evidence, or if any `fail` lacks its config + sensitive-data L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the exported provider config with its permission/protectionLevel is quoted; (2) the sensitive data its query returns is quoted; (3) the protection is missing or normal/dangerous; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the manifest was read and exported providers enumerated, every finding's query impl was read and quoted (unread -> `unverified`), no adequately-protected provider was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
