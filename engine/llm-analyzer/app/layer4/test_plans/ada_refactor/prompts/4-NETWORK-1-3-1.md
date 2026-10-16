MASTG-TEST-XXXX

masvs_v1_id    MSTG-NETWORK-3
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Endpoint identity verified on network connections (correct server-cert validation, no user-CA trust) (static)

What this test looks for
Connections carrying sensitive data must correctly validate the server's identity: validate the certificate chain to a trusted CA, verify the hostname, NOT trust user-installed CAs for sensitive data (which requires `targetSdkVersion >= 24`, where user CAs are not trusted by default), and - if the system CA store is not used - apply an alternative mechanism (certificate pinning). This is a static, inventory-style evaluation over the manifest, the network-security-config (NSC), and the app's TLS/trust code. Verdict: `pass` (sensitive connections validate correctly, no user-CA trust, pinning where the system store is not used), `fail` (trusts user-installed certs, or does not correctly validate endpoint identity, on sensitive connections), `n/a` (the app transmits no sensitive data over the network), or `inconclusive`.

This test is about **identity/authentication of the endpoint only**. Cleartext (no TLS) and weak protocol/cipher negotiation are the separate cleartext and TLS-strength tests; mention overlaps but do not base this verdict on them.

The good pattern (do not flag)
Default platform validation is correct and secure: `HttpsURLConnection`, OkHttp, Retrofit, Ktor used with **no custom `TrustManager`/`HostnameVerifier`/`SSLSocketFactory` override**, on `targetSdk >= 24`, with no NSC or an NSC that trusts only the system store -> **Compliant**, do not flag. A custom `TrustManager` that actually validates (delegates to the platform default, or pins) and a custom `HostnameVerifier` that actually checks the host are Compliant - **you MUST read the body** before concluding; the mere existence of a custom trust manager or verifier is NOT a finding. OkHttp `CertificatePinner`, NSC `<pin-set>`, and TrustKit are strong and satisfy the alternative-mechanism requirement. Absence of pinning is NOT a finding when the system CA store is used with correct validation - pinning is required only when the system store is NOT used.

Source is ground truth. A network/trust evidence index is a candidate list only - confirm the manifest `targetSdkVersion`, the NSC contents, and every custom trust/verify implementation by reading `jadx/sources/`, `AndroidManifest.xml`, and `res/xml/*network*security*config*.xml`. The `find_callers`/`find_callees` call graph gives *candidate* chains, not confirmed flow.

Scope - sensitivity
In scope: connections whose inferred purpose carries sensitive data (auth, tokens/credentials, payment, account, PII, user files). Out of scope by purpose: anonymous analytics/ads, free-browsing WebViews. Note: a **global** validation bypass (a trust-all manager installed on the default `SSLContext`, or on a shared client used for sensitive traffic) is IN scope because it undermines the sensitive connections too - judge by whether sensitive traffic can ride the weakened path.

Failure modes (each is a finding on a sensitive connection)
- EV1 - User-CA trust by default: `targetSdkVersion < 24` (user-installed CAs are trusted by default) and no NSC removes that trust and the sensitive connection is not pinned. (targetSdk >= 24 is the required baseline.)
- EV2 - NSC trusts user certs: a network-security-config with `<trust-anchors><certificates src="user"/></trust-anchors>` in `<base-config>` or a `<domain-config>` covering a sensitive domain. (NOTE: `<debug-overrides>` trust anchors apply ONLY to debuggable builds - user-cert trust there is NOT a finding for a release/non-debuggable build; check `android:debuggable`.)
- EV3 - Trust-all TrustManager: a custom `X509TrustManager` whose `checkServerTrusted` is empty / returns without throwing / accepts any chain, installed on a client used for sensitive traffic. Confirm by READING the method body (an empty body or a `return;`/no validation is the bypass).
- EV4 - Permissive HostnameVerifier: a `HostnameVerifier` whose `verify` returns `true` unconditionally, `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER`/`AllowAllHostnameVerifier`, or OkHttp `hostnameVerifier { _, _ -> true }`, on a sensitive client.
- EV5 - WebView ignores cert errors: `WebViewClient.onReceivedSslError` calling `handler.proceed()` (instead of `cancel()`) for sensitive content.
- EV6 - Custom non-system trust without pinning: the app uses a non-system trust source (bundled keystore / custom CA) for sensitive traffic without an alternative integrity mechanism (no pinning), where the spec requires one.

Trust/verify APIs to enumerate
`javax.net.ssl.X509TrustManager`/`TrustManager` (custom impls - read `checkServerTrusted`), `SSLContext.init(.., TrustManager[], ..)`, `HostnameVerifier`/`HttpsURLConnection.setDefaultHostnameVerifier`/`setHostnameVerifier`, `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER`; OkHttp `OkHttpClient.Builder().sslSocketFactory(...)`/`hostnameVerifier(...)`/`CertificatePinner`; `WebViewClient.onReceivedSslError`; NSC `<trust-anchors>`/`<certificates src=...>`/`<pin-set>`/`<debug-overrides>`; TrustKit / Conscrypt pinning; manifest `targetSdkVersion`, `networkSecurityConfig`, `debuggable`.

Procedure
1. Read the manifest `targetSdkVersion`, `android:debuggable`, and the `networkSecurityConfig` reference; read the NSC XML and record trust-anchors (system vs user), any `<pin-set>`, and whether user-cert trust is in `<base-config>`/`<domain-config>` (effective) vs `<debug-overrides>` (debug-only).
2. Enumerate custom trust/verify code, e.g. `grep -rEn "X509TrustManager|checkServerTrusted|TrustManager\[\]|SSLContext|HostnameVerifier|ALLOW_ALL_HOSTNAME|setHostnameVerifier|sslSocketFactory|CertificatePinner|onReceivedSslError|TrustKit" jadx/sources/`. If there are no sensitive network connections at all, the verdict is `n/a`.
3. For each custom `TrustManager`/`HostnameVerifier`/`onReceivedSslError`, **read the full method body** to decide whether it actually validates (Compliant) or bypasses (Finding). Do not conclude from the class's existence; an empty/permissive body is the finding, a delegating/pinning/checking body is Compliant.
4. **Infer the purpose/sensitivity** of each affected connection from context (host, path, data, calling code). Record the inferred purpose. A bypass on a sensitive connection (or a global bypass reaching sensitive traffic) is in scope; a bypass confined to a non-sensitive connection is Out-of-scope (note it). Indeterminate -> `unverified`.
5. Cross the declarative posture with code: EV1 (targetSdk<24 unoverridden), EV2 (NSC user trust effective), EV3-EV5 (code bypass), EV6 (custom trust without pinning).
6. **Ownership + reachability (mandatory for a `fail`).** Confirm proprietary code installs/uses the weak trust on a live sensitive client with `find_callers`/source, and cite it. (Third-party network libs the app configures are in scope; an independent SDK's own internal trust the app does not configure is the SDK's posture - note but do not fail the app on it.) Owner undecidable/obfuscated -> proprietary (in scope); never silently dropped. A `fail` without an evidenced owner + cited path is invalid -> `unverified`.
7. Conclude per connection/trust site: Finding (EV1-EV6 on sensitive traffic, proprietary & reachable); Compliant (default validation, or genuine custom validation/pinning); Out-of-scope (bypass confined to non-sensitive traffic); Dead-code-Unreachable (a real validation bypass exists in proprietary code but you have CONFIRMED, with a cited `find_callers` result showing no proprietary caller reaches it, that it is not on any live path - see the strict bar below); Unverified (purpose/owner/reachability/body unresolved); documented candidate (see rules).

   **Strict bar for excusing a bypass as dead code.** A trust-all `TrustManager`, permissive `HostnameVerifier`, or `onReceivedSslError`->proceed present in proprietary code is a serious latent weakness. You may classify it Dead-code-Unreachable ONLY if you ran `find_callers` on the bypass's methods/class and the result shows no proprietary caller, AND you cite that `find_callers` result in the L2 row (the same evidence bar as a finding's reachability row). A prose assertion like "static analysis indicates this class is not used" WITHOUT a cited call-graph result is NOT sufficient - default to `unverified` instead. If reachability is in any doubt - the class is obfuscated and dispatch is unclear, or it could be invoked via reflection / dependency injection / dynamic loading - the disposition is **`unverified`** (deepest unresolved point = the suspected dynamic/reflective dispatch site), NOT a clean pass. Do NOT dismiss a bypass as dead code and then hedge the residual doubt in `false_positive_risks`; that doubt is an in-APK gap and belongs in an `unverified` row. A bypass present in shipped proprietary code that you cannot prove unreachable keeps the verdict out of `pass`.
8. Budget ~2-4 reads per non-trivial site (manifest/NSC once, then each trust/verify body) plus 1-2 call-graph hops. If a body, the effective trust posture, the purpose, the owner, or reachability can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Trust handling fully inside native code or a no-source SDK can't be classified statically -> `unverified` (name the entry point). The actual server cert/chain is a runtime fact; static judges the app's validation behavior (the test's scope). The static verdict is made on what was determinable and is not deferred to runtime.

Output
List **all** network/trust uses - one L1 row per connection or trust site, **each stating the inferred purpose**. <=20 -> one L1 row each. >20 -> group Compliant/Out-of-scope uses by functionality (e.g. "API clients on default validation, targetSdk 33 - 12 uses") as one L1 row per group with the shared purpose, but always break out every Finding, documented-candidate, and unverified site as its own individual L1 row. Never sample findings.
- Finding: L1 row (inferred purpose) plus L2 rows for the failure (the targetSdk/NSC/trust-manager/verifier/WebView evidence, with the relevant method body quoted for a code bypass), for the sensitive-purpose context, and for ownership+`find_callers` reachability.
- Compliant: L1 row (inferred purpose) plus L2 for the default/genuine validation or pinning.
- Group: L1 summary with shared purpose plus an L2 naming references and the posture.

```
{
  "id": "id-001",
  "description": "Finding (EV3 trust-all TrustManager; inferred purpose: API/auth): A custom X509TrustManager with an empty checkServerTrusted is installed on the shared OkHttpClient used for authenticated API calls, disabling certificate validation.",
  "reference": "jadx/sources/com/example/app/net/TrustAllManager.java",
  "level": 1
},
{
  "id": "L2-TrustAll-body",
  "description": "Bypass (body read): TrustAllManager.checkServerTrusted(X509Certificate[], String) at lines 14-16 has an empty body (no chain validation, never throws). getAcceptedIssuers returns new X509Certificate[0]. This accepts any server certificate.",
  "reference": "jadx/sources/com/example/app/net/TrustAllManager.java:10-22",
  "level": 2
},
{
  "id": "L2-TrustAll-install",
  "description": "Applied to sensitive client: SSLContext.init(null, new TrustManager[]{new TrustAllManager()}, null) -> sslSocketFactory on the OkHttpClient that ApiService (login, /account) uses. Sensitive traffic rides the unvalidated path.",
  "reference": "jadx/sources/com/example/app/net/NetModule.java:55-72",
  "level": 2
},
{
  "id": "L2-TrustAll-reachability",
  "description": "Ownership + reachability: TrustAllManager/NetModule are first-party (app namespace) -> proprietary (obfuscated/undecidable would also default proprietary). find_callers: NetModule.client <- ApiService.<init> <- LoginRepository.login. Live in proprietary code on sensitive calls.",
  "reference": "jadx/sources/com/example/app/data/LoginRepository.java:40-50",
  "level": 2
},
{
  "id": "id-default-group",
  "description": "Compliant group (inferred purpose: API + CDN): 12 clients on default platform validation, targetSdk 33, no custom TrustManager/HostnameVerifier, NSC trusts system store only.",
  "reference": "jadx/sources/com/example/app/net/",
  "level": 1
},
{
  "id": "L2-default-coverage",
  "description": "Good pattern: OkHttp/Retrofit built without sslSocketFactory/hostnameVerifier overrides; manifest targetSdkVersion=33 (user CAs not trusted by default); res/xml/network_security_config.xml has no user trust-anchors and no debug-overrides in effect. References NetModule.java:20-110 (and 11 more).",
  "reference": "jadx/sources/com/example/app/net/NetModule.java:20-110",
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
  "rationale": "C connections/trust sites enumerated, S sensitive-in-scope, N findings (by mode EV1..EV6), K compliant, O out-of-scope, U unverified. Manifest targetSdk + NSC trust posture: <summary>. <one or two sentences naming the sites, purposes and failures>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only where the trust behavior is runtime-driven (recorded `unverified`). It does not change `pass`/`fail`.
- `fail`: >=1 sensitive connection/trust site with (a) an L2 row showing a failure mode EV1-EV6 (for a code bypass, the relevant method BODY is read and quoted - empty/permissive); (b) an L2 row establishing the sensitive inferred purpose from context (or that a global bypass reaches sensitive traffic); AND (c) an L2 row giving an evidenced proprietary-ownership + `find_callers` reachability determination.
- **Read the body before flagging.** A custom `TrustManager`/`HostnameVerifier`/`onReceivedSslError` is a finding ONLY if its body actually bypasses validation (empty `checkServerTrusted`, `verify` returning true, `handler.proceed()` on error). A delegating/pinning/host-checking body is Compliant. Do not flag on the existence of a custom implementation - quote the bypassing body.
- **A bypass cannot be dismissed as dead code without cited proof, and doubt blocks `pass`.** When you find a real bypass body in proprietary code, you may only classify it Dead-code-Unreachable with a cited `find_callers` result showing no proprietary caller. Without that cited result -> `unverified`. If the class is obfuscated with unclear dispatch, or reachable-via-reflection/DI cannot be ruled out, -> `unverified` (not `pass`). A reflection/dynamic-dispatch doubt is an in-APK gap (`unverified`), never a `false_positive_risks` entry. A proprietary bypass not proven unreachable keeps the verdict out of `pass` (it is at least `unverified`/`inconclusive`, or a Finding if any sensitive path is shown).
- **Do not flag default validation, and do not require pinning when the system store is used.** Default platform validation on targetSdk>=24 is Compliant. Pinning is required only for non-system trust (EV6); its absence is not otherwise a finding.
- **targetSdk and debug-overrides.** `targetSdk < 24` without NSC override is EV1. NSC user-cert trust counts only if effective for the build - `<debug-overrides>` applies to debuggable builds only; do not treat debug-overrides user trust as a release finding (check `android:debuggable`).
- **Enforcement / no sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: a finding missing the purpose or ownership+reachability L2 -> `unverified`; every row states an inferred purpose; finding count = finding rows; undecidable/obfuscated owner -> proprietary; `false_positive_risks` is for out-of-APK factors only (documented justification, trust config delivered at runtime, OEM behavior) - in-APK facts must be resolved by reading code, not hedged here.
- `pass`: sensitive connections validate correctly (default or genuine custom), targetSdk>=24 (or NSC removes user trust), no effective user-CA trust, pinning where the system store is not used, with L2 coverage and the targetSdk/NSC posture summarized.
- `n/a`: the app transmits no sensitive data over the network (enumeration performed; state this).
- Documented exception: a documented justification (e.g. pinning to a private CA by design) is a documentation fact outside the APK - record borderline EV6 as a Finding "documented candidate" with a matching `false_positive_risks` entry; counts toward `fail` unless the assessor downgrades it.
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any row lacks an inferred purpose, if any false_positive_risk references in-APK code, if a candidate finding was dropped/out-of-scoped without evidence, or if any `fail` lacks its three L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the failure mode is evidenced - for a code bypass you READ and quoted the bypassing body (not the class's existence); for EV1/EV2 you cited targetSdk/NSC and confirmed it is effective (not debug-only); (2) the sensitive purpose / global-reach was read from context; (3) an evidenced proprietary-ownership decision was made AND `find_callers` was run and cited. If any is missing, downgrade to `unverified` or Compliant. Confirm every row carries an inferred purpose, counts reconcile (no sampling), and no `false_positive_risks` entry describes in-APK code.
Additional check before any `pass`: if you found a real bypass body anywhere in proprietary code, confirm you are NOT dismissing it as dead code on a bare assertion - either it has a cited `find_callers` result proving no proprietary caller (Dead-code-Unreachable, pass allowed) or it is `unverified` (pass NOT allowed; verdict is at least `inconclusive`). A reflection/DI reachability hedge in `false_positive_risks` means you must convert that site to `unverified`. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.