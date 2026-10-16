MASTG-TEST-0282

maswe_id       MASWE-0052
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Unsafe Custom Trust Evaluation - permissive custom X509TrustManager (static)

What this test looks for
A custom `TrustManager` (`X509TrustManager`) whose `checkServerTrusted(...)` does not properly validate the server certificate chain disables certificate validation for every connection using it - accepting any (even self-signed) certificate and enabling a MITM. This is a static evaluation of every custom `X509TrustManager`/`checkServerTrusted` implementation. Verdict: `pass` (no custom TrustManager, or every custom one validates properly), `fail` (>=1 custom `checkServerTrusted` does not validate - empty body, always-accepts, swallowed exception, `checkValidity()`-only, or `getAcceptedIssuers` returning null/empty in a way that disables validation), `n/a` (the app defines no custom TrustManager - the platform default validates), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `X509TrustManager`/`checkServerTrusted`/`TrustManager`. If NONE appear -> `n/a` (platform default trust; state the search).

Unsafe patterns (any one -> finding)
- **No-op body**: `checkServerTrusted` returns immediately / empty body - no validation.
- **Always accept**: catches and ignores, or otherwise never throws on an invalid chain.
- **Swallowed exception**: wraps validation in try/catch and suppresses `CertificateException` without rethrowing/aborting.
- **`checkValidity()`-only**: calls only `cert.checkValidity()` (expiry check) instead of full chain + trust validation.
- **Misused `getAcceptedIssuers()`**: returns `null` or empty without proper handling, effectively disabling issuer validation.
- **Delegates to nothing**: does not delegate to the platform default `X509TrustManager`.

Compliant: delegates to the system default `X509TrustManager` (e.g. obtained from `TrustManagerFactory.getInstance("X509").init((KeyStore) null)`) and rethrows on failure, OR implements correct pinned-chain validation that throws `CertificateException` on mismatch.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `checkServerTrusted` body (and `getAcceptedIssuers`) showing the unsafe pattern, AND its wiring into an `SSLContext`/client. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual method body, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting the permissive `checkServerTrusted` (the actual body). "probably accepts all" is NOT evidence -> `unverified`. A TrustManager that delegates and rethrows is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the body or wiring can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate custom TrustManagers: `grep -rEn "X509TrustManager|checkServerTrusted|checkClientTrusted|getAcceptedIssuers|TrustManagerFactory|init\(.*TrustManager" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each custom `checkServerTrusted`, read the FULL body. Match against the unsafe patterns. Quote the body.
3. Confirm the TrustManager is actually WIRED into a live `SSLContext`/socket factory/client used for app traffic (`sslContext.init(null, new TrustManager[]{tm}, ...)`, `setSSLSocketFactory(...)`). An unused TrustManager class is not a live finding (note it). Quote the wiring.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A permissive TrustManager inside a third-party SDK that governs app traffic is reported.
5. Conclude per TrustManager: Finding (unsafe body + wiring quoted); Compliant (delegates+rethrows or correct pinned validation, quoted); Unverified (body/wiring unresolved).
6. Budget ~2-4 reads per TrustManager (the body, getAcceptedIssuers, the SSLContext wiring). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
TrustManager logic inside native code or a no-source SDK -> `unverified` (name the entry point). Hostname verification is MASTG-TEST-0234/0283; WebView SSL errors are MASTG-TEST-0284. This test is the custom TRUST evaluation (certificate-chain validation).

Output
List **all** custom TrustManagers - one L1 row per TrustManager with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group compliant delegating TrustManagers by area, but always break out every Finding and unverified TrustManager individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the unsafe `checkServerTrusted` body and the SSLContext wiring, plus owner.
- Compliant: L1 row plus an L2 quoting the delegate+rethrow / correct pinned validation.

```
{
  "id": "tm-001",
  "description": "Finding (trust manager that does nothing): A custom X509TrustManager's checkServerTrusted has an empty body, so all server certificates are accepted (MITM).",
  "reference": "jadx/sources/com/example/app/net/TrustAll.java",
  "level": 1
},
{
  "id": "L2-tm-body",
  "description": "Unsafe body (quoted): public void checkServerTrusted(X509Certificate[] chain, String authType) { } and public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; } at TrustAll.java:18-26 - no validation, never throws.",
  "reference": "jadx/sources/com/example/app/net/TrustAll.java:18-26",
  "level": 2
},
{
  "id": "L2-tm-wire",
  "description": "Wiring (quoted): SSLContext ctx = SSLContext.getInstance(\"TLS\"); ctx.init(null, new TrustManager[]{ new TrustAll() }, new SecureRandom()); client.setSSLSocketFactory(ctx.getSocketFactory()) at HttpFactory.java:50-55 - the permissive TM governs API traffic. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/net/HttpFactory.java:50-55",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0282",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "T custom TrustManagers, W wired into live SSL contexts, N findings (no-op / always-accept / swallowed-exception / checkValidity-only / bad getAcceptedIssuers), C compliant (delegate+rethrow / pinned), U unverified. Any custom TrustManager? <no -> n/a / yes>. <one or two sentences naming each unsafe TM>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (MITM is MASTG-TEST-0244); it does not change `pass`/`fail`.
- `fail`: >=1 custom `checkServerTrusted` with (a) an L2 row quoting an unsafe body AND (b) an L2 row quoting its wiring into a live SSLContext/client. A finding stated with "likely"/"may" instead of the quoted body is INVALID -> `unverified`.
- **Wiring matters.** An unsafe TrustManager class that is never wired into a live SSLContext used for app traffic is not a live finding - note it as Compliant/Unverified, not a Finding (unless reachable). State the wiring.
- **Delegate+rethrow is Compliant.** Wrapping the platform default and rethrowing on failure (e.g. for logging or pinning) is fine.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (the TM is debug-only and stripped in release - only if quoted/proven) - in-APK facts (what does the body do? is it wired?) resolved by reading, unresolved -> `unverified`.
- `pass`: no custom TrustManager, or every custom one validates properly (delegates+rethrows or pinned), with L2 coverage.
- `n/a`: no custom TrustManager appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its body + wiring L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the unsafe `checkServerTrusted` body (and getAcceptedIssuers) is quoted; (2) the wiring into a live SSLContext/client is quoted; (3) it governs app traffic (not dead code); (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the TrustManager search was performed (n/a / pass state it), every custom body AND its wiring were read and quoted (unread -> `unverified`), no delegating TM was miscounted as a Finding, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
