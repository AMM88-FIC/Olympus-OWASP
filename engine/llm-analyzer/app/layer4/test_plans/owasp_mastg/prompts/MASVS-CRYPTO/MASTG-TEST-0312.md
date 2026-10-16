MASTG-TEST-0312

maswe_id       MASWE-0020
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          References to Explicit Security Provider in Cryptographic APIs - non-default JCA provider (static)

What this test looks for
Android JCA APIs let callers pin a named security provider on `getInstance(...)`. Pinning a non-default provider is discouraged: legacy providers (`Crypto`, `BC`/BouncyCastle) have been deprecated/removed across releases, and on Android 9+ specifying a provider can throw. The default provider `AndroidOpenSSL` (Conscrypt) is actively maintained and should be used. This is a static evaluation of every JCA `getInstance` call for an explicit, non-default provider. Verdict: `pass` (no JCA call pins a non-default provider - the only allowed named providers are the legitimate exceptions below), `fail` (>=1 JCA `getInstance` pins a non-default/legacy provider), `n/a` (the app uses no JCA crypto APIs), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the JCA `getInstance` APIs below. If NONE appear -> `n/a` (no JCA usage to assess; state the search).

Allowed named providers (NOT a finding)
- `KeyStore.getInstance("AndroidKeyStore")` - the keystore TYPE, not a crypto provider; allowed.
- An explicit `"AndroidOpenSSL"` / `"AndroidKeyStoreBCWorkaround"` where required for KeyStore-bound keys - allowed (it IS the default / the documented workaround).
Any OTHER explicit provider string or `Provider` object - `"BC"`, `"BouncyCastle"`, `"Crypto"`, `"SC"` (SpongyCastle), a bundled custom `Provider` - on `Cipher`/`MessageDigest`/`Mac`/`Signature`/`KeyGenerator`/`KeyPairGenerator`/`SecretKeyFactory`/`KeyFactory`/`KeyAgreement` is a finding.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `getInstance(..., provider)` call showing the pinned provider. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting a JCA `getInstance` whose provider argument is an explicit non-default provider. "may use BouncyCastle" is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the provider argument is computed and can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Provider-bearing sinks
The two-/three-arg `getInstance` overloads taking a provider: `Cipher.getInstance(transform, provider)`, `MessageDigest.getInstance(alg, provider)`, `Mac.getInstance(alg, provider)`, `Signature.getInstance(alg, provider)`, `KeyGenerator`/`KeyPairGenerator`/`SecretKeyFactory`/`KeyFactory`/`KeyAgreement.getInstance(alg, provider)`. The `provider` is a `String` name or a `java.security.Provider` instance (e.g. a constructed `BouncyCastleProvider`). Also flag `Security.addProvider(new BouncyCastleProvider())` + subsequent pinned use.

Procedure
1. Enumerate JCA sites with a provider argument: `grep -rEn "getInstance\([^)]*,[^)]*\)" jadx/sources/` narrowed to crypto classes, plus `grep -rEn "BouncyCastleProvider|SpongyCastle|\"BC\"|\"SC\"|\"Crypto\"|Security\.addProvider|setProvider" jadx/sources/`. If no JCA crypto -> short-circuit `n/a` (state the search).
2. For each provider-bearing call, resolve the provider argument (string literal, constant, or `Provider` instance). Resolve finals; obfuscated/runtime-computed -> `unverified`.
3. Classify: allowed exception (`AndroidKeyStore` type, `AndroidOpenSSL`, documented KeyStore workaround) -> Compliant; any other explicit provider -> finding. Quote the provider.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A bundled third-party SDK pinning its own provider is attributed but reported.
5. Conclude per site: Finding (non-default provider quoted); Compliant (no provider arg, or an allowed exception, quoted); Unverified (provider unresolved).
6. Budget ~1-3 reads per site (the call, any constant holding the provider name, any addProvider registration). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Provider selection inside native code or a no-source SDK -> `unverified` (name the entry point). The algorithm/mode SECURITY (ECB, DES) is covered by 0221/0232; this test flags only explicit PROVIDER pinning. A default `getInstance(alg)` with no provider argument is always Compliant here.

Output
List **all** JCA `getInstance` sites that pin a provider (plus any `addProvider`/`setProvider`) - one L1 row per site with its disposition. Default (no-provider) calls need not each be listed, but state in the rationale that they were reviewed. <=20 provider sites -> one L1 row each. >20 (collapse) -> group Compliant allowed-exception sites by area as one L1 row per group, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus an L2 quoting the `getInstance(..., provider)` call and the non-default provider, plus owner.
- Compliant: L1 row plus an L2 quoting an allowed exception (or noting default no-provider usage).
- Group: L1 summary plus an L2 naming references and the shared (allowed) provider.

```
{
  "id": "ep-001",
  "description": "Finding (explicit non-default provider): The app pins the BouncyCastle (\"BC\") provider on a Cipher call - BC is deprecated/removed on modern Android and can break or behave inconsistently.",
  "reference": "jadx/sources/com/example/app/BcCrypto.java",
  "level": 1
},
{
  "id": "L2-ep-call",
  "description": "Pinned provider (quoted): Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\", \"BC\"); at BcCrypto.java:31 - explicit non-default provider \"BC\" instead of the default AndroidOpenSSL/Conscrypt. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/BcCrypto.java:31",
  "level": 2
},
{
  "id": "ep-ok-001",
  "description": "Not a finding (allowed exception): KeyStore.getInstance(\"AndroidKeyStore\") names the keystore type, not a crypto provider.",
  "reference": "jadx/sources/com/example/app/KeyProvider.java:18",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0312",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "J JCA getInstance sites reviewed, P pin an explicit provider, N findings (non-default/legacy provider), A allowed exceptions (AndroidKeyStore/AndroidOpenSSL), U unverified. Any JCA crypto present? <no -> n/a / yes>. <one or two sentences naming each pinned provider>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 JCA `getInstance` (or `Provider` registration + use) quoted pinning an explicit non-default provider (`BC`, `Crypto`, `SC`, a custom `Provider`). A finding stated with "likely"/"may" instead of the quoted provider is INVALID -> `unverified`.
- **Allowed exceptions are not findings.** `KeyStore.getInstance("AndroidKeyStore")`, an explicit `AndroidOpenSSL`, or the documented `AndroidKeyStoreBCWorkaround` are Compliant. Counting them as findings makes the verdict `inconclusive`-worthy.
- **Provider pinning only.** Whether the algorithm/mode is itself weak is 0221/0232; here only the PROVIDER argument is judged.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (which provider? is it an allowed exception?) resolved by reading, unresolved -> `unverified`.
- `pass`: no JCA call pins a non-default provider (only allowed exceptions / default no-provider calls), with L2/rationale coverage.
- `n/a`: no JCA crypto APIs appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if an allowed exception was counted as a finding, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its quoted `getInstance(..., provider)` call.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `getInstance(..., provider)` call (or `Provider` registration + use) is quoted; (2) the provider is an explicit non-default provider, NOT an allowed exception; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`. Exception scan: confirm no `AndroidKeyStore`/`AndroidOpenSSL` site was counted as a finding.
Before any `pass`/`fail`/`n/a`: confirm the JCA + provider searches were performed (n/a / pass state them), every provider-bearing call's provider was read and quoted (unread -> `unverified`), allowed exceptions excluded, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
