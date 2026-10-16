MASTG-TEST-XXXX

masvs_v1_id    MSTG-CRYPTO-1 (and MSTG-CRYPTO-4)
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Strong cryptography implemented per industry best practices - full primitive inventory (1.2.1.3, static)

What this test looks for
Every cryptographic primitive the app uses must be an approved, correctly applied algorithm: confidentiality via an approved block/stream cipher, integrity via an approved MAC or digital signature, combined confidentiality+integrity via an approved AEAD mode, and key derivation via an approved KDF. Approval is judged against the **ENISA Agreed Cryptographic Mechanisms** reference (allow/deny lists below). Additionally, any non-native (proprietary / homemade / re-implemented) cryptography must have been independently reviewed. This is a fully static, inventory-style evaluation across ALL primitive categories - it is the superset of test 1.2.1.2 (which covers symmetric crypto only). Verdict: `pass` (every primitive is approved and correctly used, and any non-native crypto is independently reviewed), `fail` (an unapproved/misused primitive, or proprietary crypto without independent review), `n/a` (the app implements no cryptography), or `inconclusive`.

Source is ground truth. A crypto-API evidence index is a candidate list only - extractors miss JCA default-mode traps, BouncyCastle engines, wrapper utilities, key/IV provenance, and especially homemade crypto (which uses no crypto API at all - it is loops, XOR, and bit shuffles). The `find_callers` call graph likewise identifies *candidate* caller chains, not confirmed reachability - a chain through reflection, dependency injection, or a callback interface must be confirmed by reading the source. Confirm every conclusion by reading the call site in `jadx/sources/`.

Primitive allow / deny lists (per ENISA Agreed Cryptographic Mechanisms)
- Symmetric confidentiality - approved: AES-128/192/256 in CBC (random IV) / CTR / CCM / GCM; ChaCha20(-Poly1305); Camellia >=128. Deny: DES, 3DES/DESede, RC4, RC2, Blowfish, IDEA, AES-ECB (incl. the `"AES"` algorithm-only JCA default), AES key <128.
- AEAD (confidentiality + integrity) - approved: AES-GCM, AES-CCM, ChaCha20-Poly1305. Preferred where both properties are needed.
- Hashing - approved: SHA-256/384/512, SHA-3, SHA-512/256. Deny for security use: MD2, MD4, MD5, SHA-1, RIPEMD. (A hash for a non-security checksum is benign - see context.)
- MAC / integrity - approved: HMAC-SHA-256/384/512, KMAC, CMAC, GMAC, Poly1305. Deny: HMAC-MD5, HMAC-SHA1 (legacy), a bare hash of (key||message) homemade construction, "encrypt-and-MAC" with a broken hash.
- Digital signature - approved: RSA-PSS >=3072, RSA PKCS#1 v1.5 >=3072 (legacy-acceptable), ECDSA/EdDSA on approved curves (P-256/384/521, Ed25519/Ed448). Deny: RSA <2048, DSA <3072, signatures over MD5/SHA-1.
- Key agreement - approved: ECDH on approved curves, DH >=3072. 
- KDF / password hashing - approved: HKDF, PBKDF2 (adequate iterations + random salt), scrypt, Argon2, bcrypt for passwords. Deny: a single unsalted hash as a KDF, PBKDF2 with trivial iterations or static salt.
- Asymmetric key sizes - approved: RSA >=2048 (3072+ preferred per ENISA), ECC >=256-bit curves. Deny: RSA <2048, ECC <224.

Correct-application checks (an approved primitive used wrongly is still a finding)
- ECB used for multi-block confidentiality (including the `Cipher.getInstance("AES")` default trap).
- Static/zero IV, or reused GCM/CCM nonce.
- Confidentiality without integrity where integrity is needed (CBC/CTR with no MAC handling attacker-modifiable ciphertext) - prefer AEAD.
- Hardcoded keys / static salts (cross-reference 1.2.1.2).
- "MAC-then-nothing", verifying a MAC with a non-constant-time compare, or `String.equals` on a signature.

Non-native / proprietary crypto (the homemade-crypto failure)
Treat as proprietary crypto any confidentiality/integrity routine NOT delegating to a vetted provider (JCA/JCE, AndroidKeyStore, Conscrypt, BouncyCastle/Tink/libsodium): hand-rolled XOR "encryption", custom byte permutation/substitution, a bespoke block-cipher loop, a homemade stream cipher, a custom "hash" or PRNG used for security, or a re-implementation of a standard algorithm in app code. ENISA/industry practice: do not roll your own crypto. Such code is a finding unless it has been independently reviewed - which is a documentation fact outside the APK (see rules).

Cryptographic-primitive APIs to enumerate
`Cipher`, `KeyGenerator`, `KeyPairGenerator`, `SecretKeyFactory`, `SecretKeySpec`, `IvParameterSpec`, `GCMParameterSpec`, `Mac`, `MessageDigest`, `Signature`, `KeyAgreement`, `KeyGenParameterSpec`/`KeyProperties`, `java.security.KeyStore`, `SecureRandom` (entropy for the above); BouncyCastle/SpongyCastle engines and digests; Tink, libsodium/NaCl, Conscrypt. Plus homemade-crypto signatures found by reading code (XOR loops over byte arrays, custom permutation tables) - these have no API to grep.

Procedure
1. Enumerate every crypto-primitive site from the evidence index if present, then confirm with grep, e.g. `grep -rEn "Cipher\.getInstance|KeyGenerator|KeyPairGenerator|SecretKeyFactory|SecretKeySpec|Mac\.getInstance|MessageDigest\.getInstance|Signature\.getInstance|KeyAgreement|KeyGenParameterSpec|KeyStore\.getInstance|BouncyCastle|bouncycastle|spongycastle|Tink|libsodium|lazysodium" jadx/sources/`. Also scan for homemade-crypto signatures (XOR over byte arrays, custom substitution/permutation used on secrets). If there are zero crypto primitives of any kind, the verdict is `n/a`.
2. For each site, identify the primitive and its category (cipher/AEAD/hash/MAC/signature/KDF/key-agreement) and read the algorithm string / key size. Resolve algorithm-only transformations to their JCA default mode.
3. Classify each against the allow/deny lists, then apply the correct-application checks (mode, IV/nonce, integrity pairing, key/salt provenance, comparison).
4. Determine the context by **reading the surrounding code, not just matching the API**. Read the enclosing method and its inputs/outputs to understand *what the primitive is protecting and why it is there* - the data it operates on, where that data comes from, where the result goes. A finding must be justified by this motivation, not by the algorithm name alone: state in plain terms what asset is at risk (e.g. "encrypts the stored OAuth token", "hashes a password before transport", "verifies a license signature"). Security use vs non-security (e.g. a non-security file checksum, an ETag, a cache key, display obfuscation): a deny-list primitive used purely in a non-security role is benign; require a clear, evidenced non-security purpose before calling it benign, and require a clear, evidenced security purpose before calling it a finding. If the surrounding context does not make the purpose determinable, do not assume the worst - mark it `unverified`.
5. For any routine that performs confidentiality/integrity without a vetted provider, classify it as proprietary crypto (finding candidate; independent review is a doc fact).
6. **Classify code ownership, then confirm reachability from proprietary code. Both are mandatory for every finding; a finding without them is invalid.** Two sub-steps, both producing evidence you must cite:

   6a. **Ownership classification (per site).** Decide whether the class containing the primitive is *proprietary* (first-party, the app's own code) or *third-party* (a bundled external SDK). This decision must be evidence-based and stated explicitly for each candidate finding - never asserted. Package-name prefixes are a HINT ONLY, not proof: a namespace that matches a well-known independent SDK is usually third-party, but you must not exclude a site on prefix alone. **OEM / ROM caveat (critical):** in OEM- or ROM-bundled apps, packages whose names resemble the platform/framework (e.g. a `com.android.*`-style prefix) or that look like a generic third-party library are frequently the vendor's OWN first-party code. Do not assume a platform-looking or vendor-looking prefix means third-party or out-of-scope. Confirm ownership by evidence: whether the package belongs to the app's own module/application-id family, shares the app's signing/obfuscation scheme, or is a recognizable independent SDK with its own distinct identity and (often) its own un-obfuscated package structure. **Default rule:** if ownership cannot be determined - especially for obfuscated classes (single-letter / scrambled package and class names) that cannot be traced to either a known third-party SDK or to first-party code - classify it as **proprietary (in scope)**, not third-party. Do not silently drop or "out-of-scope" a site; an undecidable owner defaults to proprietary and must be carried as a finding candidate. State the ownership verdict and its basis in the site's reachability L2 row.

   6b. **Reachability (per site).** A weak primitive is a finding only if proprietary code actually invokes it. Build the caller chain with `find_callers(methods=["<ClassFQN>.<method>"])` (a.k.a. `get_callers`) and walk upward until you either (a) reach a proprietary method that uses or calls into the primitive (reachable -> finding candidate), or (b) determine it is reached only from within an independent third-party SDK's own internals with no proprietary caller, or from no caller at all (Unreachable / not the app's finding). The call graph gives *candidate* callers; confirm reflection/DI chains in source. Test-only, `@Deprecated`-unused, and release-dead `BuildConfig.DEBUG` paths are Unreachable. **You must actually run `find_callers` for each candidate finding and cite the resulting chain in an L2 row** - you may not assert reachability or ownership from the package name. If `find_callers` cannot be run or returns nothing resolvable for a site you have classified proprietary, the site is `unverified` (deepest unresolved point named), not a silent finding and not a silent drop. (Note: a proprietary method that itself *calls a library's* weak crypto - e.g. the app picks `DES` via JCA - IS proprietary use and a finding; "proprietary" refers to who chose/invoked the primitive, not which package implements the algorithm.)
7. Conclude per site: Finding (deny-list primitive, misapplied approved primitive, or proprietary crypto without evidence of review - in a security-relevant context per step 4, with owner classified proprietary per 6a, AND a cited `find_callers` chain from proprietary code per 6b); Compliant (approved primitive correctly applied); Benign (deny-list primitive in a clear non-security role, purpose evidenced from context); Unreachable (weak primitive with no proprietary caller path / dead code / independent-SDK-internal only); documented/review candidate (see rules).
8. Budget ~1-3 reads per site, plus 1-2 `find_callers` hops to establish ownership + proprietary reachability. If a primitive's algorithm, key size, homemade nature, security purpose, owner, OR its reachability from proprietary code can't be resolved within the bytecode within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Crypto performed in native code or a no-source third-party SDK can't be classified statically: record an `unverified` row (name the entry point). Whether a TLS/network primitive belongs here or to a transport-security test is a scoping call - if the app only consumes platform TLS (`HttpsURLConnection`, OkHttp defaults) without choosing primitives, treat it as out of scope for this inventory and note it; custom `SSLContext`/cipher-suite selection IS in scope.

Output
List **all** crypto-primitive uses. <=20 uses -> one L1 row each. >20 uses -> group Compliant and Benign uses by functionality (e.g. "TLS pinning - 4 SHA-256 uses", "local storage - 6 AES/GCM uses") as one L1 row per group, but always break out every Finding, misapplication, proprietary-crypto, review-candidate, and unverified site as its own individual L1 row regardless of count.
- Finding: L1 row plus L2 rows for the unapproved/misused element (algorithm string, key size, homemade routine); for the security-relevant context and motivation (what asset the primitive protects, read from the surrounding code - not inferred from the algorithm name); AND for ownership+reachability (the explicit proprietary-vs-third-party verdict with its basis, plus the `find_callers` caller chain showing proprietary code invokes it). All three L2 rows are mandatory; a finding missing any of them is invalid.
- Compliant: L1 row plus L2 for the primitive and its correct application.
- Unreachable: L1 row plus an L2 noting the weak primitive and that `find_callers` found no proprietary caller path (dead code, or reachable only from library/SDK internals the app never calls).
- Benign group: L1 summary plus an L2 naming the references and the non-security purpose.

```
{
  "id": "crypto-001",
  "description": "Finding: TokenSigner verifies license tokens using MD5. MD5 is a broken hash (deny-list) used in a signature/integrity context.",
  "reference": "jadx/sources/com/example/app/TokenSigner.java",
  "level": 1
},
{
  "id": "L2-TokenSigner-primitive",
  "description": "Unapproved primitive: MessageDigest.getInstance(\"MD5\") at line 28 computes a digest later compared to a server value to validate a license token. MD5 is collision-broken and not approved per ENISA Agreed Cryptographic Mechanisms.",
  "reference": "jadx/sources/com/example/app/TokenSigner.java:24-34",
  "level": 2
},
{
  "id": "L2-TokenSigner-context",
  "description": "Security context: the digest gates feature entitlement in LicenseManager.verify - an integrity decision, so a broken hash is exploitable.",
  "reference": "jadx/sources/com/example/app/LicenseManager.java:70-84",
  "level": 2
},
{
  "id": "L2-TokenSigner-reachability",
  "description": "Ownership + reachability: TokenSigner is in com.example.app (first-party application-id namespace) -> proprietary. find_callers shows TokenSigner.verifyToken <- LicenseManager.verify <- com.example.app.MainActivity.onCreate, all proprietary. The app's own code chose and invokes MD5; not third-party, not dead code. (For an obfuscated class with no resolvable owner, the default would also be proprietary per step 6a.)",
  "reference": "jadx/sources/com/example/app/MainActivity.java:96-104",
  "level": 2
},
{
  "id": "crypto-002",
  "description": "Finding (proprietary crypto): Obfuscator.encrypt XORs payload bytes with a repeating hardcoded key to protect stored auth data. Homemade cipher, not a vetted primitive, no evidence of independent review.",
  "reference": "jadx/sources/com/example/app/Obfuscator.java",
  "level": 1
},
{
  "id": "L2-Obfuscator-primitive",
  "description": "Proprietary crypto: byte-wise XOR loop with key[] at lines 12-19; no JCA/keystore/vetted provider involved. Roll-your-own confidentiality.",
  "reference": "jadx/sources/com/example/app/Obfuscator.java:10-22",
  "level": 2
},
{
  "id": "L2-Obfuscator-context",
  "description": "Security context: output is the stored OAuth refresh token in SecurePrefs.put. Confidentiality-critical.",
  "reference": "jadx/sources/com/example/app/SecurePrefs.java:40-52",
  "level": 2
},
{
  "id": "crypto-hash-group",
  "description": "Compliant group: 6 SHA-256 uses for file-integrity verification and certificate-pin hashing.",
  "reference": "jadx/sources/com/example/app/integrity/",
  "level": 1
},
{
  "id": "L2-hash-coverage",
  "description": "Approved: MessageDigest.getInstance(\"SHA-256\") at FileVerifier.java:33 and PinHasher.java:18 (and 4 more); all in integrity/pinning roles. Meets ENISA allow-list.",
  "reference": "jadx/sources/com/example/app/integrity/FileVerifier.java:30-40",
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
  "rationale": "T primitive sites enumerated across categories (cipher/AEAD/hash/MAC/sig/KDF/KA), N findings, P proprietary-crypto, C compliant, B benign, D unreachable/dead-code, R review-candidates, U unverified. <one or two sentences naming the classes, algorithms and contexts involved>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only to mark native/no-source-SDK crypto recorded as `unverified`. It does not change `pass`/`fail`.
- `fail`: >=1 site with (a) an L2 row showing a deny-list primitive, a misapplied approved primitive (ECB/default-mode, static-IV/reused-nonce, missing integrity, weak comparison, weak key/salt), OR proprietary crypto without evidence of independent review; (b) an L2 row establishing a **security-relevant context and motivation** read from the surrounding code (what asset is protected, not the algorithm name alone); AND (c) an L2 row giving an explicit **ownership verdict (proprietary vs third-party, with its basis) plus a `find_callers` caller chain** from proprietary code. Algorithm-only transformation strings MUST be resolved to their JCA default mode before judging. A weak primitive not reachable from proprietary code (dead code, or only inside an independent SDK's internals the app never calls), or whose context shows a non-security purpose, is Unreachable or Benign and does not drive `fail`.
- **Enforcement - no finding without the three L2 rows.** A candidate finding that lacks the security-context L2 row OR the ownership+`find_callers` reachability L2 row is invalid: downgrade it to `unverified` (naming what was not resolved). Reachability and ownership may NOT be asserted from a package name, an obfuscated class name, or the rationale prose - they must come from an actual `find_callers` result and an evidenced ownership decision cited in L2. If `find_callers` was not run for a site, that site cannot be a finding.
- **Ownership default (OEM-aware).** Classify each candidate's owner as proprietary or third-party from evidence, not prefix. In OEM/ROM apps, vendor packages that resemble platform/framework code or a generic library are often first-party and in scope - do not out-of-scope a site on the basis of a platform-looking or vendor-looking prefix. If the owner is undecidable - including obfuscated classes that trace to neither a known SDK nor first-party code - default to **proprietary (in scope)**; never silently mark such a site out-of-scope.
- **No sampling.** Every finding is its own L1 row. Do not emit a "representative sample" and claim a larger count; the `rationale` finding count MUST equal the number of finding L1 rows actually present (grouping is only for Compliant/Benign uses, never for findings). Claiming N violations while listing fewer is an `inconclusive` condition.
- `pass`: cryptography is used, every security-context primitive is on the ENISA allow-list and correctly applied with L2 coverage, and any non-native crypto is independently reviewed (see review clause); any deny-list primitive present is confirmed benign (clear non-security purpose).
- `n/a`: no cryptographic primitive of any kind exists (enumeration performed and empty).
- Independent-review clause: "non-native crypto independently reviewed" is a documentation fact outside the APK. The model cannot statically confirm a review occurred. Record proprietary/homemade crypto as an individual Finding classified "review-candidate" and add a matching `false_positive_risks` entry stating the assessor should downgrade it only if an independent cryptographic review is documented. It counts toward `fail` unless the assessor applies the exception. (Use of a standard primitive via a vetted provider is NOT proprietary crypto and needs no review evidence.)
- A deny-list hash (MD5/SHA-1) used purely as a non-security checksum (cache key, ETag, dedup id, file-integrity fingerprint) is Benign, not a finding - but you must establish that non-security purpose by **reading the surrounding context in step 4** and stating it in the L2 row. This determination is made in-analysis; it does NOT belong in `false_positive_risks`. Default to treating hashes near tokens/passwords/signatures as security use.
- `unverified` rows name the deepest unresolved point (or the native/SDK entry point). Such sites are neither findings nor cleans.
- `false_positive_risks` is for factors **outside the static artifact only** (undocumented-but-real independent reviews, provider/curve chosen at runtime by server config, OEM framework behavior). Statements about what the in-APK code does or might be for - e.g. "this MD5 might be for caching", "this ECB might be for legacy interop" - are in-APK determinations that must be resolved by reading the code (step 4) and recorded as Benign/Finding/`unverified`; they are INVALID as `false_positive_risks` entries.
- `inconclusive` if rationale counts don't reconcile with L1 rows (counting grouped uses, and with finding count equal to finding rows), if any false_positive_risk references in-APK code, if any candidate finding was dropped or out-of-scoped without an evidenced ownership decision, or if any `fail` lacks its three L2 rows (weak-element, security-context, ownership+reachability).

Self-check before emitting (per finding)
For every site you are about to mark a Finding, confirm: (1) you read the surrounding context and named the protected asset; (2) you made an explicit proprietary-vs-third-party ownership decision from evidence (not prefix), applying the OEM-aware and obfuscated->proprietary defaults; (3) you actually ran `find_callers` and the caller chain is cited in an L2 row. If any is missing, downgrade the site to `unverified`. Then confirm the `rationale` finding count equals the number of Finding L1 rows (no sampling), and that no `false_positive_risks` entry describes in-APK code. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.