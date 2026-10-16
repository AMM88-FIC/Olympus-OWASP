MASTG-TEST-XXXX

masvs_v1_id    MSTG-CRYPTO-4 (and MSTG-CRYPTO-1 for hardcoded keys)
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Insecure operations in symmetric cryptography (weak algorithm/key size or hardcoded key) (1.2.1.2, static)

What this test looks for
Symmetric cryptography must use a recognized-strong algorithm with a key of at least 128 bits, in a secure mode of operation, and must not rely on a hardcoded symmetric key in a security-sensitive context. Strength is judged against the **ENISA Agreed Cryptographic Mechanisms** reference (allow/deny lists below). This is a fully static evaluation: classify every symmetric-crypto use on three axes — algorithm+mode, key size, and key provenance. Verdict: `pass` (all sensitive symmetric use is >=AES-128 in a secure mode with non-hardcoded keys), `fail` (a weak algorithm/mode, a key <128 bits, or a hardcoded symmetric key in a sensitive context), `n/a` (the app uses no symmetric cryptography), or `inconclusive`.

Source is ground truth. A crypto-API evidence index is a candidate list only — extractors miss the JCA default-mode trap, BouncyCastle engine usage, wrapper crypto utilities, and key bytes pulled from resources/assets/BuildConfig. Confirm every conclusion by reading the call site in `jadx/sources/` and tracing the transformation string, the key size, and the key's origin.

Algorithm / mode strength (per ENISA Agreed Cryptographic Mechanisms)
- Strong (acceptable): AES with key >=128 (AES-128/192/256) in CBC (random IV), CTR, CCM, or GCM; ChaCha20-Poly1305; Camellia >=128. CBC/ECB-less padding PKCS5/PKCS7 with CBC; no padding with CTR/GCM.
- Weak / broken (finding): DES, single DES, 2-key or 3-key Triple-DES / DESede (legacy, effective strength too low), RC4, RC2, Blowfish (64-bit block, Sweet32), IDEA, any non-standard cipher; any AES key <128 bits; **ECB mode for more than a single block** — including the JCA trap where `Cipher.getInstance("AES")` (algorithm only, no mode) defaults to `AES/ECB/PKCS5Padding`. Related insecure method to flag if seen feeding the cipher: a hardcoded/static or zero IV, or a reused GCM nonce.

Key provenance
- Hardcoded (finding in a sensitive context): a `SecretKeySpec`/`SecretKey` built from a byte-array or String literal; key bytes read from a constant field, `BuildConfig`, `strings.xml`, or an asset/raw resource; a key derived as `MD5/SHA(hardcodedString)`; PBKDF2 over a hardcoded password with a static salt and/or trivial iteration count.
- Acceptable provenance: key generated at runtime via `KeyGenerator`/`SecureRandom`; derived from a user secret via a strong KDF (PBKDF2 with adequate iterations + random salt, scrypt, Argon2); or stored/wrapped in AndroidKeyStore (`KeyGenParameterSpec`). AndroidKeyStore-backed keys are best.

Sensitive context (makes a weak algo / hardcoded key a finding)
The cipher/MAC protects credentials, tokens, PII, files, local storage, or network payloads — essentially any confidentiality/integrity purpose. Non-sensitive uses (a non-security checksum, obfuscation of non-secret config) are reportable but benign. Most symmetric crypto is sensitive; require a clear non-security purpose before calling a use benign.

Symmetric-crypto APIs to enumerate
`javax.crypto.Cipher.getInstance(...)` (parse the transformation string), `javax.crypto.KeyGenerator.getInstance(...)`+`.init(size)`, `javax.crypto.spec.SecretKeySpec`/`IvParameterSpec`/`GCMParameterSpec`, `javax.crypto.SecretKeyFactory` (PBKDF2), `javax.crypto.Mac.getInstance("Hmac...")` (keyed — check for hardcoded HMAC keys), Android `KeyGenParameterSpec`/`KeyProperties`, and BouncyCastle/SpongyCastle equivalents (`AESEngine`, `DESEngine`, `DESedeEngine`, `BlowfishEngine`, `RC4Engine`, `CBCBlockCipher`, `PaddedBufferedBlockCipher`, etc.).

Procedure
1. Enumerate every symmetric-crypto site from the evidence index if present, then confirm with grep, e.g. `grep -rEn "Cipher\.getInstance|KeyGenerator|SecretKeySpec|IvParameterSpec|GCMParameterSpec|SecretKeyFactory|Mac\.getInstance|KeyGenParameterSpec|AESEngine|DESEngine|DESedeEngine|BlowfishEngine|RC4Engine" jadx/sources/`. If there are zero symmetric-crypto sites, the verdict is `n/a`.
2. For each `Cipher`/engine site, read the transformation string and classify algorithm + mode (resolve algorithm-only strings to their JCA default — `"AES"` -> ECB). For each `KeyGenerator.init`/`SecretKeySpec`, determine the key size in bits.
3. Trace the key's origin to classify provenance (hardcoded vs generated/derived/keystore). Follow wrapper crypto utilities and `SecretKeySpec` byte sources back to a literal, resource, KDF, or generator.
4. Decide whether the use is in a sensitive context (what data the cipher/MAC protects).
5. Conclude per site: Finding (weak algo/mode, key <128, or hardcoded key in a sensitive context); Compliant (>=AES-128-equivalent in a secure mode with acceptable key provenance); Benign (weak primitive but a clear non-security purpose); or a documented-compat candidate (see rules).
6. Budget ~1-3 reads per site (transformation string, key init/spec, key-origin trace). If the key origin or transformation can't be resolved within the bytecode within budget, mark the site `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Symmetric crypto performed in native code or a no-source third-party SDK can't be classified statically: record an `unverified` row (name the entry point); it is neither finding nor clean. The static verdict is made on what was determinable and is not deferred to runtime.

Output
List **all** symmetric-crypto uses. <=20 uses -> one L1 row each. >20 uses -> group the Compliant and Benign uses by functionality (e.g. "local DB encryption - 5 AES/GCM uses", "non-security checksum - 9 uses") as one L1 row per group, but always break out every Finding, Insufficient, documented-compat candidate, and unverified site as its own individual L1 row regardless of count.
- Finding: L1 row plus L2 rows for the weak element (the transformation string, the key size, or the hardcoded-key source line) and for the sensitive context it protects.
- Compliant: L1 row plus L2 for the transformation/key size and the acceptable key provenance.
- Benign group: L1 summary plus an L2 naming the references and the non-security purpose.

```
{
  "id": "sym-001",
  "description": "Finding: VaultCrypto.encrypt uses AES in ECB mode with a hardcoded key to encrypt stored credentials. Two weak elements: ECB mode and a hardcoded SecretKeySpec.",
  "reference": "jadx/sources/com/example/app/VaultCrypto.java",
  "level": 1
},
{
  "id": "L2-VaultCrypto-algo",
  "description": "Weak mode: Cipher.getInstance(\"AES\") at line 41 resolves to AES/ECB/PKCS5Padding (JCA default). ECB leaks plaintext structure - not acceptable per ENISA Agreed Cryptographic Mechanisms.",
  "reference": "jadx/sources/com/example/app/VaultCrypto.java:38-45",
  "level": 2
},
{
  "id": "L2-VaultCrypto-key",
  "description": "Hardcoded key: new SecretKeySpec(\"0123456789abcdef\".getBytes(), \"AES\") at line 33 - a 128-bit key embedded in the APK. Provenance is hardcoded.",
  "reference": "jadx/sources/com/example/app/VaultCrypto.java:30-36",
  "level": 2
},
{
  "id": "L2-VaultCrypto-context",
  "description": "Sensitive context: VaultCrypto.encrypt is called from CredentialStore.save to encrypt the user's stored password before writing to SharedPreferences.",
  "reference": "jadx/sources/com/example/app/CredentialStore.java:58-66",
  "level": 2
},
{
  "id": "sym-db-group",
  "description": "Compliant group: 5 AES/GCM/NoPadding uses with AndroidKeyStore-backed keys for local database field encryption.",
  "reference": "jadx/sources/com/example/app/db/",
  "level": 1
},
{
  "id": "L2-db-coverage",
  "description": "Strong: Cipher.getInstance(\"AES/GCM/NoPadding\") with keys from KeyGenParameterSpec (AndroidKeyStore, 256-bit) and random 12-byte nonces; references DbCrypto.java:22-90 (and 4 more). Meets ENISA allow-list.",
  "reference": "jadx/sources/com/example/app/db/DbCrypto.java:22-90",
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
  "rationale": "T symmetric-crypto sites enumerated, N findings (algo/mode, keysize, hardcoded), C compliant, B benign, X documented-compat candidates, U unverified. <one or two sentences naming the classes, transformations, key sizes and contexts involved>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set it true only to mark native/no-source-SDK crypto recorded as `unverified`. It does not change `pass`/`fail`.
- `fail`: >=1 sensitive-context site with an L2 row showing a weak algorithm/mode, a key <128 bits, OR a hardcoded key, plus an L2 row showing the sensitive data it protects. Algorithm-only transformation strings (`"AES"`, `"DES"`) MUST be resolved to their JCA default mode before judging.
- `pass`: symmetric crypto is used and every sensitive-context use is on the ENISA allow-list (>=AES-128 or equivalent, secure mode) with acceptable key provenance, with L2 coverage; any weak primitive present is confirmed benign (clear non-security purpose).
- `n/a`: no symmetric-crypto site of any kind exists (enumeration performed and empty).
- Documented third-party-compatibility exception: the spec allows a weak algorithm or shared key when mandated by an external system AND documented. Documentation is outside the APK, so the model cannot grant the exception. Record such a use as an individual Finding row classified "documented-compat candidate", and add a matching `false_positive_risks` entry stating the assessor should downgrade it only if the external-system requirement is documented. It still counts toward `fail` unless the assessor applies the exception.
- `unverified` rows name the deepest unresolved point (or the native/SDK entry point). Such sites are neither findings nor cleans.
- `false_positive_risks` is for factors outside the static artifact only (documented-compat exceptions, a key literal that is actually a non-secret test fixture, provider chosen at runtime). In-APK gaps go in `unverified` rows.
- `inconclusive` if rationale counts don't reconcile with L1 rows (counting grouped uses), if any false_positive_risk references in-APK code, or if any `fail` lacks its L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.