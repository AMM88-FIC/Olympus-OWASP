MASTG-TEST-XXXX

masvs_v1_id    MSTG-CRYPTO-2
masvs_v2_id    MASVS-CRYPTO-1
platform       android
title          Cryptographic keys used only for their defined purpose (no cross-purpose reuse) (1.2.1.4, static)

What this test looks for
Every cryptographic key must serve exactly one purpose: confidentiality (encryption/decryption), integrity/authenticity (signing/verification), or maintenance/key-protection (key wrapping, key agreement, import/export). A single key reused across more than one of these purpose categories is the failure. This is a fully static, inventory-style evaluation: build a map of every key (variable / field / AndroidKeyStore alias) to all of its uses, then flag any key whose use set spans more than one purpose category. Verdict: `pass` (every key is used for one purpose only), `fail` (at least one key crosses purpose boundaries, by declaration or by use), `n/a` (the app manages no cryptographic keys), or `inconclusive`.

Source is ground truth. A crypto-API evidence index is a candidate list only - it does not track a key object across methods, fields, and keystore aliases. Confirm every conclusion by reading the key's materialization and each consumer in `jadx/sources/`, and by tracing the key through wrappers. The `find_callees`/`find_callers` call graph identifies *candidate* uses and caller chains, not confirmed data flow - confirm key identity (same object/alias actually reaching the consumer) by reading the source.

Purpose categories (the boundaries that must not be crossed)
- C - Confidentiality: a key used by `Cipher` in `ENCRYPT_MODE` / `DECRYPT_MODE`.
- I - Integrity / authenticity: a key used by `Mac` (HMAC), or by `Signature` (`initSign` / `initVerify`).
- M - Maintenance / key-protection: a key used by `Cipher` in `WRAP_MODE` / `UNWRAP_MODE`, by `KeyAgreement`, or as a key-encryption/transport key for import/export into a KeyStore.
Within one category there is no violation: encrypt+decrypt is one C purpose; sign+verify (incl. an HMAC key doing both) is one I purpose; wrap+unwrap is one M purpose. A violation is one key spanning two categories - the canonical case being a single key used both to encrypt data (C) and to MAC it (I), instead of two derived keys.

NOT violations (do not flag these)
- **AEAD is a single purpose.** AES-GCM, AES-CCM, ChaCha20-Poly1305 give confidentiality AND integrity from one key in one operation. That is one C(+integrity) purpose, not key reuse. Do not flag a single AEAD key as serving two purposes.
- **HMAC sign+verify with the same key** is normal symmetric integrity - one I purpose.
- **A KDF master key (HKDF/PBKDF2) used only to derive sub-keys** is one M/derivation purpose; the derived keys are distinct keys. Proper separation, not reuse. (Only flag if a *derived* key is itself then reused across categories.)
- **An asymmetric keypair** where the private key signs and the public key verifies is one I purpose; encrypt with public / decrypt with private is one C purpose. The violation is the *same* keypair used for both signing AND encryption (e.g. RSA-PSS and RSA-OAEP on one key).

Key materialization sources (where a key comes into being - the left side of the map)
`javax.crypto.spec.SecretKeySpec`, `KeyGenerator.generateKey`, `KeyPairGenerator.generateKeyPair`, `SecretKeyFactory.generateSecret` (PBKDF2), `KeyStore.getKey` / `getEntry` (by alias), `android.security.keystore.KeyGenParameterSpec.Builder(alias, purposes)` (read the purposes bitmask), key bytes loaded from resources/assets/network. Track each by its variable, field, or keystore alias string.

Procedure
1. Enumerate every key materialization from the evidence index if present, then confirm with grep, e.g. `grep -rEn "SecretKeySpec|KeyGenerator|KeyPairGenerator|SecretKeyFactory|KeyGenParameterSpec|KeyStore\.getInstance|\.getKey\(|\.getEntry\(|setKeyEntry|setEntry" jadx/sources/`. If there are zero key materializations of any kind, the verdict is `n/a`.
2. **Declaration check (AndroidKeyStore).** For each `KeyGenParameterSpec`, read the purposes bitmask. A single spec combining categories - `PURPOSE_ENCRYPT`/`PURPOSE_DECRYPT` together with `PURPOSE_SIGN`/`PURPOSE_VERIFY` (or with `PURPOSE_WRAP_KEY`/`PURPOSE_AGREE_KEY`) - authorizes the key for mixed purposes and is a finding by declaration, even before tracing uses. `PURPOSE_ENCRYPT|PURPOSE_DECRYPT` alone is fine (one C purpose); `PURPOSE_SIGN|PURPOSE_VERIFY` alone is fine (one I purpose).
3. **Use tracing.** For each key, trace it forward to every consumer - `Cipher.init` (the mode argument gives C vs M), `Mac.init` (I), `Signature.initSign`/`initVerify` (I), `KeyAgreement.init` (M), `Cipher` wrap/unwrap (M). Follow the key through assignments, returns, fields, and wrapper helpers (read a wrapper's body once). For keystore keys, track the **alias string**: the same alias fetched and used in two purpose categories is reuse. Use `find_callees` on the key-holding method to locate candidate consumers, then confirm in source that the same key reaches them.
4. **Read the surrounding context** of each consumer to confirm the purpose category (e.g. a `Cipher.init(ENCRYPT_MODE, key)` that is actually wrapping another key is M, not C - the mode and the plaintext argument tell you which). Base the purpose on what the operation does, not the API name alone.
5. **Reachability from proprietary code.** A cross-purpose key is the app's finding only if proprietary (first-party) code performs the reuse. Treat library/SDK namespaces as non-proprietary (`androidx.`, `android.`, `com.google.`, `okhttp3.`, `org.bouncycastle.`, etc.); the proprietary namespace is the app's own application id and first-party modules. Use `find_callers` to confirm a proprietary method materializes and/or uses the key across purposes. A key whose multi-purpose use exists only inside vendored library internals the app never drives, or in dead/test/`BuildConfig.DEBUG`-only code, is classified Unreachable, not a finding.
6. Conclude per key: Finding (one key spanning >=2 purpose categories, by declaration or by use, in proprietary reachable code); Compliant (key used in exactly one category); Unreachable (multi-purpose use only in dead/library/test code); documented candidate (see rules).
7. Budget ~2-4 reads per key (materialization + each distinct consumer) plus 1-2 call-graph hops. If a key's identity across methods, a consumer's purpose, or proprietary reachability can't be resolved within the bytecode within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Key use inside native code or a no-source third-party SDK can't be traced statically: record an `unverified` row (name the entry point / SDK method). The static verdict is made on what was determinable and is not deferred to runtime.

Output
List the **assignment of variables to cryptographic keys and their subsequent use** - one L1 row per key mapping it to its uses. <=20 keys -> one L1 row each. >20 keys -> group Compliant keys by use/functionality (e.g. "DB field keys - 6 keys, C only", "JWT signing keys - 3 keys, I only") as one L1 row per group, but always break out every Finding (cross-purpose key), documented-candidate, and unverified key as its own individual L1 row regardless of count.
- Finding: L1 row plus L2 rows for the key materialization (the variable/field/alias) and for each of the >=2 distinct-category uses (or, for a declaration finding, the mixed purposes bitmask) AND a reachability L2 showing proprietary code performs the reuse.
- Compliant: L1 row plus L2 for the materialization and the single-category use(s).
- Group: L1 summary plus an L2 naming the keys/references and the single shared purpose.

```
{
  "id": "key-001",
  "description": "Finding: The AES key 'masterKey' (SecretKeySpec from prefs) is reused for two purpose categories - it both encrypts message bodies (C) and is used as the HMAC key to authenticate them (I). Confidentiality and integrity must use separate keys.",
  "reference": "jadx/sources/com/example/app/MessageCrypto.java",
  "level": 1
},
{
  "id": "L2-masterKey-materialization",
  "description": "Key materialization: masterKey = new SecretKeySpec(prefBytes, \"AES\") at line 27, held as a field and shared by encrypt() and authenticate().",
  "reference": "jadx/sources/com/example/app/MessageCrypto.java:24-30",
  "level": 2
},
{
  "id": "L2-masterKey-useC",
  "description": "Use 1 (Confidentiality): Cipher.getInstance(\"AES/CBC/PKCS5Padding\").init(ENCRYPT_MODE, masterKey) at line 41 - encrypts the message body.",
  "reference": "jadx/sources/com/example/app/MessageCrypto.java:38-46",
  "level": 2
},
{
  "id": "L2-masterKey-useI",
  "description": "Use 2 (Integrity): Mac.getInstance(\"HmacSHA256\").init(masterKey) at line 58 - the SAME masterKey authenticates the ciphertext. One key, two purpose categories (C + I).",
  "reference": "jadx/sources/com/example/app/MessageCrypto.java:54-62",
  "level": 2
},
{
  "id": "L2-masterKey-reachability",
  "description": "Reachability from proprietary code: find_callers shows MessageCrypto.encrypt and MessageCrypto.authenticate both <- com.example.app.ChatRepository.send (first-party). The reuse is live in proprietary code.",
  "reference": "jadx/sources/com/example/app/ChatRepository.java:88-96",
  "level": 2
},
{
  "id": "key-aead-group",
  "description": "Compliant group: 6 AndroidKeyStore AES/GCM keys for local field encryption - each used for confidentiality only (AEAD is one purpose; GCM's built-in integrity is not a second purpose).",
  "reference": "jadx/sources/com/example/app/store/",
  "level": 1
},
{
  "id": "L2-aead-coverage",
  "description": "Single purpose: each key from KeyGenParameterSpec(alias, PURPOSE_ENCRYPT|PURPOSE_DECRYPT) is used only via Cipher AES/GCM encrypt/decrypt; references FieldVault.java:30-120 (and 5 more). No key reaches a Mac/Signature/wrap consumer.",
  "reference": "jadx/sources/com/example/app/store/FieldVault.java:30-120",
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
  "rationale": "K keys enumerated, N findings (cross-purpose), C compliant (single-purpose), D unreachable, U unverified. <one or two sentences naming the keys, their categories and the reuse site>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only to mark native/no-source-SDK key use recorded as `unverified`. It does not change `pass`/`fail`.
- `fail`: >=1 key with L2 rows showing it materialized once and then used across >=2 purpose categories (C/I/M) - by a mixed `KeyGenParameterSpec` purposes bitmask OR by traced use - PLUS an L2 row showing proprietary reachable code performs the reuse. "Same key" means the same object/field or the same keystore alias actually reaching both consumers, confirmed in source - not two different keys that merely look similar.
- `pass`: keys are managed and every key is confined to a single purpose category, with L2 coverage.
- `n/a`: no cryptographic key materialization of any kind exists (enumeration performed and empty).
- Do not flag the NOT-violations: single-key AEAD (GCM/CCM/ChaCha20-Poly1305), HMAC sign+verify, a KDF master deriving distinct sub-keys, encrypt+decrypt within C, sign+verify within I, wrap+unwrap within M.
- Documented exception: if the spec's "maintenance" allowance or an external-system requirement is invoked to justify a shared key, that is a documentation fact outside the APK - record the key as a Finding classified "documented candidate" with a matching `false_positive_risks` entry; it counts toward `fail` unless the assessor downgrades it.
- `unverified` rows name the deepest unresolved point (or the native/SDK entry point). Such keys are neither findings nor cleans.
- `false_positive_risks` is for factors outside the static artifact only (documented key-reuse exceptions, a key whose two consumers are actually distinct keys at runtime, alias resolved at runtime). In-APK gaps go in `unverified` rows.
- `inconclusive` if rationale counts don't reconcile with L1 rows (counting grouped keys), if any false_positive_risk references in-APK code, or if any `fail` key lacks its materialization + multi-use + reachability L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.