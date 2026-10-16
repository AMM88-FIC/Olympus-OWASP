MASTG-TEST-0212

maswe_id       MASWE-0014
masvs_v2_id    MASVS-CRYPTO-2
platform       android
title          Use of Hardcoded Cryptographic Keys in Code - keys embedded in the app (static)

What this test looks for
Cryptographic keys must not be hardcoded in the app. A key that ships inside the APK (a literal byte array / string, a constant field, a value read from bundled resources/assets, or one trivially derived from such a constant) is recoverable by anyone with the APK, so any protection it provides is void. This is a static evaluation: a hardcoded/derivable key reaching a cryptographic use. Verdict: `pass` (keys come from AndroidKeyStore / a proper KDF over a runtime secret / secure provisioning, with no hardcoded key in a security-relevant use), `fail` (>=1 hardcoded or trivially-derivable key is used cryptographically), `n/a` (the app performs no keyed cryptography), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the key-material APIs below. If NONE appear -> `n/a` (no keyed crypto to assess; state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the literal/constant key material AND the cryptographic use it feeds. A "key" with no quoted constant is an assertion -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` (or the resource/asset path) of the actual key constant and its use, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the hardcoded key bytes/string/constant and (b) its use as key material. "probably hardcoded" is NOT evidence -> `unverified`. A key fetched from AndroidKeyStore or derived from a user secret via a real KDF is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the key's origin (hardcoded vs runtime-provisioned) can't be resolved within budget, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Hardcoded-key indicators (taint sources)
- `new SecretKeySpec("literal".getBytes(), "AES")` / `new SecretKeySpec(new byte[]{...}, ...)` - literal symmetric key.
- A `static final` `String`/`byte[]` constant named like a key/secret/password/passphrase used as key material.
- `IvParameterSpec` aside: IVs are covered by MASTG-TEST-0309; here the focus is the KEY.
- A key read from a bundled asset/resource (`assets/`, `res/raw/`, a `BuildConfig` field, `strings.xml`) and used directly as key material.
- A passphrase string constant fed to a KDF with a hardcoded salt and low iteration count (the derived key is effectively hardcoded).
- Base64/hex-decoded literal that becomes a key.

Compliant key sources
AndroidKeyStore-backed keys (`KeyGenParameterSpec` + `KeyStore.getInstance("AndroidKeyStore")`), keys derived from a genuine runtime secret (user password / server-provisioned secret) via a proper KDF (PBKDF2/scrypt/Argon2 with a random per-user salt and adequate iterations), or keys delivered/negotiated at runtime and never embedded.

Failure modes
- HK1 - Literal key in code: a String/byte[] literal (or constant) is used directly as a `SecretKey`/`SecretKeySpec`/`PrivateKey` or raw key bytes. Quote the literal + the crypto use.
- HK2 - Bundled-secret key: a key read from an asset/resource/BuildConfig and used as key material. Quote the source + use.
- HK3 - Effectively-hardcoded derived key: a KDF over a hardcoded passphrase + hardcoded salt (no runtime secret). Quote the passphrase, salt, and derivation.

Procedure
1. Enumerate key-material sites: `grep -rEn "SecretKeySpec|SecretKey|PrivateKey|KeyStore\.getInstance|KeyGenParameterSpec|PBKDF2|SecretKeyFactory|BuildConfig|getBytes\(\)" jadx/sources/`. If no keyed crypto -> short-circuit `n/a` (state the search). Also `grep` `assets/`, `res/raw/`, and `strings.xml` references when a key appears to load from resources.
2. For each key-material site, resolve where the key comes from: a literal/constant (HK1), a bundled asset/resource/BuildConfig (HK2), an effectively-hardcoded KDF (HK3), or a Compliant source (AndroidKeyStore / runtime-provisioned / real KDF). Quote the origin.
3. Confirm the key is actually USED cryptographically (encrypt/decrypt/sign/HMAC) - a leftover constant never used is not a finding (note it as Compliant/Unverified, not a Finding).
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A hardcoded key inside a third-party SDK is attributed but reported when it protects app data.
5. Conclude per key: Finding (HK1/HK2/HK3 with constant+use quoted); Compliant (KeyStore/runtime/KDF over runtime secret, quoted); Unverified (origin unresolved).
6. Budget ~2-4 reads per key (the constant, the KeySpec/use, any KDF). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Key provisioning inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a constant is a true key vs test scaffolding is read from context; indeterminate -> `unverified`. IV reuse is MASTG-TEST-0309's scope.

Output
List **all** key-material sites - one L1 row per key with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant keys by area as one L1 row per group, but always break out every Finding (HK1/HK2/HK3) and unverified key individually. Never sample findings.
- Finding HK1/HK2/HK3: L1 row plus L2 rows for the hardcoded key/constant (quoted) and the cryptographic use (quoted), plus owner.
- Compliant: L1 row plus L2 showing a KeyStore/runtime/KDF source (quoted).
- Group: L1 summary plus an L2 naming references and the shared safe key source.

```
{
  "id": "hk-001",
  "description": "Finding (HK1 literal key in code): The app encrypts stored credentials with a 16-byte AES key hardcoded as a string literal, recoverable from the APK.",
  "reference": "jadx/sources/com/example/app/Vault.java",
  "level": 1
},
{
  "id": "L2-hk-literal",
  "description": "Hardcoded key (quoted): SecretKeySpec key = new SecretKeySpec(\"MySuperSecretKey1\".getBytes(), \"AES\"); at Vault.java:33 - 16-byte literal AES key embedded in code.",
  "reference": "jadx/sources/com/example/app/Vault.java:33",
  "level": 2
},
{
  "id": "L2-hk-use",
  "description": "Cryptographic use (quoted): Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\"); c.init(ENCRYPT_MODE, key, iv); c.doFinal(credentials) at lines 35-39 - the literal key encrypts the user's credentials. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Vault.java:35-39",
  "level": 2
},
{
  "id": "hk-ok-001",
  "description": "Compliant: encryption key is generated in and retrieved from AndroidKeyStore (non-exportable).",
  "reference": "jadx/sources/com/example/app/KeyProvider.java",
  "level": 1
},
{
  "id": "L2-hk-ok",
  "description": "Safe key source (quoted): KeyStore ks = KeyStore.getInstance(\"AndroidKeyStore\"); SecretKey k = ((KeyStore.SecretKeyEntry) ks.getEntry(\"app_key\", null)).getSecretKey(); at KeyProvider.java:18-24 - hardware-backed, never embedded.",
  "reference": "jadx/sources/com/example/app/KeyProvider.java:18-24",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0212",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K key-material sites enumerated, N findings (HK1 literal / HK2 bundled / HK3 effectively-hardcoded KDF), C compliant (KeyStore/runtime/KDF), U unverified. Any keyed crypto present? <no -> n/a / yes>. <one or two sentences naming each hardcoded key and its use>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 key with (a) an L2 row quoting the hardcoded constant / bundled secret / effectively-hardcoded KDF AND (b) an L2 row quoting its cryptographic use. A finding stated with "likely"/"may" instead of the quoted constant is INVALID -> `unverified`.
- **Origin is the test.** A key from AndroidKeyStore, or derived via a real KDF from a genuine runtime secret with a random salt, is Compliant - not a finding. A KDF over a hardcoded passphrase + hardcoded salt IS a finding (HK3).
- **Used cryptographically.** A constant that is never used as key material is not a Finding (note it Compliant/Unverified).
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (key actually provisioned at runtime and the constant is a decoy/fallback established outside the APK) - in-APK facts (is this constant the key? is it used?) resolved by reading, unresolved -> `unverified`. Reject "the real key might come from the server".
- `pass`: every key used cryptographically comes from a Compliant source, with L2 coverage.
- `n/a`: no keyed-crypto APIs appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its constant + use L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the hardcoded key / bundled secret / hardcoded-KDF inputs are quoted; (2) the cryptographic use is quoted; (3) the key is actually used as key material; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the key-material search was performed (n/a / pass state it), every key's origin was read and quoted (unread -> `unverified`), no unused constant was flagged as a Finding, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
