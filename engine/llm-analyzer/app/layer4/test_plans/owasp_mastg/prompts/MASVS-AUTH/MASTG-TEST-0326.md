MASTG-TEST-0326

maswe_id       MASWE-0045
masvs_v2_id    MASVS-AUTH-2
platform       android
title          References to APIs Allowing Fallback to Non-Biometric Authentication - DEVICE_CREDENTIAL fallback (static)

What this test looks for
When the app gates a sensitive operation behind biometric authentication, allowing fallback to a device credential (PIN / pattern / password) weakens that gate - passcodes are more susceptible to compromise (shoulder-surfing, coercion) than biometrics. The fallback is enabled by including `DEVICE_CREDENTIAL` in `BiometricPrompt.Builder.setAllowedAuthenticators(...)` (alone or OR'd with biometric authenticators), or by the deprecated `setDeviceCredentialAllowed(true)`. This is a static evaluation of every BiometricPrompt configuration guarding a sensitive resource. Verdict: `pass` (biometric prompts guarding sensitive operations require biometrics only - no `DEVICE_CREDENTIAL` fallback), `fail` (>=1 sensitive operation is guarded by a prompt allowing device-credential fallback), `n/a` (the app uses no biometric authentication), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `BiometricPrompt`/`setAllowedAuthenticators`/`setDeviceCredentialAllowed`. If NONE appear -> `n/a` (no biometric auth to assess; state the search).

Authenticator constants (decode the integer)
In decompiled code the authenticators argument is an integer bitmask:
- `BIOMETRIC_STRONG = 0x000F (15)`, `BIOMETRIC_WEAK = 0x00FF (255)`, `DEVICE_CREDENTIAL = 0x8000 (32768)`.
A value with bit `0x8000` set includes `DEVICE_CREDENTIAL` (e.g. `BIOMETRIC_STRONG | DEVICE_CREDENTIAL = 0x800F = 32783`). Decode the integer and state whether `DEVICE_CREDENTIAL` is present. `setDeviceCredentialAllowed(true)` is the deprecated equivalent.

Sensitive operations (what's worth protecting)
Access to keys/tokens/credentials, decryption of sensitive data, payment/transaction authorization, viewing PII/financial/health data, unlocking a secure area, or any operation the app treats as requiring user authentication. A biometric prompt guarding a non-sensitive, low-risk action with device-credential fallback is NOT a finding (note it).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `setAllowedAuthenticators(...)`/`setDeviceCredentialAllowed(true)` AND the sensitive operation the prompt guards. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual builder call and the guarded operation, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the device-credential fallback config and (b) the sensitive operation it guards. "probably allows PIN fallback" with no quoted call is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the authenticators integer can't be decoded, or the guarded operation's sensitivity is unclear, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate BiometricPrompt configs: `grep -rEn "BiometricPrompt|setAllowedAuthenticators|setDeviceCredentialAllowed|DEVICE_CREDENTIAL|Authenticators" jadx/sources/`. If no biometric auth -> short-circuit `n/a` (state the search).
2. For each prompt, resolve the authenticators bitmask (decode the integer) or detect `setDeviceCredentialAllowed(true)`. Quote it. Determine whether `DEVICE_CREDENTIAL` is allowed.
3. For each prompt allowing the fallback, trace what operation it guards and whether that operation is sensitive (key/token access, payment, PII, etc.). Quote the guarded operation. Non-sensitive -> Compliant (note).
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per prompt: Finding (DEVICE_CREDENTIAL fallback guarding a sensitive op, quoted+decoded); Compliant (biometric-only, or fallback only on a non-sensitive op); Unverified (bitmask undecodable / sensitivity unresolved).
6. Budget ~2-4 reads per prompt (the builder, the authenticate call, the guarded operation). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Biometric config inside native code or a no-source SDK -> `unverified` (name the entry point). CryptoObject-binding is MASTG-TEST-0327; confirmation is MASTG-TEST-0329; key validity is MASTG-TEST-0330; enrollment invalidation is MASTG-TEST-0328. This test is specifically the DEVICE_CREDENTIAL fallback.

Output
List **all** BiometricPrompt configurations guarding app operations - one L1 row per prompt with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant biometric-only prompts by area, but always break out every Finding and unverified prompt individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the device-credential fallback config (with decoded bitmask) and the sensitive operation guarded, plus owner.
- Compliant: L1 row plus an L2 showing biometric-only authenticators, or fallback on a non-sensitive op.
- Group: L1 summary plus an L2 naming references and the shared biometric-only pattern.

```
{
  "id": "dc-001",
  "description": "Finding (device-credential fallback on a sensitive operation): The prompt guarding decryption of the stored auth token allows PIN/pattern/password fallback, weakening the biometric gate.",
  "reference": "jadx/sources/com/example/app/auth/BioGate.java",
  "level": 1
},
{
  "id": "L2-dc-config",
  "description": "Fallback config (quoted+decoded): new BiometricPrompt.Builder(ctx).setAllowedAuthenticators(32783) at BioGate.java:40 - 32783 = BIOMETRIC_STRONG(15) | DEVICE_CREDENTIAL(0x8000); DEVICE_CREDENTIAL bit set -> device-credential fallback allowed.",
  "reference": "jadx/sources/com/example/app/auth/BioGate.java:40",
  "level": 2
},
{
  "id": "L2-dc-op",
  "description": "Sensitive operation guarded (quoted): on onAuthenticationSucceeded -> SecretKey k = keyStore.getKey(\"token_key\"); decrypt(token) at lines 55-60 - protects the auth token. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/auth/BioGate.java:55-60",
  "level": 2
},
{
  "id": "dc-ok-001",
  "description": "Compliant: payment-authorization prompt requires BIOMETRIC_STRONG only.",
  "reference": "jadx/sources/com/example/app/pay/PayAuth.java",
  "level": 1
},
{
  "id": "L2-dc-ok",
  "description": "Biometric-only (quoted): setAllowedAuthenticators(BIOMETRIC_STRONG) i.e. 15 at PayAuth.java:22 - DEVICE_CREDENTIAL bit not set.",
  "reference": "jadx/sources/com/example/app/pay/PayAuth.java:22",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0326",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "B BiometricPrompt configs enumerated, S guarding sensitive operations, N findings (DEVICE_CREDENTIAL fallback on a sensitive op), C compliant (biometric-only / non-sensitive), U unverified. Any biometric auth present? <no -> n/a / yes>. <one or two sentences naming each fallback-allowing prompt and the operation it guards>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive operation with (a) an L2 row quoting+decoding a `setAllowedAuthenticators(...)` that includes `DEVICE_CREDENTIAL` (or `setDeviceCredentialAllowed(true)`) AND (b) an L2 row quoting the sensitive operation it guards. A finding stated with "likely"/"may" instead of the quoted+decoded config is INVALID -> `unverified`.
- **Decode the integer.** The L2 must show the bitmask decomposition (e.g. 32783 = 15 | 0x8000) and that the `DEVICE_CREDENTIAL` bit is set.
- **Sensitive operation required.** DEVICE_CREDENTIAL is not inherently a vuln (per OWASP) - it is a finding only when it guards a sensitive operation. A non-sensitive prompt with fallback is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is DEVICE_CREDENTIAL set? is the op sensitive?) resolved by reading, unresolved -> `unverified`.
- `pass`: every prompt guarding a sensitive operation requires biometrics only, with L2 coverage.
- `n/a`: no biometric authentication appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if a bitmask was flagged without decoding, if any false_positive_risk references in-APK code, or if any `fail` lacks its fallback-config + sensitive-operation L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the `setAllowedAuthenticators`/`setDeviceCredentialAllowed(true)` is quoted and (for the bitmask) decoded to show DEVICE_CREDENTIAL set; (2) the sensitive operation it guards is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the BiometricPrompt search was performed (n/a / pass state it), every fallback-allowing prompt's guarded operation was read and quoted (unread -> `unverified`), no non-sensitive prompt was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
