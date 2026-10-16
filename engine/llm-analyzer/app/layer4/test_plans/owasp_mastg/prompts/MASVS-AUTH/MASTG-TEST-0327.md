MASTG-TEST-0327

maswe_id       MASWE-0044
masvs_v2_id    MASVS-AUTH-2
platform       android
title          References to APIs for Event-Bound Biometric Authentication - authenticate() without CryptoObject (static)

What this test looks for
Biometric authentication that gates a sensitive operation must be CRYPTO-bound, not merely EVENT-bound. Event-bound auth - `BiometricPrompt.authenticate(...)` WITHOUT a `CryptoObject`, trusting only the `onAuthenticationSucceeded` callback - can be bypassed by manipulating the callback (e.g. invoking it directly, instrumentation) because success is just a boolean. Crypto-bound auth passes a `CryptoObject` (`Cipher`/`Signature`/`Mac`) tied to a key generated with `setUserAuthenticationRequired(true)`, so the sensitive operation actually depends on a key that only unlocks after real biometric verification. This is a static evaluation. Verdict: `pass` (biometric gating of sensitive operations is crypto-bound), `fail` (>=1 sensitive operation is gated by event-bound auth - authenticate() without a CryptoObject AND no auth-required key backing it), `n/a` (the app uses no biometric authentication), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `BiometricPrompt`/`authenticate(`/`CryptoObject`. If NONE appear -> `n/a` (no biometric auth; state the search).

The failure condition (BOTH must hold for a sensitive operation)
1. `BiometricPrompt.authenticate(...)` is called WITHOUT a `CryptoObject` (the no-CryptoObject overload), AND
2. There is no key generation with `setUserAuthenticationRequired(true)` bound to that biometric flow (so the protected key, if any, is usable regardless of authentication).
If either is false (a CryptoObject is passed, OR an auth-required key actually gates the operation), it is Compliant for THIS test.

Sensitive operations (worth protecting)
Decryption/retrieval of keys/tokens/credentials, payment authorization, access to PII/financial/health data, unlocking a secure store. A purely cosmetic biometric "lock screen" guarding nothing sensitive is not a finding (note it).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `authenticate(...)` call (showing no CryptoObject), the absence of an auth-required key backing it, AND the sensitive operation in the success callback. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the authenticate call and the guarded operation, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the no-CryptoObject authenticate, (b) no `setUserAuthenticationRequired(true)` key gating the op, and (c) the sensitive operation done in the callback. "probably event-bound" with no quoted call is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the overload or the key backing can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate biometric flows: `grep -rEn "BiometricPrompt|\.authenticate\(|CryptoObject|setUserAuthenticationRequired|onAuthenticationSucceeded" jadx/sources/`. If no biometric auth -> short-circuit `n/a` (state the search).
2. For each `authenticate(...)`, determine the overload: with a `CryptoObject` (crypto-bound -> Compliant) or without (event-bound candidate). Quote it.
3. For each event-bound candidate, check whether the sensitive operation is instead protected by a key generated with `setUserAuthenticationRequired(true)` (crypto gate exists despite no CryptoObject at the prompt) -> Compliant; if no such key gates it -> finding. Read the success callback to confirm a sensitive operation occurs there. Quote all three.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per flow: Finding (event-bound + no auth-required key + sensitive op, quoted); Compliant (CryptoObject used, or auth-required key gates the op, or non-sensitive); Unverified (overload/key/op unresolved).
6. Budget ~3-5 reads per flow (the authenticate, the key generation, the success callback, the protected op). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Biometric logic inside native code or a no-source SDK -> `unverified` (name the entry point). DEVICE_CREDENTIAL fallback is MASTG-TEST-0326; confirmation is MASTG-TEST-0329; key validity duration is MASTG-TEST-0330 (a related but distinct key-config concern); enrollment invalidation is MASTG-TEST-0328. This test is event-bound vs crypto-bound.

Output
List **all** biometric authentication flows guarding app operations - one L1 row per flow with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant crypto-bound flows by area, but always break out every Finding and unverified flow individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the no-CryptoObject authenticate, the absence of an auth-required key, and the sensitive operation in the callback, plus owner.
- Compliant: L1 row plus an L2 showing a CryptoObject passed, or an auth-required key gating the op.
- Group: L1 summary plus an L2 naming references and the shared crypto-bound pattern.

```
{
  "id": "eb-001",
  "description": "Finding (event-bound biometric auth on a sensitive operation): The app reveals stored credentials in onAuthenticationSucceeded after an authenticate() call with no CryptoObject and no auth-required key - bypassable by manipulating the callback.",
  "reference": "jadx/sources/com/example/app/auth/Unlock.java",
  "level": 1
},
{
  "id": "L2-eb-call",
  "description": "Event-bound authenticate (quoted): biometricPrompt.authenticate(cancellationSignal, executor, callback) at Unlock.java:40-42 - the no-CryptoObject overload; success is a boolean callback only.",
  "reference": "jadx/sources/com/example/app/auth/Unlock.java:40-42",
  "level": 2
},
{
  "id": "L2-eb-nokey",
  "description": "No crypto gate (quoted): the credential is read as plaintext from SharedPreferences in onAuthenticationSucceeded (lines 50-54); no KeyGenParameterSpec with setUserAuthenticationRequired(true) backs this flow (grep clean for the key). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/auth/Unlock.java:50-54",
  "level": 2
},
{
  "id": "eb-ok-001",
  "description": "Compliant: crypto-bound auth - authenticate() receives a CryptoObject wrapping an auth-required Cipher.",
  "reference": "jadx/sources/com/example/app/auth/SecureUnlock.java",
  "level": 1
},
{
  "id": "L2-eb-ok",
  "description": "Crypto-bound (quoted): biometricPrompt.authenticate(new BiometricPrompt.CryptoObject(cipher), ...) where cipher uses a key built with setUserAuthenticationRequired(true) at SecureUnlock.java:30-38 - the decrypt depends on real authentication.",
  "reference": "jadx/sources/com/example/app/auth/SecureUnlock.java:30-38",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0327",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "F biometric flows enumerated, S guarding sensitive operations, N findings (event-bound: no CryptoObject AND no auth-required key), C compliant (crypto-bound / auth-required key / non-sensitive), U unverified. Any biometric auth present? <no -> n/a / yes>. <one or two sentences naming each event-bound flow and the operation it guards>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive operation with (a) an L2 quoting an `authenticate(...)` WITHOUT a CryptoObject, (b) an L2 showing no `setUserAuthenticationRequired(true)` key gates the operation, AND (c) an L2 quoting the sensitive operation in the success callback. A finding stated with "likely"/"may" instead of the quoted three is INVALID -> `unverified`.
- **Both conditions required.** A CryptoObject at the prompt, OR an auth-required key actually gating the op, makes it Compliant. Do not fail an event-bound prompt that is backed by an auth-required key.
- **Sensitive operation required.** Event-bound auth guarding nothing sensitive is not a finding.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (CryptoObject? auth-required key? sensitive op?) resolved by reading, unresolved -> `unverified`.
- `pass`: biometric gating of sensitive operations is crypto-bound (CryptoObject and/or auth-required key), with L2 coverage.
- `n/a`: no biometric authentication appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if a finding omits one of the three required L2s, if any false_positive_risk references in-APK code, or if any `fail` lacks its no-CryptoObject + no-auth-key + sensitive-op L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the no-CryptoObject `authenticate(...)` overload is quoted; (2) no `setUserAuthenticationRequired(true)` key gates the operation (shown); (3) the sensitive operation in the success callback is quoted; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the biometric search was performed (n/a / pass state it), every flow's overload + key-backing + guarded op were read and quoted (unread -> `unverified`), no crypto-bound flow was miscounted, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
