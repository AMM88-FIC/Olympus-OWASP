MASTG-TEST-0330

maswe_id       MASWE-0044
masvs_v2_id    MASVS-AUTH-2
platform       android
title          References to APIs for Keys used in Biometric Authentication with Extended Validity Duration - auth validity > 0 (static)

What this test looks for
An auth-bound key used with biometric authentication should require authentication for EVERY use (validity duration = 0), so each sensitive operation is individually authorized. A non-zero validity duration leaves the key unlocked for a window after one authentication; if that window is long (minutes/hours), an attacker with physical access can trigger sensitive operations without re-authenticating. The duration is set via `KeyGenParameterSpec.Builder.setUserAuthenticationParameters(timeout, type)` or the deprecated `setUserAuthenticationValidityDurationSeconds(timeout)`. This is a static evaluation of every auth-bound key's validity duration. Verdict: `pass` (auth-bound keys protecting sensitive operations use per-use auth - duration = 0), `fail` (>=1 key protecting a sensitive operation is configured with duration > 0), `n/a` (the app generates no auth-bound keys), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `setUserAuthenticationParameters`/`setUserAuthenticationValidityDurationSeconds`/`setUserAuthenticationRequired`. If no auth-bound key generation appears -> `n/a` (state the search).

The failure condition
- `setUserAuthenticationParameters(duration, type)` with `duration > 0`, OR
- `setUserAuthenticationValidityDurationSeconds(duration)` with `duration > 0`,
on a key protecting a sensitive operation. `duration = 0` (per-use authentication) is the secure configuration.

Severity nuance (per OWASP): a non-zero duration is not inherently a vuln - SHORT durations (a few seconds, for rapid successive related operations) may be acceptable. LONG durations (minutes/hours) for sensitive operations are the real weakness. State the duration value; flag any `> 0` on a sensitive-operation key, and emphasize long durations.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `setUserAuthenticationParameters(...)`/`setUserAuthenticationValidityDurationSeconds(...)` with its duration AND the sensitive operation the key protects. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual builder call, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the duration > 0 setting and (b) the sensitive operation the key guards. "probably stays unlocked" with no quoted duration is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the duration value or the key's protected operation can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate auth-bound key generations: `grep -rEn "KeyGenParameterSpec|setUserAuthenticationParameters|setUserAuthenticationValidityDurationSeconds|setUserAuthenticationRequired" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each auth-bound key (`setUserAuthenticationRequired(true)`), read the validity duration: `0` (Compliant - per-use), `> 0` (candidate; note the value and whether it is short-seconds or long-minutes/hours). Resolve constants/finals; runtime-computed duration that can't be pinned -> `unverified`. Quote it.
3. For each `duration > 0`, trace what sensitive operation the key protects. Quote the operation. Non-sensitive -> Compliant (note).
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
5. Conclude per key: Finding (duration > 0 on a sensitive-operation key, quoted - emphasize long durations); Compliant (duration = 0, or non-sensitive); Unverified (duration/operation unresolved).
6. Budget ~2-4 reads per key (the builder, the duration constant, the protected operation). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Key generation inside native code or a no-source SDK -> `unverified` (name the entry point). DEVICE_CREDENTIAL fallback is MASTG-TEST-0326; CryptoObject binding is MASTG-TEST-0327; enrollment invalidation is MASTG-TEST-0328; confirmation is MASTG-TEST-0329. This test is the auth validity DURATION.

Output
List **all** auth-bound key generations - one L1 row per key with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant per-use keys by area, but always break out every Finding and unverified key individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the duration > 0 setting (with the value) and the sensitive operation the key protects, plus owner.
- Compliant: L1 row plus an L2 showing duration = 0 (per-use), or a non-sensitive key.
- Group: L1 summary plus an L2 naming references and the shared per-use pattern.

```
{
  "id": "vd-001",
  "description": "Finding (extended key validity on a sensitive operation): The key protecting fund transfers stays unlocked for 300 seconds after one authentication, so transfers can be triggered without re-auth within that window.",
  "reference": "jadx/sources/com/example/app/bank/TransferKey.java",
  "level": 1
},
{
  "id": "L2-vd-config",
  "description": "Extended validity (quoted): new KeyGenParameterSpec.Builder(\"transfer_key\", PURPOSE_SIGN).setUserAuthenticationRequired(true).setUserAuthenticationParameters(300, KeyProperties.AUTH_BIOMETRIC_STRONG)... at TransferKey.java:30-37 - duration = 300s (5 minutes) > 0; key remains usable without re-auth for 5 minutes.",
  "reference": "jadx/sources/com/example/app/bank/TransferKey.java:30-37",
  "level": 2
},
{
  "id": "L2-vd-op",
  "description": "Sensitive operation (quoted): this key signs fund-transfer requests at TransferService.java:55-60. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/bank/TransferService.java:55-60",
  "level": 2
},
{
  "id": "vd-ok-001",
  "description": "Compliant: vault key requires authentication for every use (duration = 0).",
  "reference": "jadx/sources/com/example/app/vault/VaultKey.java",
  "level": 1
},
{
  "id": "L2-vd-ok",
  "description": "Per-use auth (quoted): setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG) at VaultKey.java:24 - duration 0; each use needs biometric verification.",
  "reference": "jadx/sources/com/example/app/vault/VaultKey.java:24",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0330",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K auth-bound key generations enumerated, S protecting sensitive operations, N findings (validity duration > 0 on a sensitive-op key; D of them long minutes/hours), C compliant (duration 0 / non-sensitive), U unverified. Any auth-bound key generation? <no -> n/a / yes>. <one or two sentences naming each extended-validity key, its duration, and the operation it protects>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 auth-bound key protecting a sensitive operation with (a) an L2 quoting a duration > 0 (`setUserAuthenticationParameters(duration,...)` or `setUserAuthenticationValidityDurationSeconds(duration)`) AND (b) an L2 quoting the sensitive operation it protects. State the duration value. A finding stated with "likely"/"may" instead of the quoted duration is INVALID -> `unverified`.
- **Duration value stated; long durations emphasized.** Any `> 0` on a sensitive-operation key is reported; long durations (minutes/hours) are the strongest findings. `duration = 0` is Compliant.
- **Sensitive operation required.** A non-zero duration on a key guarding nothing sensitive is Compliant/noted.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (what is the duration? is the op sensitive?) resolved by reading, unresolved -> `unverified`.
- `pass`: every auth-bound key protecting a sensitive operation uses per-use auth (duration = 0), with L2 coverage.
- `n/a`: no auth-bound key generation appears in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if a duration was flagged without quoting its value, if any false_positive_risk references in-APK code, or if any `fail` lacks its duration + sensitive-operation L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the duration > 0 setting is quoted with its numeric value; (2) the key is auth-bound and the sensitive operation it protects is quoted; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the key-spec search was performed (n/a / pass state it), every key's validity duration and protected operation were read and quoted (unread -> `unverified`), no duration-0 key was miscounted as a Finding, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
