MASTG-TEST-0338

maswe_id       MASWE-0082
masvs_v2_id    MASVS-CODE-4
platform       android
title          Integrity and Authenticity Validation of Local Storage Data (static)

What this test looks for
Data the app stores locally (SharedPreferences, files, databases, app-managed storage) and later uses in a SECURITY-RELEVANT decision must have its integrity and authenticity verified before use - otherwise an attacker who can tamper with local storage (rooted device, backups, dynamic analysis, privileged access) can feed the app forged values. This is a static, taint-style evaluation: security-relevant value loaded from local storage -> used in a security decision WITHOUT integrity/authenticity verification. Verdict: `pass` (security-relevant local-storage values are verified, or none are used in security decisions), `fail` (>=1 security-relevant value from local storage is used in a security decision with no integrity/authenticity check), `n/a` (the app stores/uses no security-relevant data from local storage), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for local-storage READ APIs. If NONE feed a security-relevant decision -> `pass`/`n/a` (state it).

Security-relevant uses (what makes a loaded value in scope)
The loaded value influences: authentication state ("is the user logged in"), authorization / entitlement / role, feature flags gating security behavior, trust decisions (pinned values, allowlists), license/premium state guarding sensitive features, or configuration that changes a security control. A loaded value used only cosmetically (UI prefs, last-tab) is out of scope.

Integrity/authenticity verification (Compliant)
Before using the value, the app verifies it with an HMAC/MAC (and a constant-time compare), a digital signature, an AEAD tag (the value was stored under AES-GCM with a keystore key and decryption authenticates it), or an equivalent tamper-detection mechanism whose key/secret is NOT itself trivially tamperable. A plain checksum (CRC) is NOT authenticity (note it). Storing in the private sandbox is NOT sufficient by itself (the threat model includes local tampering).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the local-storage read, the security-relevant use, AND the verification (Compliant) or its absence (Finding). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the read and the decision, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a security-relevant value loaded from local storage and (b) its use in a security decision with no integrity/authenticity check nearby. "probably trusts the prefs" with no quoted use is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the value's security-relevance or the presence of verification can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Local-storage read sinks
`SharedPreferences.getString/getBoolean/getInt(...)`, `File`/`FileInputStream`/`openFileInput` reads, SQLite/Room queries, DataStore reads, `getExternalFilesDir` reads, any app-managed store. Look NEARBY for HMAC/MAC/`Mac.doFinal`/`MessageDigest`+compare/`Signature.verify`/AES-GCM decrypt that gates the use.

Procedure
1. Enumerate reads: `grep -rEn "getSharedPreferences|SharedPreferences|getString\(|getBoolean\(|openFileInput|FileInputStream|rawQuery|DataStore|MessageDigest|Mac\.|HmacSHA|Signature\.|GCMParameterSpec|verify\(" jadx/sources/`.
2. For each local-storage read, determine whether the value feeds a security-relevant decision (auth/authorization/trust/feature gate). Quote the read + the decision. Non-security uses -> out of scope.
3. For each security-relevant loaded value, check for integrity/authenticity verification before use (HMAC/MAC/signature/AEAD tag). Absent -> finding; present and effective -> Compliant. Quote it. A plain CRC/length check is not authenticity.
4. Classify owner (proprietary vs library; OEM-aware; obfuscated -> proprietary).
5. Conclude per value: Finding (security-relevant + loaded + unverified, quoted); Compliant (verified, or non-security use); Unverified (relevance/verification unresolved).
6. Budget ~2-4 reads per value (the read, the decision, any verification). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Storage/verification inside native code or a no-source SDK -> `unverified` (name the entry point). Whether the verification key is itself tamperable is a deeper check; note it where relevant. Sandbox-only storage does NOT by itself satisfy this control (the threat model includes local tampering).

Output
List **all** security-relevant local-storage values - one L1 row per value with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant verified/non-security values, but always break out every Finding and unverified value individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the load, the security-relevant use, and the absence of integrity/authenticity verification, plus owner.
- Compliant: L1 row plus an L2 quoting the verification (HMAC/MAC/signature/AEAD) before use, or a non-security use.

```
{
  "id": "int-001",
  "description": "Finding (unverified security flag from local storage): The app reads an 'is_premium'/'is_admin' style flag from SharedPreferences and grants access without verifying its integrity, so local tampering escalates privilege.",
  "reference": "jadx/sources/com/example/app/Entitlements.java",
  "level": 1
},
{
  "id": "L2-int-load",
  "description": "Security-relevant load (quoted): boolean isAdmin = prefs.getBoolean(\"is_admin\", false); at Entitlements.java:30 - prefs are tamperable on rooted devices / via backup.",
  "reference": "jadx/sources/com/example/app/Entitlements.java:30",
  "level": 2
},
{
  "id": "L2-int-use",
  "description": "Unverified security decision (quoted): if (isAdmin) { showAdminPanel(); enableDangerousOps(); } at lines 33-37 - no HMAC/MAC/signature verification of the stored flag before trusting it. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Entitlements.java:33-37",
  "level": 2
},
{
  "id": "int-ok-001",
  "description": "Compliant: stored session token verified with an HMAC before use.",
  "reference": "jadx/sources/com/example/app/Session.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0338",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "L local-storage reads feeding security decisions, V verified (HMAC/MAC/signature/AEAD), N findings (unverified), U unverified. Any security-relevant value trusted from local storage without integrity/authenticity? <no -> pass/n-a / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 value with (a) an L2 quoting a security-relevant value loaded from local storage AND (b) an L2 quoting its use in a security decision with no integrity/authenticity verification. A finding stated with "likely"/"may" instead of the quoted load+use is INVALID -> `unverified`.
- **Security-relevant use required.** A loaded value used only cosmetically is out of scope. The finding needs influence over an auth/authorization/trust/feature-gate decision.
- **Authenticity, not just integrity.** HMAC/MAC/signature/AEAD tag (with a non-tamperable key) clears it; a plain CRC/checksum does not. Sandbox storage alone does not.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the value security-relevant? verified?) resolved by reading, unresolved -> `unverified`.
- `pass`: security-relevant local-storage values are verified before use, or none are used in security decisions, with L2 coverage.
- `n/a`: the app uses no security-relevant data from local storage (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its load + security-use L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the local-storage load is quoted; (2) the security-relevant use is quoted; (3) no integrity/authenticity verification (HMAC/MAC/signature/AEAD) gates the use; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the local-storage-read search was performed, every security-relevant value's verification state was read and quoted (unread -> `unverified`), no cosmetic value was flagged, sandbox-only storage was not treated as sufficient, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
