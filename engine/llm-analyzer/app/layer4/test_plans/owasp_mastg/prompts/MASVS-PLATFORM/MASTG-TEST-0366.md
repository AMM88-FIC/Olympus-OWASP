MASTG-TEST-0366

maswe_id       MASWE-0063
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          Exported And Unprotected Broadcast Receivers That Expose Sensitive Functionality (static)

What this test looks for
An exported broadcast receiver without an appropriate `android:permission` can receive broadcasts from any third-party app, letting it trigger the receiver's `onReceive` logic - performing a security-relevant action or disclosing sensitive data based on attacker-controlled intent extras. This is a static evaluation of manifest-declared AND context-registered receivers + their `onReceive` code. Verdict: `pass` (no exported receiver exposes sensitive functionality without adequate protection), `fail` (>=1 exported, inadequately-protected receiver exposes sensitive functionality), `n/a` (the app declares no exported receivers exposing sensitive functionality - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): enumerate exported receivers - manifest `<receiver>` (`android:exported="true"`, or an `<intent-filter>` with no explicit `exported`) AND code `registerReceiver(...)` calls (context-registered receivers are exported unless flagged `RECEIVER_NOT_EXPORTED` on API 33+, or they only listen to protected system broadcasts). If none are exported -> `n/a`/`pass` (state it).

Adequately protected vs not
Adequate: `android:permission` (manifest) or the permission arg of `registerReceiver`/`sendBroadcast` with a `signature`/restricted level; OR the receiver only listens to PROTECTED system broadcasts (e.g. `BOOT_COMPLETED`) that third-party apps cannot send; OR context-registered with `RECEIVER_NOT_EXPORTED` (API 33+). Inadequate: exported with no permission and a non-protected action, or a `normal`/`dangerous` permission.

Sensitive functionality
`onReceive` performs a security-relevant action or discloses sensitive data based on the received intent (e.g. reads extras and sends a message, changes state, starts a privileged operation), especially without validating the intent.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the `<receiver>` manifest entry (or the `registerReceiver` call) with export/permission/flags AND the `onReceive` code exposing sensitive functionality. No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>` and `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the exported+unprotected registration and (b) the sensitive `onReceive` logic. "probably acts on the intent" with no quoted code is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If export/permission/onReceive can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Manifest + code: enumerate `<receiver>` (`grep -nE "<receiver|exported|permission|intent-filter|action android:name" jadx/resources/AndroidManifest.xml`) and `grep -rEn "registerReceiver|RECEIVER_NOT_EXPORTED|RECEIVER_EXPORTED" jadx/sources/`. Determine which are exported. For each action, note whether it is a PROTECTED system broadcast (cannot be sent by third-party apps). Quote each.
2. For each exported receiver, check the permission (manifest or registration arg) + protection level, or `RECEIVER_NOT_EXPORTED`, or protected-action-only. Classify protection. Quote it.
3. For each exported, inadequately-protected receiver, read `onReceive` to determine whether it performs a security-relevant action / discloses sensitive data based on the intent, and whether it validates the intent. Quote the code. Benign -> Compliant.
4. Owner: app-declared (proprietary); a library receiver is reported if it acts on app data.
5. Conclude per receiver: Finding (exported + inadequate + sensitive onReceive, quoted); Compliant (not exported / protected / protected-action-only / RECEIVER_NOT_EXPORTED / benign); Unverified (unresolved).
6. Budget ~2-4 reads per receiver (the registration, the permission, onReceive). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Receiver logic inside native code or a no-source SDK -> `unverified` (name the entry point). Activities are MASTG-TEST-0364; services MASTG-TEST-0365; providers MASTG-TEST-0355/0357. This test is exported BROADCAST RECEIVERS.

Output
List **all** exported receivers (manifest + context-registered) - one L1 row per receiver with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group benign/protected-action receivers, but always break out every Finding and unverified receiver individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the exported+unprotected registration and the sensitive `onReceive` logic, plus owner.
- Compliant: L1 row plus an L2 showing protected / RECEIVER_NOT_EXPORTED / protected-action-only / benign.

```
{
  "id": "rcv-001",
  "description": "Finding (exported receiver performs a security-relevant action): An exported, unprotected receiver wipes the local vault when it receives a broadcast, with attacker-controllable action and no permission.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-rcv-manifest",
  "description": "Exported + unprotected (quoted): <receiver android:name=\".WipeReceiver\" android:exported=\"true\"><intent-filter><action android:name=\"com.example.app.WIPE\"/></intent-filter></receiver> at AndroidManifest.xml:80-84 - custom (non-protected) action, no android:permission.",
  "reference": "jadx/resources/AndroidManifest.xml:80-84",
  "level": 2
},
{
  "id": "L2-rcv-code",
  "description": "Sensitive functionality (quoted): WipeReceiver.onReceive deletes the vault database (vaultRepo.wipe()) at WipeReceiver.java:18-24 with no caller validation - any app can send com.example.app.WIPE to destroy data. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/WipeReceiver.java:18-24",
  "level": 2
},
{
  "id": "rcv-ok-001",
  "description": "Compliant: boot receiver listens only to the protected BOOT_COMPLETED action.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0366",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R receivers (manifest + context-registered), E exported, P adequately protected (permission/RECEIVER_NOT_EXPORTED/protected-action), N findings (exported + inadequate + sensitive onReceive), C compliant, U unverified. Any exported receiver exposing sensitive functionality without protection? <no -> pass/n-a / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 receiver with (a) an L2 quoting an exported, inadequately-protected registration (manifest or context-registered, non-protected action) AND (b) an L2 quoting sensitive `onReceive` logic. A finding stated with "likely"/"may" instead of the quoted registration+code is INVALID -> `unverified`.
- **Protected actions / RECEIVER_NOT_EXPORTED count.** A receiver listening only to protected system broadcasts, or context-registered with `RECEIVER_NOT_EXPORTED`, is Compliant - quote it.
- **Protection adequacy.** `signature`/restricted permission = adequate; `normal`/`dangerous`/none = not. Quote the `protectionLevel`.
- **Sensitive functionality required.** A benign exported receiver is Compliant - note it.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: no exported receiver exposes sensitive functionality without adequate protection, with L2 coverage.
- `n/a`: no exported receivers exposing sensitive functionality (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK evidence, if a finding was dropped without evidence, or if any `fail` lacks its registration + sensitive-onReceive L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the exported+unprotected registration (manifest or context-registered) is quoted; (2) the sensitive `onReceive` logic is quoted; (3) the action is not a protected system broadcast and no adequate permission/`RECEIVER_NOT_EXPORTED` guards it; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the manifest AND code registrations were read and exported receivers enumerated, every finding's `onReceive` was read and quoted (unread -> `unverified`), no protected-action/RECEIVER_NOT_EXPORTED receiver was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
