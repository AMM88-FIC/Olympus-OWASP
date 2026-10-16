MASTG-TEST-0292

maswe_id       MASWE-0055
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          setRecentsScreenshotEnabled Not Used to Prevent Screenshots When Backgrounded (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0292 as a `status: placeholder` (no procedure body; note: "verifies whether an app prevents sensitive data from being captured in the Recents screen when backgrounded"). This prompt implements the best-effort static detection: whether sensitive activities call `Activity.setRecentsScreenshotEnabled(false)` (API 33+) to suppress the Recents/background screenshot - or otherwise protect it via `FLAG_SECURE` (which also blanks the Recents thumbnail).

What this test looks for
Sensitive activities should suppress the Recents/backgrounding screenshot. `setRecentsScreenshotEnabled(false)` disables the system task screenshot for an activity; `FLAG_SECURE` achieves the same blanking. This is a static evaluation. Verdict: `pass` (every sensitive activity disables the recents screenshot via setRecentsScreenshotEnabled(false) or FLAG_SECURE), `fail` (>=1 sensitive activity has neither), `n/a` (no sensitive screens - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): identify sensitive activities. If none -> `n/a` (state how concluded). Then `grep` for `setRecentsScreenshotEnabled`/`FLAG_SECURE`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the sensitive activity AND its protection (`setRecentsScreenshotEnabled(false)`/`FLAG_SECURE`) or the absence of both. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a sensitive activity and (b) the absence of both protections (searches). "probably leaks in Recents" with no quoted activity is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If sensitivity or protection can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Note on minSdk / API level
`setRecentsScreenshotEnabled` is API 33+. On apps supporting older versions, FLAG_SECURE is the portable protection. Treat EITHER as adequate; a `setRecentsScreenshotEnabled(false)` call guarded by an API check, or a FLAG_SECURE, is Compliant. State the relevant API consideration.

Procedure
1. Identify sensitive activities (login, payment, account, OTP, secure content). Quote the basis.
2. Enumerate protections: `grep -rEn "setRecentsScreenshotEnabled|FLAG_SECURE|addFlags" jadx/sources/`. Map to activities (note base activities).
3. For each sensitive activity, determine whether `setRecentsScreenshotEnabled(false)` OR `FLAG_SECURE` protects it. Neither -> finding. Quote it.
4. Owner: app (proprietary).
5. Conclude per activity: Finding (neither, quoted); Compliant (one present); Unverified (sensitivity/protection unresolved).
6. Budget ~2-4 reads per activity. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
General FLAG_SECURE coverage is MASTG-TEST-0291; the dynamic snapshot inspection is MASTG-TEST-0289; SurfaceView is MASTG-TEST-0293; Compose dialogs MASTG-TEST-0294. This test is the Recents-screenshot control on sensitive activities. Native/no-source screens -> `unverified`.

Output
List **all** sensitive activities - one L1 row per activity with its disposition. Always break out every Finding and unverified activity individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the sensitive activity and the absence of both protections, plus owner.
- Compliant: L1 row plus an L2 quoting setRecentsScreenshotEnabled(false) or FLAG_SECURE.

```
{
  "id": "rs-001",
  "description": "Finding (no Recents-screenshot protection on a sensitive activity): The OTP activity neither disables the recents screenshot nor sets FLAG_SECURE.",
  "reference": "jadx/sources/com/example/app/OtpActivity.java",
  "level": 1
},
{
  "id": "L2-rs-screen",
  "description": "Sensitive activity (quoted): OtpActivity displays the received OTP code (R.layout.otp) at OtpActivity.java:26-32.",
  "reference": "jadx/sources/com/example/app/OtpActivity.java:26-32",
  "level": 2
},
{
  "id": "L2-rs-missing",
  "description": "No protection (quoted searches): no setRecentsScreenshotEnabled(false) and no FLAG_SECURE for OtpActivity or its base (grep clean). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/OtpActivity.java",
  "level": 2
},
{
  "id": "rs-ok-001",
  "description": "Compliant: sensitive activity disables the recents screenshot (with an API-33 guard).",
  "reference": "jadx/sources/com/example/app/SecureActivity.java",
  "level": 1
},
{
  "id": "L2-rs-ok",
  "description": "Protection (quoted): if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false); at SecureActivity.java:22 - recents screenshot disabled.",
  "reference": "jadx/sources/com/example/app/SecureActivity.java:22",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0292",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S sensitive activities, P protected (setRecentsScreenshotEnabled(false) or FLAG_SECURE), N findings (neither), U unverified. Any sensitive activity exposed in Recents? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (snapshot inspection is MASTG-TEST-0289); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive activity with (a) an L2 quoting the activity + sensitive data AND (b) an L2 showing neither setRecentsScreenshotEnabled(false) nor FLAG_SECURE (searches incl. base classes). A finding stated with "likely"/"may" instead of the quoted absence is INVALID -> `unverified`.
- **Either protection suffices** (FLAG_SECURE or setRecentsScreenshotEnabled(false)); base-class coverage counts - quote the inheritance.
- **Sensitive activities only.** Do not flag non-sensitive activities.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: every sensitive activity disables the recents screenshot (either mechanism), with L2 coverage.
- `n/a`: no sensitive screens (state how concluded).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its activity + missing-protection L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the sensitive activity and its data are quoted; (2) neither setRecentsScreenshotEnabled(false) nor FLAG_SECURE is present (searches incl. base classes); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm sensitive activities were identified, the protection search was performed (incl. base classes), every finding activity's protection was read and quoted/shown-absent (unread -> `unverified`), no protected activity was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
