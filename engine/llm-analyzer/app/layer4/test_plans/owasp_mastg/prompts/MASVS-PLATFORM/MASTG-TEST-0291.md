MASTG-TEST-0291

maswe_id       MASWE-0055
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          References to Screen Capturing Prevention APIs - FLAG_SECURE on sensitive screens (static)

What this test looks for
Screens that display sensitive data should set `WindowManager.LayoutParams.FLAG_SECURE` so Android blocks screenshots, screen recording, and non-secure display mirroring (and shows a blank thumbnail in Recents). Common failures: not setting `FLAG_SECURE` on a sensitive screen, or clearing it during transitions (`clearFlags(FLAG_SECURE)` / `setFlags` overwriting it). This is a static evaluation of which sensitive screens set/clear the flag. Verdict: `pass` (every sensitive screen sets and keeps FLAG_SECURE), `fail` (>=1 sensitive screen never sets FLAG_SECURE, or clears it without justification), `n/a` (the app has no sensitive screens - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): identify sensitive screens (activities/fragments showing credentials, payment, PII, OTP, secure content). If the app has none -> `n/a` (state how you concluded that). Then `grep` for `FLAG_SECURE`/`addFlags`/`setFlags`/`clearFlags`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the sensitive screen AND either its `FLAG_SECURE` set (Compliant) or the absence/clearing of it (Finding). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the screen and the flag handling, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a sensitive screen and (b) the absence of `FLAG_SECURE` (searches across its window setup) or a `clearFlags(FLAG_SECURE)`. "probably not protected" with no quoted screen is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If a screen's sensitivity or its flag handling can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

What counts (Compliant vs Finding)
- Compliant: `getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE)` (or `setFlags(FLAG_SECURE, FLAG_SECURE)`) set in the sensitive screen's setup (onCreate before setContentView, or in a base activity all sensitive screens extend) and not subsequently cleared.
- Finding: a sensitive screen with no `FLAG_SECURE` anywhere in its window setup, OR a `clearFlags(FLAG_SECURE)` / `setFlags` overwrite that removes it on a sensitive screen without an adequate justification.

Procedure
1. Identify sensitive screens: from `app_capabilities.json`/`components.json` and code - login, payment, account, OTP, secure-content activities/fragments. Quote the basis (what sensitive data each shows).
2. Enumerate flag handling: `grep -rEn "FLAG_SECURE|addFlags|setFlags|clearFlags|setRecentsScreenshotEnabled" jadx/sources/`. Map each to its screen (note a shared base activity that sets it for all).
3. For each sensitive screen, determine: FLAG_SECURE set and kept (Compliant), absent (Finding), or set-then-cleared (Finding). Quote it.
4. Owner: app (proprietary).
5. Conclude per sensitive screen: Finding (no FLAG_SECURE / cleared, quoted); Compliant (set and kept, quoted); Unverified (sensitivity/flag handling unresolved).
6. Budget ~2-4 reads per screen (the window setup, any base class, any clearFlags). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The actual screenshot content is confirmed dynamically (MASTG-TEST-0289). Recents-specific control is MASTG-TEST-0292; SurfaceView is MASTG-TEST-0293; Compose dialogs MASTG-TEST-0294. This test is the FLAG_SECURE reference coverage on sensitive screens. Screen handling in native/no-source code -> `unverified`.

Output
List **all** sensitive screens - one L1 row per screen with its FLAG_SECURE disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant screens covered by a base activity, but always break out every Finding and unverified screen individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the sensitive screen (and its data) and the absence/clearing of FLAG_SECURE, plus owner.
- Compliant: L1 row plus an L2 quoting the FLAG_SECURE set (and that it is not cleared).

```
{
  "id": "fs-001",
  "description": "Finding (sensitive screen without FLAG_SECURE): The payment-entry activity displays card data but never sets FLAG_SECURE, so screenshots/recording capture it.",
  "reference": "jadx/sources/com/example/app/pay/CardEntryActivity.java",
  "level": 1
},
{
  "id": "L2-fs-screen",
  "description": "Sensitive screen (quoted): CardEntryActivity.onCreate inflates the card-number/CVV form (R.layout.card_entry) at CardEntryActivity.java:28-34 - displays payment data.",
  "reference": "jadx/sources/com/example/app/pay/CardEntryActivity.java:28-34",
  "level": 2
},
{
  "id": "L2-fs-missing",
  "description": "No FLAG_SECURE (quoted searches): no addFlags(FLAG_SECURE)/setFlags(FLAG_SECURE) in CardEntryActivity or its parent BaseActivity (grep clean for FLAG_SECURE on this path). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/pay/CardEntryActivity.java",
  "level": 2
},
{
  "id": "fs-ok-001",
  "description": "Compliant: all sensitive screens extend a base activity that sets FLAG_SECURE.",
  "reference": "jadx/sources/com/example/app/SecureBaseActivity.java",
  "level": 1
},
{
  "id": "L2-fs-ok",
  "description": "FLAG_SECURE set (quoted): getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE) in SecureBaseActivity.onCreate at SecureBaseActivity.java:18; CardEntryActivity extends SecureBaseActivity; never cleared.",
  "reference": "jadx/sources/com/example/app/SecureBaseActivity.java:18",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0291",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S sensitive screens identified, P protected by FLAG_SECURE (set and kept), N findings (missing / cleared), U unverified. Any sensitive screen unprotected? <no -> pass / n-a if no sensitive screens / yes -> fail>. <one or two sentences naming each finding>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime screenshot confirmation is MASTG-TEST-0289); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive screen with (a) an L2 quoting the screen + its sensitive data AND (b) an L2 showing FLAG_SECURE absent (searches) or cleared without justification. A finding stated with "likely"/"may" instead of the quoted screen+absence is INVALID -> `unverified`.
- **Base-class coverage counts.** A shared base activity setting FLAG_SECURE covers all subclasses - quote the inheritance. Do not flag a subclass whose base sets it.
- **Clearing is a finding.** `clearFlags(FLAG_SECURE)` / a `setFlags` overwrite on a sensitive screen removes protection - flag it unless justified.
- **Sensitive screens only.** Non-sensitive screens need no FLAG_SECURE - do not flag them.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the screen sensitive? is FLAG_SECURE set?) resolved by reading, unresolved -> `unverified`.
- `pass`: every sensitive screen sets and keeps FLAG_SECURE, with L2 coverage.
- `n/a`: the app has no sensitive screens (state how concluded).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its sensitive-screen + missing/cleared-FLAG_SECURE L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the sensitive screen and its data are quoted; (2) FLAG_SECURE is shown absent (searches incl. any base class) or cleared; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm sensitive screens were identified, the FLAG_SECURE search was performed (incl. base classes), every finding screen's flag handling was read and quoted (unread -> `unverified`), no base-covered screen was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
