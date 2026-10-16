MASTG-TEST-0289

maswe_id       MASWE-0055
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          Sensitive Content Exposure in Screenshots During App Backgrounding (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0289 is a dynamic test (background the app on each sensitive screen, then pull the task screenshots from `/data/system_ce/0/snapshots` and inspect them for sensitive content). This static engine cannot capture or inspect task screenshots, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0291 (whether sensitive screens set `FLAG_SECURE`), plus the Recents-screenshot controls (`setRecentsScreenshotEnabled(false)`). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only inspecting the actual task snapshot proves whether sensitive content is captured when backgrounded.

What this test looks for
When the app is backgrounded, Android captures a task screenshot (used in Recents); sensitive screens must prevent sensitive content from appearing there. Statically, the proxy is whether sensitive screens set `FLAG_SECURE` (which also blanks the Recents thumbnail) or disable the recents screenshot via `setRecentsScreenshotEnabled(false)`. Verdict: `pass` (every sensitive screen blocks the backgrounding screenshot via FLAG_SECURE or setRecentsScreenshotEnabled(false)), `fail` (>=1 sensitive screen has neither), `n/a` (no sensitive screens - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): identify sensitive screens. If none -> `n/a` (state how concluded). Then `grep` for `FLAG_SECURE`/`setRecentsScreenshotEnabled`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the sensitive screen AND its protection (FLAG_SECURE / setRecentsScreenshotEnabled(false)) or the absence of both. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a sensitive screen and (b) the absence of both protections (searches). "the thumbnail probably leaks" with no quoted screen is NOT static evidence -> `unverified` (flag for the snapshot inspection).
4. **Unresolved determinacy is `unverified`, not a hedge.** If screen sensitivity or protection can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Protections (either suffices, statically)
- `FLAG_SECURE` set on the sensitive screen's window (blanks the snapshot) - see MASTG-TEST-0291.
- `Activity.setRecentsScreenshotEnabled(false)` (API 33+) - disables the recents screenshot for that activity.
(Older alternatives: `setExcludeFromRecents`, or hiding sensitive views in `onPause`/`onStop`.)

Procedure
1. Identify sensitive screens (login, payment, account, OTP, secure content) from `app_capabilities.json`/`components.json` and code. Quote the basis.
2. Enumerate protections: `grep -rEn "FLAG_SECURE|addFlags|setRecentsScreenshotEnabled|setExcludeFromRecents" jadx/sources/`. Map to screens (note base activities).
3. For each sensitive screen, determine whether FLAG_SECURE OR setRecentsScreenshotEnabled(false) protects it. Neither -> finding. Quote it.
4. Owner: app (proprietary).
5. Conclude per sensitive screen: Finding (neither protection, quoted); Compliant (one protection present); Unverified (sensitivity/protection unresolved -> confirm via snapshot).
6. Budget ~2-4 reads per screen. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
The actual snapshot content is the dynamic test's job - hence the forced `needs_dynamic_testing`. FLAG_SECURE coverage in general is MASTG-TEST-0291; Recents-specific control is MASTG-TEST-0292. Screen handling in native/no-source code -> `unverified`.

Output
List **all** sensitive screens - one L1 row per screen with its disposition. Always break out every Finding and unverified screen individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the sensitive screen and the absence of both protections, plus owner.
- Compliant: L1 row plus an L2 quoting FLAG_SECURE or setRecentsScreenshotEnabled(false).

```
{
  "id": "bg-001",
  "description": "Finding (sensitive screen captured when backgrounded): The account screen shows balances but sets neither FLAG_SECURE nor setRecentsScreenshotEnabled(false), so the Recents thumbnail can expose them.",
  "reference": "jadx/sources/com/example/app/AccountActivity.java",
  "level": 1
},
{
  "id": "L2-bg-screen",
  "description": "Sensitive screen (quoted): AccountActivity displays the balance and account number (R.layout.account) at AccountActivity.java:30-38.",
  "reference": "jadx/sources/com/example/app/AccountActivity.java:30-38",
  "level": 2
},
{
  "id": "L2-bg-missing",
  "description": "No backgrounding protection (quoted searches): no FLAG_SECURE and no setRecentsScreenshotEnabled(false) for AccountActivity or its base class (grep clean on this path). Owner: com.example.app (proprietary). Snapshot inspection confirms exposure.",
  "reference": "jadx/sources/com/example/app/AccountActivity.java",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0289",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "S sensitive screens, P protected (FLAG_SECURE or setRecentsScreenshotEnabled(false)), N findings (neither), U unverified. Any sensitive screen exposed when backgrounded? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>; snapshot inspection confirms.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that snapshot inspection is warranted; it does not change the static `pass`/`fail`.
- `fail`: >=1 sensitive screen with (a) an L2 quoting the screen + sensitive data AND (b) an L2 showing neither FLAG_SECURE nor setRecentsScreenshotEnabled(false) (searches incl. base classes). A finding stated with "likely"/"may" instead of the quoted absence is INVALID -> `unverified`.
- **Either protection suffices.** FLAG_SECURE OR setRecentsScreenshotEnabled(false) on the screen (or its base) is Compliant. Quote the inheritance for base-class coverage.
- **Sensitive screens only.** Do not flag non-sensitive screens.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: every sensitive screen blocks the backgrounding screenshot, with L2 coverage.
- `n/a`: no sensitive screens (state how concluded).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its sensitive-screen + missing-protection L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the sensitive screen and its data are quoted; (2) neither FLAG_SECURE nor setRecentsScreenshotEnabled(false) is present (searches incl. base classes); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm sensitive screens were identified, the protection search was performed (incl. base classes), every finding screen's protection was read and quoted/shown-absent (unread -> `unverified`), no protected screen was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
