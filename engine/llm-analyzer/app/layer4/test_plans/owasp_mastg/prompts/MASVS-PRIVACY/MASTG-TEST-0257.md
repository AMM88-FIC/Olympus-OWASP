MASTG-TEST-0257

maswe_id       MASWE-0117
masvs_v2_id    MASVS-PRIVACY-1
platform       android
title          Not Resetting Unused Permissions - auto-revoke of unused permissions disabled (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0257 as a `status: placeholder` (no procedure body; note: "checks if the app does not remove unnecessary access to granted permissions"). This prompt implements the best-effort static detection: whether the app DISABLES Android's automatic reset of unused runtime permissions (the system auto-revokes permissions of unused apps on API 30+), or otherwise prevents permissions it no longer needs from being relinquished.

What this test looks for
Android automatically revokes the runtime permissions of apps that go unused for a few months (default behavior on API 30+). An app should NOT opt out of this without strong justification. This test flags the app opting out of permission auto-reset (or requesting the user to exempt it). Verdict: `pass` (the app does not disable auto-revoke - it relies on the default, or proactively relinquishes unused permissions), `fail` (>=1 site disables/whitelists the app from permission auto-reset, or directs the user to exempt the app, without justification), `n/a` (the app holds no runtime permissions to reset - state it), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the auto-revoke / hibernation opt-out APIs below. If NONE appear AND the app declares dangerous permissions -> the app relies on the default auto-reset -> lean `pass` (state the search). If none AND no dangerous permissions -> `n/a`.

Auto-revoke opt-out indicators (finding)
- `PackageManager.isAutoRevokeWhitelisted()` used to confirm/maintain an exemption, `PackageManager.setAutoRevokeWhitelisted(...)`.
- The manifest `<application android:autoRevokePermissions="disallowed">` (or equivalent) opting out.
- Launching `Intent.ACTION_AUTO_REVOKE_PERMISSIONS` / `ACTION_APPLICATION_DETAILS_SETTINGS` to ask the user to DISABLE auto-revoke / unused-app hibernation for the app.
- `REQUEST_PERMISSIONS`-adjacent flows that re-request and hold permissions to defeat reset.
Compliant: none of the above (default auto-reset stays on); or code that proactively relinquishes/relies on the default.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the opt-out call / manifest attribute (finding), or show its absence (compliant). No quoted evidence -> `unverified`.
2. **Read from the actual files, not the index.** Cite `jadx/sources/...:<line-range>` / `jadx/resources/AndroidManifest.xml:<line>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting an auto-revoke opt-out. "probably keeps permissions" without a quoted opt-out is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If an opt-out's intent can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "isAutoRevokeWhitelisted|setAutoRevokeWhitelisted|autoRevokePermissions|ACTION_AUTO_REVOKE|unused app|hibernation|REQUEST_DISABLE" jadx/sources/ jadx/resources/AndroidManifest.xml`. Also confirm whether the app declares dangerous runtime permissions (otherwise n/a).
2. For each opt-out indicator, determine whether the app disables/whitelists itself from auto-reset or steers the user to do so. Quote it.
3. If no opt-out exists, the app relies on the default auto-reset -> Compliant (state the empty search).
4. Owner: app (proprietary).
5. Conclude: Finding (auto-revoke opt-out, quoted); Compliant (default relied upon / proactive relinquishment); Unverified (intent unresolved).
6. Budget ~2-3 reads (the opt-out site, the manifest attribute). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether the app TRULY no longer needs a permission is product context; this static test flags the app DISABLING the platform's reset mechanism (the detectable proxy for "not resetting unused permissions"). Permission justification is MASTG-TEST-0254; minimization is MASTG-TEST-0255. Opt-out via native code -> `unverified`.

Output
A small table: whether the app opts out of permission auto-reset.
- Finding: L1 row plus an L2 quoting the auto-revoke opt-out (call/manifest/user-steering), plus owner.
- Compliant: L1 row plus an L2 showing no opt-out (default auto-reset relied upon).

```
{
  "id": "rev-001",
  "description": "Finding (app disables unused-permission auto-reset): The app sets itself as auto-revoke whitelisted, so unused runtime permissions are not automatically reset.",
  "reference": "jadx/sources/com/example/app/Startup.java",
  "level": 1
},
{
  "id": "L2-rev-optout",
  "description": "Auto-revoke opt-out (quoted): packageManager.setAutoRevokeWhitelisted(true); (and a prompt steering the user to 'Pause app activity if unused' = OFF) at Startup.java:40-48 - the app prevents the platform from resetting its unused permissions. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Startup.java:40-48",
  "level": 2
},
{
  "id": "rev-ok-001",
  "description": "Compliant: no auto-revoke opt-out found; the app relies on the default reset of unused permissions.",
  "reference": "jadx/sources/",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0257",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Auto-revoke opt-out indicators: <found/none>. O opt-out sites (whitelist / manifest disallow / user-steering). Does the app prevent unused-permission reset? <no -> pass / n-a if no runtime perms / yes -> fail>. <one sentence>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 quoted auto-revoke opt-out (`setAutoRevokeWhitelisted(true)`, manifest `autoRevokePermissions="disallowed"`, or steering the user to disable unused-app hibernation) without justification. A finding stated with "likely"/"may" instead of the quoted opt-out is INVALID -> `unverified`.
- **Default-on is Compliant.** Absence of any opt-out means the platform's auto-reset stays on -> pass (state the empty search).
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts resolved by reading, unresolved -> `unverified`.
- `pass`: no auto-revoke opt-out (default reset relied upon), with the search shown.
- `n/a`: the app holds no runtime permissions to reset (state it).
- `unverified` rows name the deepest unresolved point (or native entry point). Neither pass nor fail.
- `inconclusive` if the cited evidence doesn't support the verdict, if any false_positive_risk references resolvable in-APK code, or if a `fail` lacks its quoted opt-out.

Self-check before emitting
Confirm: (1) for FAIL the auto-revoke opt-out is quoted; (2) for PASS the opt-out search is shown empty; (3) the app actually holds runtime permissions (else n/a).
Hedge scan: "likely", "may", "appears", "probably", "might" -> `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the opt-out search was performed (code + manifest), the verdict rests on quoted evidence / a shown-empty search, and no `false_positive_risks` entry describes a resolvable in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
