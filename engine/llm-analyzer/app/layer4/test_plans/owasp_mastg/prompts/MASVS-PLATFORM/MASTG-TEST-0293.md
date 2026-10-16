MASTG-TEST-0293

maswe_id       MASWE-0055
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          setSecure Not Used to Prevent Screenshots in SurfaceViews (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0293 as a `status: placeholder` (no procedure body; note: "verifies whether an app prevents sensitive data from being captured in screenshots and screen recordings of SurfaceView components"). This prompt implements the best-effort static detection: whether `SurfaceView` components that display sensitive content call `SurfaceView.setSecure(true)`. A secure SurfaceView appears blank in screenshots/recordings/non-secure displays.

What this test looks for
A `SurfaceView` (or `GLSurfaceView`/`VideoView`-backed surface) rendering sensitive content - secure video, a camera preview of a document, a custom secure canvas - should call `setSecure(true)` so its contents are excluded from screen capture. (FLAG_SECURE on the window also covers it, but a SurfaceView in an otherwise non-secure window needs `setSecure`.) This is a static evaluation. Verdict: `pass` (every sensitive SurfaceView is secured via setSecure(true), or the hosting window sets FLAG_SECURE), `fail` (>=1 sensitive SurfaceView has neither), `n/a` (the app uses no SurfaceView with sensitive content - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `SurfaceView`/`setSecure`. If NO SurfaceView appears -> `n/a` (state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the SurfaceView (and the sensitive content it renders) AND its `setSecure(true)` or the absence of it (and of a hosting FLAG_SECURE). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a SurfaceView rendering sensitive content and (b) the absence of setSecure(true) and a hosting FLAG_SECURE. "the surface probably shows secrets" with no quoted content is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the surface content's sensitivity or the setSecure/FLAG_SECURE state can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate SurfaceViews: `grep -rEn "SurfaceView|GLSurfaceView|setSecure|FLAG_SECURE" jadx/sources/` and `res/layout` for `<SurfaceView>`/custom surface subclasses. If none -> short-circuit `n/a` (state the search).
2. For each SurfaceView, determine what it renders and whether it is sensitive (secure video/DRM, document camera preview, secure custom canvas). Non-sensitive surfaces (game graphics, decorative animation) -> Compliant (note). Quote the content.
3. For each sensitive SurfaceView, check for `setSecure(true)` on it, OR FLAG_SECURE on its hosting window/activity. Neither -> finding. Quote it.
4. Owner: app (proprietary).
5. Conclude per SurfaceView: Finding (sensitive + no setSecure + no hosting FLAG_SECURE, quoted); Compliant (setSecure(true) / hosting FLAG_SECURE / non-sensitive); Unverified (content/protection unresolved).
6. Budget ~2-4 reads per SurfaceView (the construction, the content render, the setSecure / window flags). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
General FLAG_SECURE coverage is MASTG-TEST-0291; Recents control is MASTG-TEST-0292; Compose dialogs MASTG-TEST-0294. This test is `SurfaceView.setSecure`. Surface rendering in native/no-source code -> `unverified`.

Output
List **all** SurfaceViews rendering app content - one L1 row per SurfaceView with its disposition. Always break out every Finding and unverified SurfaceView individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the sensitive SurfaceView (and content) and the absence of setSecure/FLAG_SECURE, plus owner.
- Compliant: L1 row plus an L2 quoting setSecure(true) / hosting FLAG_SECURE / non-sensitive content.

```
{
  "id": "sv-001",
  "description": "Finding (sensitive SurfaceView not secured): A SurfaceView shows a live camera preview of the user's ID document but never calls setSecure(true), and the hosting activity has no FLAG_SECURE.",
  "reference": "jadx/sources/com/example/app/kyc/DocScanView.java",
  "level": 1
},
{
  "id": "L2-sv-content",
  "description": "Sensitive surface (quoted): DocScanView extends SurfaceView and renders the camera preview used to capture the ID document at DocScanView.java:30-44.",
  "reference": "jadx/sources/com/example/app/kyc/DocScanView.java:30-44",
  "level": 2
},
{
  "id": "L2-sv-missing",
  "description": "No protection (quoted searches): no setSecure(true) on DocScanView and no FLAG_SECURE on DocScanActivity (grep clean for both on this path). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/kyc/DocScanView.java",
  "level": 2
},
{
  "id": "sv-ok-001",
  "description": "Compliant: secure video SurfaceView calls setSecure(true).",
  "reference": "jadx/sources/com/example/app/player/SecureSurface.java",
  "level": 1
},
{
  "id": "L2-sv-ok",
  "description": "Protection (quoted): surfaceView.setSecure(true) at SecureSurface.java:20 - excluded from screen capture.",
  "reference": "jadx/sources/com/example/app/player/SecureSurface.java:20",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0293",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "V SurfaceViews, S rendering sensitive content, P secured (setSecure(true) or hosting FLAG_SECURE), N findings (sensitive + neither), U unverified. Any sensitive SurfaceView unsecured? <no -> pass / n-a if no SurfaceView / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 SurfaceView with (a) an L2 quoting the surface + its sensitive content AND (b) an L2 showing neither setSecure(true) nor a hosting FLAG_SECURE (searches). A finding stated with "likely"/"may" instead of the quoted content+absence is INVALID -> `unverified`.
- **Either protection suffices** (setSecure(true) on the surface OR FLAG_SECURE on the host window). Quote it.
- **Sensitive content required.** A SurfaceView rendering non-sensitive content (games, decorative graphics) is Compliant - note it.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the surface sensitive? secured?) resolved by reading, unresolved -> `unverified`.
- `pass`: every sensitive SurfaceView is secured, with L2 coverage.
- `n/a`: no SurfaceView with sensitive content (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its surface-content + missing-protection L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the SurfaceView and its sensitive content are quoted; (2) neither setSecure(true) nor a hosting FLAG_SECURE is present (searches); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the SurfaceView search was performed (n/a state it), every finding surface's content and protection were read and quoted (unread -> `unverified`), no non-sensitive/secured surface was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
