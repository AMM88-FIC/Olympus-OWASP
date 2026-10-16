MASTG-TEST-0340

maswe_id       MASWE-0053
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          References to Overlay Attack Protections - tapjacking on sensitive UI (static)

What this test looks for
Overlay (tapjacking) attacks place deceptive UI over the app to trick users into actions (granting permissions, confirming payments, revealing credentials). The app should protect SENSITIVE UI elements with touch-filtering so taps are ignored when the view is obscured. This test checks whether the app references overlay-protection mechanisms on its sensitive interactions. Verdict: `pass` (sensitive UI is protected by an overlay mechanism), `fail` (>=1 sensitive interaction has no overlay protection), `n/a` (the app has no sensitive user interactions - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): identify sensitive interactions (login, payment/transaction confirm, permission grant prompts, security settings, biometric/PIN confirm). If none -> `n/a` (state how concluded). Then `grep` for the protection APIs.

Overlay-protection mechanisms (any adequately covering the sensitive UI -> Compliant)
- `View.setFilterTouchesWhenObscured(true)` (programmatic) or `android:filterTouchesWhenObscured="true"` (layout) on the sensitive view.
- Overriding `View.onFilterTouchEventForSecurity(MotionEvent)` to enforce a custom policy.
- Checking `MotionEvent.FLAG_WINDOW_IS_OBSCURED` / `FLAG_WINDOW_IS_PARTIALLY_OBSCURED` in touch handlers for sensitive interactions and rejecting obscured taps.
- `Window.setHideOverlayWindows(true)` + the `HIDE_OVERLAY_WINDOWS` permission (API 31+).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code/layout it rests on.** Quote the sensitive interaction AND its overlay protection (or the absence of any). No quoted evidence -> `unverified`.
2. **Read from the actual code/layout, not the index.** Cite `jadx/sources/...:<line-range>` / `jadx/resources/res/layout/...:<line>`, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) a sensitive interaction and (b) the absence of any overlay protection (searches). "probably tapjackable" with no quoted interaction is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If an interaction's sensitivity or its protection can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Identify sensitive interactions (login submit, payment confirm, permission/consent buttons, security-setting toggles, PIN/biometric confirm). Quote the basis.
2. Enumerate protections: `grep -rEn "setFilterTouchesWhenObscured|filterTouchesWhenObscured|onFilterTouchEventForSecurity|FLAG_WINDOW_IS_OBSCURED|FLAG_WINDOW_IS_PARTIALLY_OBSCURED|setHideOverlayWindows|HIDE_OVERLAY_WINDOWS" jadx/sources/ jadx/resources/`. Also note `targetSdkVersion` and the `HIDE_OVERLAY_WINDOWS` permission (for the API-31 mechanism). Map protections to the sensitive UI they cover.
3. For each sensitive interaction, determine whether any mechanism protects it. None -> finding. Quote the protection or its absence.
4. Owner: app (proprietary).
5. Conclude per sensitive interaction: Finding (no overlay protection, quoted); Compliant (a mechanism covers it, quoted); Unverified (sensitivity/protection unresolved).
6. Budget ~2-4 reads per interaction (the view/handler, the protection, any base). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Whether an overlay actually succeeds is runtime/device-specific; this static test judges PROTECTION coverage on sensitive UI. UI handling in native/no-source code -> `unverified`.

Output
List **all** sensitive interactions - one L1 row per interaction with its disposition - plus an Observation row for `targetSdkVersion` and the `HIDE_OVERLAY_WINDOWS` permission. <=20 -> one L1 row each. >20 (collapse) -> group Compliant protected interactions, but always break out every Finding and unverified interaction individually. Never sample findings.
- Observation: L1 row with `targetSdkVersion` and whether `HIDE_OVERLAY_WINDOWS` is declared.
- Finding: L1 row plus L2 rows quoting the sensitive interaction and the absence of any overlay protection, plus owner.
- Compliant: L1 row plus an L2 quoting the protection mechanism covering it.

```
{
  "id": "ov-001",
  "description": "Finding (sensitive interaction without overlay protection): The payment-confirm button has no touch filtering, so a malicious overlay could capture or redirect the confirmation tap.",
  "reference": "jadx/sources/com/example/app/pay/ConfirmActivity.java",
  "level": 1
},
{
  "id": "L2-ov-ui",
  "description": "Sensitive interaction (quoted): the 'Confirm payment' button (R.id.confirmPay) triggers paymentService.authorize(...) at ConfirmActivity.java:40-46.",
  "reference": "jadx/sources/com/example/app/pay/ConfirmActivity.java:40-46",
  "level": 2
},
{
  "id": "L2-ov-missing",
  "description": "No overlay protection (quoted searches): no setFilterTouchesWhenObscured / filterTouchesWhenObscured / onFilterTouchEventForSecurity / FLAG_WINDOW_IS_OBSCURED check / setHideOverlayWindows for this screen (grep clean); the confirm button's layout has no filterTouchesWhenObscured. Owner: com.example.app (proprietary).",
  "reference": "jadx/resources/res/layout/confirm.xml",
  "level": 2
},
{
  "id": "ov-ok-001",
  "description": "Compliant: login button filters obscured touches.",
  "reference": "jadx/resources/res/layout/login.xml",
  "level": 1
},
{
  "id": "L2-ov-ok",
  "description": "Protection (quoted): <Button android:id=\"@+id/login\" android:filterTouchesWhenObscured=\"true\"/> at res/layout/login.xml:30 - taps ignored when obscured.",
  "reference": "jadx/resources/res/layout/login.xml:30",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0340",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "targetSdkVersion=<N>, HIDE_OVERLAY_WINDOWS <declared/absent>. S sensitive interactions, P protected (filterTouchesWhenObscured / onFilterTouchEventForSecurity / obscured-flag check / setHideOverlayWindows), N findings (unprotected), U unverified. Any sensitive interaction unprotected? <no -> pass / n-a if none / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 sensitive interaction with (a) an L2 quoting the interaction AND (b) an L2 showing no overlay protection mechanism covering it (searches). A finding stated with "likely"/"may" instead of the quoted absence is INVALID -> `unverified`.
- **Any mechanism suffices.** `filterTouchesWhenObscured`, `onFilterTouchEventForSecurity`, an obscured-flag check, or `setHideOverlayWindows(true)`+permission covering the sensitive UI is Compliant. Quote it.
- **Sensitive interactions only.** Non-sensitive UI need not be protected - do not flag.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the interaction sensitive? protected?) resolved by reading, unresolved -> `unverified`.
- `pass`: every sensitive interaction has overlay protection, with L2 coverage.
- `n/a`: no sensitive user interactions (state how concluded).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its interaction + missing-protection L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the sensitive interaction is quoted; (2) no overlay-protection mechanism covering it is present (searches); (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm sensitive interactions were identified, the protection search was performed, every finding interaction's protection was read and quoted/shown-absent (unread -> `unverified`), no protected interaction was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
