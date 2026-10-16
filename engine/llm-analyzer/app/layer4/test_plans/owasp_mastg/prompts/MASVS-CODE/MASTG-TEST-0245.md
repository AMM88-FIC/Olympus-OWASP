MASTG-TEST-0245

maswe_id       MASWE-0077
masvs_v2_id    MASVS-CODE-1
platform       android
title          References to Platform Version APIs - runtime OS-version checks (static)

What this test looks for
An app should verify the OS version at runtime (`Build.VERSION.SDK_INT` compared to `Build.VERSION_CODES.*`) so it can use newer, more secure platform features when available while staying backward compatible. This test checks whether the app references the platform-version API at all. It FAILS if the app includes NO such runtime version check. This is an INVERSE/coverage test: presence -> pass, total absence -> fail. Verdict: `pass` (>=1 genuine runtime OS-version check exists), `fail` (no platform-version API reference anywhere), or `inconclusive`. (No N/A: every app can perform a version check.)

SHORT-CIRCUIT (decide first): `grep` for the platform-version APIs. If >=1 genuine reference exists -> lean PASS (quote one). If NONE exist -> lean FAIL (state the search).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 real `Build.VERSION.SDK_INT` comparison. For FAIL, show the searches returned nothing. No quoted evidence -> `inconclusive`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the actual check, not an index record or line 1.
3. **No verdict by inference/hedge.** PASS requires a quoted check; FAIL requires shown-empty searches. "probably checks the version somewhere" is NOT evidence -> `inconclusive`.
4. **Unresolved determinacy is `inconclusive`.** If the search can't be completed within budget, say so. `false_positive_risks` is out-of-APK only.

Platform-version references (any genuine one -> pass)
`Build.VERSION.SDK_INT` (compared to `Build.VERSION_CODES.*` or an int), `Build.VERSION.RELEASE`, `VERSION.SDK_INT >= N`, `if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.<X>)`, `@RequiresApi`/`Build.VERSION` guards, `ContextCompat`/`BuildCompat.isAtLeast*`. A genuine check is one used to gate behavior; a stray constant never compared is weak evidence (note it).

Procedure
1. Enumerate: `grep -rEn "Build\.VERSION\.SDK_INT|VERSION_CODES|Build\.VERSION\.RELEASE|RequiresApi|BuildCompat\.isAtLeast|SDK_INT" jadx/sources/`.
2. If >=1 genuine SDK_INT/version comparison exists (gating behavior), quote it -> PASS. Prefer a check that selects a more-secure code path on newer OS.
3. If none exist, state the search and conclude FAIL. Distinguish references inside third-party SDK code vs the app's own code - the OWASP intent is the app checks; a check only in a bundled SDK still counts as a reference but note its owner.
4. Owner: note proprietary vs library for the cited check.
5. Budget ~1-3 reads (the search, 1-2 confirmations). Unresolved -> `inconclusive`.

Out-of-scope / static limits
Whether the version check is USED effectively (gates the right behavior) is a deeper review; the OWASP control fails only on TOTAL ABSENCE of any version-check reference. `minSdkVersion` is a manifest floor, not a runtime check - do not treat a high minSdk as satisfying this test (the test wants runtime `SDK_INT` usage). Version checks in native code -> note as a limit.

Output
A small table: one L1 row stating whether any platform-version reference exists, with a quoted example (pass) or the empty-search result (fail).
- Pass: L1 row plus an L2 quoting a genuine `Build.VERSION.SDK_INT` comparison.
- Fail: L1 row plus an L2 showing the searches returned no platform-version reference.

```
{
  "id": "pv-001",
  "description": "Pass: the app performs runtime OS-version checks via Build.VERSION.SDK_INT.",
  "reference": "jadx/sources/com/example/app/Compat.java",
  "level": 1
},
{
  "id": "L2-pv-check",
  "description": "Version check (quoted): if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) { useKeystoreAuthBoundKey(); } else { useFallback(); } at Compat.java:40-46 - selects a more secure path on API 23+. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/Compat.java:40-46",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0245",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R platform-version references found (genuine SDK_INT comparisons G). Any runtime OS-version check present? <yes -> pass / no -> fail>. <one sentence: where, or that the search was empty>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `pass`: >=1 genuine `Build.VERSION.SDK_INT` (or equivalent) runtime version comparison is quoted. Even one suffices (this is a presence test).
- `fail`: the platform-version search returns NO reference anywhere (state the search). A FAIL asserted without showing the empty search is INVALID -> `inconclusive`.
- **Presence test.** Do not fail an app that has any genuine version check; do not pass an app on `minSdkVersion` alone (that is not a runtime check).
- **Ownership note.** Distinguish a check in the app's own code from one only in a bundled SDK; both are references but note the owner. (OEM-aware; obfuscated -> proprietary.)
- **No N/A.** Every app can perform a version check; the outcome is pass or fail (or inconclusive if unsearched).
- `false_positive_risks` out-of-APK only.
- `inconclusive` if the search could not be completed, or if a verdict was asserted without the quoted check / empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS, a genuine SDK_INT/version comparison is quoted; (2) for FAIL, the platform-version search is shown empty; (3) minSdk was not mistaken for a runtime check.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `inconclusive`.
Before emitting: confirm the search was performed, the verdict rests on quoted evidence (or a shown-empty search), and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
