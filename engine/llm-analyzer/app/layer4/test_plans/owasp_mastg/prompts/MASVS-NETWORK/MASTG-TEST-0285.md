MASTG-TEST-0285

maswe_id       MASWE-0052
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          Outdated Android Version Allowing Trust in User-Provided CAs - minSdkVersion below 24 (static)

What this test looks for
Apps installable on Android 6.0 (API 23) or lower implicitly trust BOTH system AND user-added CA certificates by default (the pre-Android-7 default Network Security Configuration). A user-installed malicious CA can then intercept the app's TLS traffic. Since Android 7.0 (API 24) apps no longer trust user CAs by default. This test checks the effective minimum SDK. It FAILS if `minSdkVersion < 24`. This is a static evaluation of one manifest value. Verdict: `pass` (`minSdkVersion >= 24`), `fail` (`minSdkVersion < 24`), `n/a` (rare - only if the minimum cannot apply; in practice prefer pass/fail), or `inconclusive` (the value cannot be resolved).

EVIDENCE DISCIPLINE (applies to the verdict)
1. **Quote the value it rests on.** Quote the `minSdkVersion` source (manifest `<uses-sdk>` or the merged manifest) with its line. No quoted value -> `unverified`/`inconclusive`.
2. **Read from the actual manifest, not the index.** Cite `jadx/resources/AndroidManifest.xml:<line>`. The `app_metadata.json` evidence may report minSdk; corroborate with the manifest where possible, and state which source you used.
3. **No verdict by inference/hedge.** The verdict is a numeric comparison; quote the number. "probably old" is NOT evidence -> `inconclusive`.
4. **Unresolved determinacy is `inconclusive`/`unverified`.** If `minSdkVersion` is absent and not otherwise recoverable, say so. `false_positive_risks` is out-of-APK only.

Note on sources of minSdkVersion
In a built APK, `minSdkVersion` may not appear as a literal `<uses-sdk>` element in the decompiled `AndroidManifest.xml` (it can be encoded in the manifest's compiled attributes or only in `app_metadata.json` derived from the APK). Use the most authoritative available source and STATE it. If only `app_metadata.json` has it, quote that record; if the manifest has `<uses-sdk android:minSdkVersion=...>`, quote that.

Procedure
1. Resolve `minSdkVersion`: `grep -nE "minSdkVersion|uses-sdk" jadx/resources/AndroidManifest.xml`; if absent there, consult `app_metadata.json` (min_sdk field). Quote whichever source yields it and name the source.
2. Compare to 24: `< 24` -> `fail`; `>= 24` -> `pass`. State the number.
3. Owner: app-level (proprietary).
4. Budget ~1-2 reads (manifest, app_metadata.json). Unresolvable -> `inconclusive` naming what was searched.

Out-of-scope / static limits
EXPLICIT trust of user CAs via the NSC (`<certificates src="user"/>`) is MASTG-TEST-0286 - a separate, additive finding. This test is purely the `minSdkVersion < 24` implicit-trust condition.

Output
One L1 row stating the resolved `minSdkVersion`, its source, and the disposition. An L2 quotes the value.
```
{
  "id": "minsdk-001",
  "description": "Finding (minSdkVersion < 24 - implicit trust of user CAs): the app can be installed on API 21, where the default config trusts user-added CAs, enabling interception.",
  "reference": "jadx/resources/AndroidManifest.xml",
  "level": 1
},
{
  "id": "L2-minsdk",
  "description": "minSdkVersion (quoted): <uses-sdk android:minSdkVersion=\"21\" .../> at AndroidManifest.xml:7 (corroborated by app_metadata.json min_sdk=21) - 21 < 24. Owner: app (proprietary).",
  "reference": "jadx/resources/AndroidManifest.xml:7",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0285",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "minSdkVersion = <N> (source: <manifest uses-sdk / app_metadata.json>). <N < 24 -> fail (implicit user-CA trust) / N >= 24 -> pass>. <one sentence>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: `minSdkVersion < 24`, quoted with its source. A verdict without the quoted number is INVALID -> `inconclusive`.
- `pass`: `minSdkVersion >= 24`, quoted.
- **Source transparency.** State whether the number came from the manifest `<uses-sdk>` or `app_metadata.json`. Prefer the manifest; corroborate when both exist.
- **Additive to NSC.** A pass here does NOT clear MASTG-TEST-0286 (explicit user-CA trust); a fail here is independent of it.
- **false_positive hygiene**: `false_positive_risks` out-of-APK only - the SDK value is in-APK; if unresolved -> `inconclusive`, not a guess.
- `inconclusive` if `minSdkVersion` cannot be resolved from any source (state what was searched).

Self-check before emitting
Confirm: (1) `minSdkVersion` is quoted with its source named; (2) the comparison to 24 is explicit; (3) the verdict matches the comparison.
Before emitting: confirm the manifest (and app_metadata.json if needed) were read; unresolved -> `inconclusive`; no `false_positive_risks` entry describes the in-APK SDK value. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
