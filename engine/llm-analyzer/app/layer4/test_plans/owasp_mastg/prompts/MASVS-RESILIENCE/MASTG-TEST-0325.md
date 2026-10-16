MASTG-TEST-0325

maswe_id       MASWE-0097
masvs_v2_id    MASVS-RESILIENCE-1
platform       android
title          Runtime Use of Root Detection Techniques (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0325 is a dynamic test (hook common root-detection APIs / trace syscalls at runtime to confirm root checks fire). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0324 (presence of root-detection mechanisms in code/native/libraries). OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only hooking/tracing at runtime confirms the checks actually execute (and a rooted device/emulator is recommended).

What this test looks for
At runtime the app should perform root detection. Statically, the proxy is the presence of root-detection mechanisms (as in MASTG-TEST-0324). PRESENCE test: FAILS if no root detection is found. Verdict: `pass` (>=1 root-detection mechanism), `fail` (none found), `n/a` (anti-tampering not in scope - state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the root-detection indicators (below). >=1 genuine -> lean PASS; none -> lean FAIL (state the searches). Runtime execution is still flagged via the forced `needs_dynamic_testing`.

Root-detection indicators (any genuine one -> pass)
su-path checks (`/system/xbin/su`, `which su`, `Runtime.exec("su")`), management apps (Magisk/SuperSU/Superuser.apk), `Build.TAGS` `test-keys`, RASP libraries (RootBeer `com.scottyab.rootbeer`, freerasp), SafetyNet/Play Integrity attestation, `/proc/mounts` rw-system checks, native root checks.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 root-detection check. For FAIL, show empty searches. No quoted evidence -> `inconclusive`/`unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No verdict by inference/hedge.** PASS needs a quoted check; FAIL needs shown-empty searches. "probably checks at runtime" is NOT static proof -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`/`inconclusive`.** Obfuscated/native checks may evade static detection - say so. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "/su\b|/system/xbin/su|which su|test-keys|magisk|supersu|Superuser|rootbeer|isRooted|checkRoot|SafetyNet|PlayIntegrity|/proc/mounts" jadx/sources/ jadx/resources/`; scan native libs / `detected_libraries.json` for RASP libs.
2. >=1 genuine mechanism -> PASS (quote it); none -> FAIL (state the searches; lower certainty; note native/obfuscation caveat).
3. Owner: note proprietary vs RASP library.
4. Budget ~2-4 reads. Unresolved -> `unverified`/`inconclusive`.

Out-of-scope / static limits
Robustness/effectiveness is OUT OF SCOPE - presence only. Whether checks fire at runtime is the dynamic test's job - hence the forced `needs_dynamic_testing`. Static presence is MASTG-TEST-0324. Native/obfuscated checks may be missed.

Output
One L1 row stating whether root-detection logic exists, with a quoted example (pass) or the empty-search result (fail).
- Pass: L1 row plus L2(s) quoting genuine root-detection checks.
- Fail: L1 row plus an L2 showing the searches returned nothing.

```
{
  "id": "rootr-001",
  "description": "Pass: the app references RootBeer root detection; runtime hook confirms execution.",
  "reference": "jadx/sources/com/example/app/RootCheck.java",
  "level": 1
},
{
  "id": "L2-rootr-check",
  "description": "Root detection (quoted): boolean rooted = new RootBeer(ctx).isRooted(); at RootCheck.java:48; su-path checks at lines 30-40. Owner: com.scottyab.rootbeer (RASP). Runtime hook confirms the check fires.",
  "reference": "jadx/sources/com/example/app/RootCheck.java:30-48",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0325",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R root-detection mechanisms found. Any root detection present? <yes -> pass / no -> fail>. <one or two sentences>; runtime hook/trace confirms execution. Note: static analysis may miss obfuscated/native checks.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... e.g. native/obfuscated root checks not statically visible ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `pass`: >=1 genuine root-detection mechanism is quoted (presence test).
- `fail`: the root-detection searches (code + native + libraries) return nothing (state them); lower certainty; add a native/obfuscation `false_positive_risks` note. A FAIL asserted without the shown searches is INVALID -> `unverified`.
- **Presence, not robustness** (out of scope). **Ownership note** (RASP libraries count; OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification.
- `false_positive_risks` out-of-APK / non-static only.
- `unverified`/`inconclusive` if searches incomplete or the verdict lacks quoted/empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS a genuine root-detection check is quoted; (2) for FAIL the code+native+library searches are shown empty AND a native/obfuscation caveat recorded; (3) robustness not assessed.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `unverified`.
Before emitting: confirm the searches were performed, the verdict rests on quoted/empty-search evidence, and `false_positive_risks` notes only non-static factors. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
