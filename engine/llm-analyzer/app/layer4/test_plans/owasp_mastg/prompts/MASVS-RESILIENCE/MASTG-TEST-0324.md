MASTG-TEST-0324

maswe_id       MASWE-0097
masvs_v2_id    MASVS-RESILIENCE-1
platform       android
title          References to Root Detection Mechanisms (static)

What this test looks for
A resilience-profile (R) app should detect rooted devices, since root undermines the platform's security guarantees. This is a PRESENCE test: it FAILS if the app implements NO root-detection logic. Verdict: `pass` (>=1 genuine root-detection mechanism), `fail` (no root-detection logic found), `n/a` (the app is not a resilience-profile app where anti-tampering is expected - state the justification), or `inconclusive`. (Static analysis may miss obfuscated/native checks - reflect that in certainty and `false_positive_risks`.)

SHORT-CIRCUIT (decide first): `grep` for the root-detection indicators below. >=1 genuine indicator -> lean PASS (quote it). NONE -> lean FAIL (state the searches). NOTE: this test does NOT assess robustness/effectiveness - only presence (per the OWASP out-of-scope note).

Root-detection indicators (any genuine one -> pass)
- su binary / path checks: `/system/xbin/su`, `/system/bin/su`, `/sbin/su`, `which su`, `Runtime.exec("su")`, `new File("/system/.../su").exists()`.
- Superuser / management apps: `eu.chainfire.supersu`, `com.topjohnwu.magisk` (Magisk), `Superuser.apk`, `com.koushikdutta.superuser`, busybox.
- Build tags / props: `Build.TAGS` containing `test-keys`, `ro.debuggable`/`ro.secure` system-prop reads for root.
- Known libraries: RootBeer (`com.scottyab.rootbeer`), RootTools, SafetyNet/Play Integrity attestation used for root/integrity, Google `DevicePolicyManager` integrity, `freerasp`, native root checks.
- Writable-system / mount checks, `/proc/mounts` for rw system.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 genuine root-detection check. For FAIL, show the searches returned nothing. No quoted evidence -> `inconclusive`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`, not an index record or line 1.
3. **No verdict by inference/hedge.** PASS requires a quoted check; FAIL requires shown-empty searches across the indicator set. "probably checks for root" is NOT evidence -> `inconclusive`.
4. **Unresolved determinacy is `inconclusive`.** Obfuscated/native root checks may evade static detection - say so; absence of findings does not prove absence of root detection. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "/su\b|/system/xbin/su|/system/bin/su|/sbin/su|which su|test-keys|magisk|supersu|Superuser|rootbeer|RootTools|busybox|isRooted|checkRoot|SafetyNet|PlayIntegrity|/proc/mounts" jadx/sources/ jadx/resources/`. Also scan native libs / `detected_libraries.json` for RootBeer/freerasp.
2. If >=1 genuine root-detection mechanism exists, quote it -> PASS. Note the owner (proprietary vs a known RASP library).
3. If none exist, state the searches (incl. the native/library scan) and conclude FAIL - but lower certainty and add a `false_positive_risks` note that obfuscated/native checks may be undetected.
4. Budget ~2-4 reads. Unresolved -> `inconclusive`.

Out-of-scope / static limits
Robustness/effectiveness of the detection is OUT OF SCOPE (per OWASP) - this is presence only. Runtime confirmation is MASTG-TEST-0325. Native/obfuscated/dynamically-loaded root checks may be missed -> reflect in certainty + `false_positive_risks`.

Output
One L1 row stating whether root-detection logic exists, with a quoted example (pass) or the empty-search result (fail). If multiple mechanisms, list the notable ones.
- Pass: L1 row plus L2(s) quoting genuine root-detection checks.
- Fail: L1 row plus an L2 showing the searches (incl. native/library) returned nothing.

```
{
  "id": "root-001",
  "description": "Pass: the app implements root detection (su-path checks + RootBeer).",
  "reference": "jadx/sources/com/example/app/RootCheck.java",
  "level": 1
},
{
  "id": "L2-root-check",
  "description": "Root detection (quoted): for (String p : SU_PATHS) if (new File(p).exists()) return true; with SU_PATHS = {\"/system/xbin/su\", \"/sbin/su\", ...} at RootCheck.java:30-40; also new RootBeer(ctx).isRooted() at line 48. Owner: com.example.app + com.scottyab.rootbeer (RASP library).",
  "reference": "jadx/sources/com/example/app/RootCheck.java:30-48",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0324",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "R root-detection mechanisms found (su-paths/management-apps/Build.TAGS/RASP libs/native). Any root detection present? <yes -> pass / no -> fail>. <one or two sentences>. Note: static analysis may miss obfuscated/native checks.",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... e.g. obfuscated/native root checks not statically visible ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime confirmation is MASTG-TEST-0325); it does not change `pass`/`fail`.
- `pass`: >=1 genuine root-detection mechanism is quoted (presence test). Even one suffices.
- `fail`: the root-detection searches (code + native + libraries) return nothing (state them). Lower the certainty and add a `false_positive_risks` note that obfuscated/native checks may exist undetected. A FAIL asserted without the shown searches is INVALID -> `inconclusive`.
- **Presence, not robustness.** Do not assess effectiveness (out of scope). One genuine check passes.
- **Ownership note.** A known RASP library (RootBeer/freerasp) counts; note it (OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification that anti-tampering is not in scope for this app.
- `false_positive_risks` out-of-APK / non-static only (native/obfuscated checks).
- `inconclusive` if the searches could not be completed or the verdict lacks quoted/empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS a genuine root-detection check is quoted; (2) for FAIL the code + native + library searches are shown empty AND a native/obfuscation caveat is recorded; (3) robustness was not assessed.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `inconclusive`.
Before emitting: confirm the searches were performed (incl. native/library), the verdict rests on quoted/empty-search evidence, and `false_positive_risks` notes only non-static factors. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
