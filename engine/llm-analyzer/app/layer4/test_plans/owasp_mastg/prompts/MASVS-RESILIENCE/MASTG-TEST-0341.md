MASTG-TEST-0341

maswe_id       MASWE-0107
masvs_v2_id    MASVS-RESILIENCE-4
platform       android
title          Hook / Instrumentation Detection Techniques (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0341 is a dynamic test (hook sensitive APIs at runtime and confirm the app detects/responds - e.g. terminates - to instrumentation). This static engine cannot instrument the app, so this prompt performs the best-effort static equivalent - detect the PRESENCE of anti-hooking / anti-instrumentation (Frida/Xposed/etc.) detection logic. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only attempting to hook at runtime proves the app actually detects and responds.

What this test looks for
A resilience-profile (R) app should detect and respond to runtime instrumentation/hooking (Frida, Xposed, Substrate). PRESENCE test: it FAILS if no hook/instrumentation-detection logic is found. Verdict: `pass` (>=1 genuine hook/instrumentation-detection mechanism), `fail` (none found), `n/a` (anti-tampering not in scope - state the justification), or `inconclusive`. (Static analysis may miss obfuscated/native checks - reflect in certainty + `false_positive_risks`.)

SHORT-CIRCUIT (decide first): `grep` for the indicators below. >=1 genuine -> lean PASS; none -> lean FAIL (state the searches). Robustness is OUT OF SCOPE - presence only.

Hook/instrumentation-detection indicators (any genuine one -> pass)
- Frida: strings/checks for `frida`, `frida-server`, `gum-js-loop`, `gmain`, default Frida ports (`27042`/`27043`), `re.frida.server`, `/data/local/tmp/frida*`, scanning `/proc/self/maps` for `frida`/`gadget`.
- Xposed / Substrate: `de.robv.android.xposed`, `XposedBridge`, `XC_MethodHook`, `/system/framework/XposedBridge.jar`, `com.saurik.substrate`, `app_process` tampering.
- Generic instrumentation: scanning loaded libraries / `/proc/self/maps` for injected `.so`, checking for unexpected JDWP, inline-hook/PLT-hook integrity checks, native `dlopen`/`maps` self-inspection, stack-trace inspection for hooking frameworks.
- RASP libraries (freerasp, DexProtector, Promon, AppSealing) that bundle anti-hooking.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 genuine hook-detection check. For FAIL, show empty searches. No quoted evidence -> `inconclusive`/`unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` (or the native string location), not an index record or line 1.
3. **No verdict by inference/hedge.** PASS needs a quoted check; FAIL needs shown-empty searches. "probably detects Frida" is NOT static proof -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`/`inconclusive`.** Obfuscated/native anti-hooking commonly evades static detection - say so. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "frida|gum-js|gmain|27042|27043|re\.frida|xposed|XposedBridge|substrate|app_process|/proc/self/maps|gadget|InMemoryDexClassLoader" jadx/sources/ jadx/resources/`; scan native libs (strings) and `detected_libraries.json` for RASP libs.
2. >=1 genuine mechanism -> PASS (quote it); none -> FAIL (state the searches; lower certainty; note native/obfuscation caveat).
3. Owner: note proprietary vs RASP library.
4. Budget ~2-5 reads (code + native strings). Unresolved -> `unverified`/`inconclusive`.

Out-of-scope / static limits
Robustness/effectiveness and whether the app actually RESPONDS (terminates) is the dynamic test's job - hence the forced `needs_dynamic_testing`. Native/obfuscated anti-hooking may be missed -> reflect in certainty + `false_positive_risks`.

Output
One L1 row stating whether hook/instrumentation-detection logic exists, with a quoted example (pass) or the empty-search result (fail).
- Pass: L1 row plus L2(s) quoting genuine hook-detection checks.
- Fail: L1 row plus an L2 showing the searches (code + native + libraries) returned nothing.

```
{
  "id": "hook-001",
  "description": "Pass: the app scans /proc/self/maps and checks for Frida artifacts.",
  "reference": "jadx/sources/com/example/app/AntiHook.java",
  "level": 1
},
{
  "id": "L2-hook-check",
  "description": "Hook detection (quoted): reads /proc/self/maps and returns true if it contains \"frida\" or \"gadget\"; also checks ports 27042/27047 at AntiHook.java:30-52. Owner: com.example.app (proprietary). Runtime confirmation of the response is required.",
  "reference": "jadx/sources/com/example/app/AntiHook.java:30-52",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0341",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "H hook/instrumentation-detection mechanisms found (Frida/Xposed/maps-scan/RASP). Any anti-hooking present? <yes -> pass / no -> fail>. <one or two sentences>; runtime hooking confirms detection+response. Note: static analysis may miss obfuscated/native checks.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... e.g. native/obfuscated anti-hooking not statically visible ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation (and the app's response) is warranted; it does not change the static `pass`/`fail`.
- `pass`: >=1 genuine hook/instrumentation-detection mechanism is quoted (presence test).
- `fail`: the searches (code + native + libraries) return nothing (state them); lower certainty; add a native/obfuscation `false_positive_risks` note. A FAIL asserted without the shown searches is INVALID -> `unverified`.
- **Presence, not robustness/response** (out of scope statically). **Ownership note** (RASP libraries count; OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification.
- `false_positive_risks` out-of-APK / non-static only.
- `unverified`/`inconclusive` if searches incomplete or the verdict lacks quoted/empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS a genuine hook-detection check is quoted; (2) for FAIL the code+native+library searches are shown empty AND a native/obfuscation caveat recorded; (3) robustness/response not assessed.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `unverified`.
Before emitting: confirm the searches were performed, the verdict rests on quoted/empty-search evidence, and `false_positive_risks` notes only non-static factors. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
