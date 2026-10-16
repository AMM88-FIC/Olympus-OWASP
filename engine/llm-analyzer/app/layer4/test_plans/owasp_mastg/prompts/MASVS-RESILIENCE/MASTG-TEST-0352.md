MASTG-TEST-0352

maswe_id       MASWE-0101
masvs_v2_id    MASVS-RESILIENCE-4
platform       android
title          References to Debugging Detection APIs (static)

What this test looks for
A resilience-profile (R) app should detect debuggers (JDWP at the Java level, native anti-debug at the C/C++ level), since a debugger lets an attacker inspect/modify runtime state. PRESENCE test: it FAILS if the app references NO debugging-detection mechanism in either Java/Kotlin or native code. Verdict: `pass` (>=1 genuine debugging-detection mechanism), `fail` (none found in Java/Kotlin or native), `n/a` (anti-tampering not in scope - state the justification), or `inconclusive`. (Static analysis may miss obfuscated/native checks - reflect in certainty + `false_positive_risks`.)

SHORT-CIRCUIT (decide first): `grep` for the indicators below (Java AND native). >=1 genuine -> lean PASS; none -> lean FAIL (state both searches). Robustness is OUT OF SCOPE - presence only.

Debugging-detection indicators (any genuine one -> pass)
- Java/Kotlin (JDWP): `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`, checking `ApplicationInfo.FLAG_DEBUGGABLE` as an anti-debug gate, `android.os.Debug` timing checks.
- Native: `ptrace(PTRACE_TRACEME, ...)` self-trace, reading `/proc/self/status` for `TracerPid` != 0, `/proc/self/stat`, inlined anti-debug syscalls, `fork`+`ptrace` self-attach, checking `TracerPid` in native code.
- RASP libraries (freerasp, DexProtector, Promon) bundling anti-debug.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 genuine debug-detection check (Java or native). For FAIL, show both searches returned nothing. No quoted evidence -> `inconclusive`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` (Java) or the native library + symbol/string (native), not an index record or line 1.
3. **No verdict by inference/hedge.** PASS requires a quoted check; FAIL requires shown-empty Java AND native searches. "probably detects debuggers" is NOT evidence -> `inconclusive`.
4. **Unresolved determinacy is `inconclusive`.** Obfuscated/native/inline-syscall anti-debug commonly evades static detection - say so. `false_positive_risks` is out-of-APK only.

Procedure
1. Java/Kotlin: `grep -rEn "isDebuggerConnected|waitingForDebugger|FLAG_DEBUGGABLE|android\.os\.Debug" jadx/sources/`.
2. Native: scan extracted `.so` symbols/strings for `ptrace`, `TracerPid`, `/proc/self/status`, `/proc/self/stat` (use the native_binaries evidence imports + strings, or note that native disassembly is needed). 
3. >=1 genuine mechanism (Java OR native) -> PASS (quote it). None in BOTH layers -> FAIL (state both searches; lower certainty; note the native/inline-syscall caveat).
4. Owner: note proprietary vs RASP library.
5. Budget ~2-5 reads (Java + native). Unresolved -> `inconclusive`.

Out-of-scope / static limits
Robustness/effectiveness and whether the check runs in release (not just debug variants) and triggers a response is partly MASTG-TEST-0353 (dynamic) - note it; this static test is PRESENCE. Native inline-syscall anti-debug may be invisible to static analysis -> reflect in certainty + `false_positive_risks`.

Output
One L1 row stating whether debugging-detection logic exists (Java/native), with a quoted example (pass) or the empty-search result (fail).
- Pass: L1 row plus L2(s) quoting genuine debug-detection checks (Java and/or native).
- Fail: L1 row plus an L2 showing the Java AND native searches returned nothing.

```
{
  "id": "dbgd-001",
  "description": "Pass: the app checks for a connected debugger (Java) and TracerPid (native).",
  "reference": "jadx/sources/com/example/app/AntiDebug.java",
  "level": 1
},
{
  "id": "L2-dbgd-check",
  "description": "Debug detection (quoted): if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) reactToDebugger(); at AntiDebug.java:30-34; native lib libsec.so imports ptrace and reads /proc/self/status TracerPid (native_binaries.json#libsec imports). Owner: com.example.app (proprietary). Effectiveness/response confirmed by MASTG-TEST-0353.",
  "reference": "jadx/sources/com/example/app/AntiDebug.java:30-34",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0352",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "D debugging-detection mechanisms found (Java JDWP / native ptrace+TracerPid / RASP). Any debug detection present? <yes -> pass / no -> fail>. <one or two sentences>. Note: static analysis may miss obfuscated/native inline-syscall checks.",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... e.g. native/inline-syscall anti-debug not statically visible ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (runtime confirmation is MASTG-TEST-0353); it does not change `pass`/`fail`.
- `pass`: >=1 genuine debugging-detection mechanism (Java or native) is quoted (presence test).
- `fail`: the Java AND native searches both return nothing (state them); lower certainty; add a native/inline-syscall `false_positive_risks` note. A FAIL asserted without both shown searches is INVALID -> `inconclusive`.
- **Both layers searched.** A FAIL must show that neither Java/Kotlin nor native debug detection was found. **Presence, not robustness** (out of scope). **Ownership note** (RASP libraries count; OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification.
- `false_positive_risks` out-of-APK / non-static only.
- `inconclusive` if searches incomplete or the verdict lacks quoted/empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS a genuine debug-detection check is quoted; (2) for FAIL both the Java and native searches are shown empty AND a native/inline-syscall caveat recorded; (3) robustness not assessed.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `inconclusive`.
Before emitting: confirm both searches were performed, the verdict rests on quoted/empty-search evidence, and `false_positive_risks` notes only non-static factors. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
