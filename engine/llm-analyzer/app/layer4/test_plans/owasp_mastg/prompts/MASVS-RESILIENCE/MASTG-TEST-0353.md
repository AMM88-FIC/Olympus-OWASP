MASTG-TEST-0353

maswe_id       MASWE-0101
masvs_v2_id    MASVS-RESILIENCE-4
platform       android
title          Runtime Use of Debugging Detection APIs (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0353 is a dynamic test (hook debugging-detection APIs at runtime to confirm they are invoked in security-relevant paths, not just present as dead/debug-only code). This static engine cannot hook the app, so this prompt performs the best-effort static equivalent - the same presence analysis as MASTG-TEST-0352, plus a check that the detection runs in release (not gated to debug builds) and triggers a response. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only hooking at runtime confirms the checks actually execute.

What this test looks for
At runtime the app should invoke its debugging-detection logic in security-relevant paths. Statically, the proxy is: a debugging-detection mechanism is present (MASTG-TEST-0352), is NOT confined to debug-only build variants, and leads to a response. PRESENCE+reachability test: FAILS if no debug detection is found, or it is plainly debug-only / dead code. Verdict: `pass` (>=1 debug-detection mechanism reachable in release with a response), `fail` (none found, or only debug-only/dead), `n/a` (anti-tampering not in scope - state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the indicators (Java + native). >=1 genuine + release-reachable -> lean PASS; none -> lean FAIL (state the searches). Runtime execution is still flagged via the forced `needs_dynamic_testing`.

Debug-detection indicators (any genuine one -> candidate pass)
Java: `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()`, timing checks. Native: `ptrace(PTRACE_TRACEME)`, `/proc/self/status` `TracerPid`, inline anti-debug syscalls. RASP libraries.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 debug-detection check AND that it is reachable in release (not `if (BuildConfig.DEBUG)`-gated) with a response. For FAIL, show empty searches OR that the only checks are debug-only/dead. No quoted evidence -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` / native symbol-string, not an index record or line 1.
3. **No verdict by inference/hedge.** PASS needs a quoted, release-reachable check; FAIL needs shown-empty searches or quoted debug-only gating. "probably runs at startup" is NOT static proof -> `unverified` (flag for the hook).
4. **Unresolved determinacy is `unverified`/`inconclusive`.** Reachability is hard to fully prove statically - where unclear, `unverified` and rely on the dynamic test. `false_positive_risks` is out-of-APK only.

Procedure
1. Java: `grep -rEn "isDebuggerConnected|waitingForDebugger|FLAG_DEBUGGABLE|BuildConfig\.DEBUG" jadx/sources/`. Native: scan `.so` for `ptrace`/`TracerPid`/`/proc/self/status`.
2. For each detection mechanism, check whether it is invoked outside a debug-only guard (i.e. runs in release) and leads to a response (terminate/restrict). Quote it. A check only inside `if (BuildConfig.DEBUG)` is debug-only -> not effective at runtime in release.
3. >=1 genuine release-reachable mechanism with a response -> PASS; none, or only debug-only/dead -> FAIL (state the searches/gating; note native caveat).
4. Owner: note proprietary vs RASP library.
5. Budget ~2-5 reads (Java + native + the response). Unresolved reachability -> `unverified`.

Out-of-scope / static limits
Whether the checks fire at runtime and the app responds is the dynamic test's job - hence the forced `needs_dynamic_testing`. Static presence is MASTG-TEST-0352. Native/inline-syscall anti-debug may be missed.

Output
One L1 row stating whether release-reachable debug-detection logic exists, with a quoted example (pass) or the empty/debug-only result (fail).
- Pass: L1 row plus L2(s) quoting a debug-detection check that is release-reachable with a response.
- Fail: L1 row plus an L2 showing the searches returned nothing, or that the only checks are debug-only/dead.

```
{
  "id": "dbgr-001",
  "description": "Pass: the app checks for a debugger at startup in release and terminates if detected.",
  "reference": "jadx/sources/com/example/app/AntiDebug.java",
  "level": 1
},
{
  "id": "L2-dbgr-check",
  "description": "Release-reachable detection + response (quoted): in onCreate (no BuildConfig.DEBUG guard): if (Debug.isDebuggerConnected()) { Process.killProcess(Process.myPid()); } at AntiDebug.java:30-34 - runs in release and responds. Owner: com.example.app (proprietary). Runtime hook confirms the call fires.",
  "reference": "jadx/sources/com/example/app/AntiDebug.java:30-34",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0353",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "D debug-detection mechanisms found, R release-reachable with a response, G debug-only/dead. Any effective debug detection present? <yes -> pass / no/only-debug-only -> fail>. <one or two sentences>; runtime hook confirms execution. Note: static analysis may miss obfuscated/native checks.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... e.g. native/inline-syscall anti-debug not statically visible ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `pass`: >=1 genuine debug-detection mechanism quoted as release-reachable (not debug-only-gated) with a response.
- `fail`: the Java AND native searches return nothing, OR the only detection is quoted inside a debug-only guard / is dead code (state it). Lower certainty; add a native/inline-syscall `false_positive_risks` note. A FAIL asserted without the shown searches/gating is INVALID -> `unverified`.
- **Release-reachability matters.** A check only inside `BuildConfig.DEBUG` does not protect release - treat as a FAIL (or unverified if reachability is unclear). **Presence, not full robustness.** **Ownership note** (RASP libraries count; OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification.
- `false_positive_risks` out-of-APK / non-static only.
- `unverified`/`inconclusive` if reachability is unresolved or the verdict lacks quoted evidence.

Self-check before emitting
Confirm: (1) for PASS a release-reachable debug-detection check with a response is quoted; (2) for FAIL the searches are shown empty OR the only checks are quoted as debug-only/dead AND a native caveat recorded; (3) a debug-only check was not counted as effective.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `unverified`.
Before emitting: confirm both searches were performed, the verdict rests on quoted evidence (check + reachability, or empty/debug-only), and `false_positive_risks` notes only non-static factors. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
