MASTG-TEST-0351

maswe_id       MASWE-0099
masvs_v2_id    MASVS-RESILIENCE-1
platform       android
title          Emulator Detection Techniques (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0351 is a dynamic test (hook/trace emulator-detection APIs at runtime, ideally on an emulator, to confirm the checks fire). This static engine cannot run the app, so this prompt performs the best-effort static equivalent - detect the PRESENCE of emulator-detection logic. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; only running on an emulator and tracing confirms the checks actually execute.

What this test looks for
A resilience-profile (R) app should detect emulated/virtualized environments. PRESENCE test: it FAILS if no emulator-detection logic is found. Verdict: `pass` (>=1 genuine emulator-detection mechanism), `fail` (none found), `n/a` (anti-tampering not in scope - state the justification), or `inconclusive`. (Static analysis may miss obfuscated/native checks - reflect in certainty + `false_positive_risks`.)

SHORT-CIRCUIT (decide first): `grep` for the indicators below. >=1 genuine -> lean PASS; none -> lean FAIL (state the searches). Robustness is OUT OF SCOPE - presence only.

Emulator-detection indicators (any genuine one -> pass)
- Build properties: checks on `Build.FINGERPRINT` (`generic`/`unknown`), `Build.MODEL` (`google_sdk`/`Emulator`/`Android SDK built for x86`), `Build.MANUFACTURER` (`Genymotion`), `Build.HARDWARE` (`goldfish`/`ranchu`/`vbox`), `Build.PRODUCT` (`sdk`/`vbox86p`), `Build.BOARD`, `Build.BRAND` (`generic`).
- System props / files: `ro.kernel.qemu`, `ro.hardware` qemu, `/dev/qemu_pipe`, `/dev/socket/qemud`, `/system/lib/libc_malloc_debug_qemu.so`, `/sys/qemu_trace`, Genymotion files, `/proc/cpuinfo` checks.
- Telephony/sensors: emulator IMEI/phone-number (`15555215554`), absence of sensors, `TelephonyManager.getNetworkOperatorName()` == "Android".
- Known libraries / RASP that bundle emulator detection.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** For PASS, quote >=1 genuine emulator-detection check. For FAIL, show empty searches. No quoted evidence -> `inconclusive`/`unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` (or the native string location), not an index record or line 1.
3. **No verdict by inference/hedge.** PASS needs a quoted check; FAIL needs shown-empty searches. "probably detects emulators" is NOT static proof -> `unverified` (flag for the dynamic test).
4. **Unresolved determinacy is `unverified`/`inconclusive`.** Obfuscated/native checks may evade static detection - say so. A single innocuous `Build.MODEL` read for analytics is NOT emulator detection - require a genuine emulator-artifact comparison. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate: `grep -rEn "ro\.kernel\.qemu|goldfish|ranchu|qemu_pipe|qemud|google_sdk|vbox|Genymotion|Build\.FINGERPRINT|Build\.MODEL|Build\.HARDWARE|Build\.PRODUCT|15555215554|isEmulator" jadx/sources/ jadx/resources/`; scan native libs / `detected_libraries.json` for RASP libs.
2. >=1 genuine emulator-artifact check -> PASS (quote it); none -> FAIL (state the searches; lower certainty; note native/obfuscation caveat). A bare `Build.MODEL` read not compared to emulator artifacts is not a detection - don't count it.
3. Owner: note proprietary vs RASP library.
4. Budget ~2-5 reads. Unresolved -> `unverified`/`inconclusive`.

Out-of-scope / static limits
Robustness/effectiveness is OUT OF SCOPE - presence only. Whether checks fire at runtime is the dynamic test's job - hence the forced `needs_dynamic_testing`. Native/obfuscated checks may be missed.

Output
One L1 row stating whether emulator-detection logic exists, with a quoted example (pass) or the empty-search result (fail).
- Pass: L1 row plus L2(s) quoting genuine emulator-detection checks.
- Fail: L1 row plus an L2 showing the searches returned nothing.

```
{
  "id": "emu-001",
  "description": "Pass: the app checks Build properties and qemu artifacts for emulators.",
  "reference": "jadx/sources/com/example/app/EmuCheck.java",
  "level": 1
},
{
  "id": "L2-emu-check",
  "description": "Emulator detection (quoted): return Build.FINGERPRINT.contains(\"generic\") || Build.HARDWARE.equals(\"goldfish\") || new File(\"/dev/qemu_pipe\").exists(); at EmuCheck.java:30-40. Owner: com.example.app (proprietary). Runtime trace on an emulator confirms execution.",
  "reference": "jadx/sources/com/example/app/EmuCheck.java:30-40",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0351",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "E emulator-detection mechanisms found (Build-props/qemu/Genymotion/RASP). Any emulator detection present? <yes -> pass / no -> fail>. <one or two sentences>; runtime trace confirms execution. Note: static analysis may miss obfuscated/native checks.",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... e.g. native/obfuscated emulator checks not statically visible ... ]
}
```

Rules
- The static `pass`/`fail` is final. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `pass`: >=1 genuine emulator-detection mechanism (an actual emulator-artifact comparison) is quoted (presence test).
- `fail`: the searches (code + native + libraries) return nothing genuine (state them); lower certainty; add a native/obfuscation `false_positive_risks` note. A FAIL asserted without the shown searches is INVALID -> `unverified`.
- **Genuine check required.** A `Build.MODEL`/`FINGERPRINT` read used for analytics (not compared to emulator artifacts) is not emulator detection - do not count it.
- **Presence, not robustness** (out of scope). **Ownership note** (RASP libraries count; OEM-aware; obfuscated -> proprietary).
- `n/a` only with a stated justification.
- `false_positive_risks` out-of-APK / non-static only.
- `unverified`/`inconclusive` if searches incomplete or the verdict lacks quoted/empty-search evidence.

Self-check before emitting
Confirm: (1) for PASS a genuine emulator-artifact comparison is quoted; (2) for FAIL the code+native+library searches are shown empty AND a native/obfuscation caveat recorded; (3) an analytics-only Build read was not counted; (4) robustness not assessed.
Hedge scan: "likely", "may", "appears", "probably", "might" -> `unverified`.
Before emitting: confirm the searches were performed, the verdict rests on quoted/empty-search evidence, and `false_positive_risks` notes only non-static factors. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
