MASTG-TEST-0369

maswe_id       MASWE-0089
masvs_v2_id    MASVS-RESILIENCE-3
platform       android
title          Insufficient Obfuscation of Security-Relevant Native Code (static)

What this test looks for
A resilience-profile (R) app that puts SECURITY-RELEVANT logic in native libraries (integrity/root checks, attestation, anti-fraud, key handling) should obfuscate it - native code is not inherently safe. This test FAILS if such native logic can be identified, correlated, and understood with reasonable effort via plaintext strings, descriptive JNI symbol names, or recognizable call structure. Best-effort static assessment over the native binaries. Verdict: `pass` (security-relevant native logic is meaningfully obfuscated), `fail` (security-relevant native logic is readable/locatable with reasonable effort), `n/a` (the app has no native libraries / no security-relevant native logic / anti-static-analysis not in scope - state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): determine whether the app ships native libraries (`native_binaries.json`) AND whether any implement security-relevant logic. If no native libs, or none are security-relevant -> `n/a` (state how concluded).

Obfuscation indicators (native, per MASTG-KNOW-0033)
- Plaintext strings (`.rodata`): do monitored file paths (`/system/xbin/su`), system props, API tokens, integrity values, error messages remain in cleartext - revealing the check's scope by `strings` alone?
- JNI / exported symbols: do exported function names retain descriptive meaning (`Java_com_example_app_Security_isRooted`, `checkIntegrity`) that correlate to security functionality? (Symbol stripping + renaming hides these - cross-ref MASTG-TEST-0288 for debug symbols, but JNI exports must remain to be callable, so their NAMES matter.)
- Call structure / control flow: does the disassembled structure reveal the original logic with recognizable patterns, or is it obfuscated (flattening, opaque predicates)?

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the native library + the exposing indicator (plaintext string, descriptive JNI symbol) - or the obfuscation. No quoted evidence -> `unverified`.
2. **Read from the evidence, not guesses.** Cite `native_binaries.json#records[<lib>]` (strings, exports, jni_entry_points) and, where available, the extracted strings/symbols. Do not assert obfuscation status without the evidence.
3. **No verdict by inference/hedge.** A FAIL requires quoting readable native security logic (a descriptive JNI export and/or plaintext detection strings in a security-relevant lib). "native code is probably analyzable" without a quoted example is NOT evidence -> `inconclusive`.
4. **Unresolved determinacy is `inconclusive`.** Full native obfuscation assessment needs disassembly (MASTG-TECH-0018/0024); where the engine only has strings/symbols, judge on those and note the limit. `false_positive_risks` is out-of-APK only.

Procedure
1. From `native_binaries.json`, identify security-relevant native libs: those whose name, JNI entry points, imports (root/debug/crypto categories), or strings indicate security logic (`isRooted`, `integrity`, `attest`, `/system/xbin/su`, `frida`, crypto). Quote them. If none -> `n/a`.
2. For each security-relevant lib, assess: are exported JNI symbol names descriptive? Do plaintext `.rodata` strings reveal the checked artifacts/scope? Is the structure recognizable? Quote examples (the jni_entry_points + interesting strings from the evidence).
3. Decide: native security logic locatable+understandable with reasonable effort (descriptive symbols and/or plaintext strings) -> FAIL; genuinely obfuscated (stripped+renamed symbols, encrypted strings, obfuscated flow) -> PASS.
4. Owner: app (proprietary); a bundled native RASP/protector (DexProtector, Promon) is noted.
5. Budget ~2-5 reads (the lib record, its symbols/strings). Unresolved (needs disassembly) -> `inconclusive` naming the lib.

Out-of-scope / static limits
Deep native obfuscation assessment needs disassembly (often beyond this engine's evidence) -> `inconclusive` with that note. Java/Kotlin obfuscation is MASTG-TEST-0368. JNI export names must remain to be callable, so their descriptiveness is a legitimate indicator; internal function stripping is separate (MASTG-TEST-0288 covers debug symbols).

Output
List the security-relevant native libraries assessed - one L1 row per lib with its disposition.
- Fail: L1 row plus L2 rows quoting the readable native security logic (descriptive JNI symbol and/or plaintext strings) in the lib, plus owner.
- Pass: L1 row plus an L2 quoting the obfuscation (stripped/renamed symbols + encrypted strings) of the security lib.

```
{
  "id": "nobf-001",
  "description": "Finding (native security logic not obfuscated): libsec.so implements root/integrity checks but exposes a descriptive JNI symbol and plaintext detection strings, so an attacker understands the check from strings/symbols alone.",
  "reference": "native_binaries.json",
  "level": 1
},
{
  "id": "L2-nobf-sym",
  "description": "Descriptive JNI export (quoted): native_binaries.json#records[libsec.so].exports.jni_entry_points includes Java_com_example_app_Security_isRooted (java_class com.example.app.Security) - the symbol name maps directly to the security function.",
  "reference": "native_binaries.json#records[libsec.so]",
  "level": 2
},
{
  "id": "L2-nobf-strings",
  "description": "Plaintext strings (quoted): libsec.so .rodata contains \"/system/xbin/su\", \"magisk\", \"frida\" in cleartext (native strings), revealing the full detection scope. Owner: com.example.app (proprietary). Full assessment may need disassembly.",
  "reference": "native_binaries.json#records[libsec.so]",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0369",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Security-relevant native libs: <libs>. Obfuscation indicators: JNI symbol descriptiveness <yes/no>, plaintext strings <yes/no>, recognizable structure <yes/no>. Can native security logic be reverse-engineered with reasonable effort? <yes -> fail / no -> pass / no such libs -> n/a>. <one or two sentences>. Note: full assessment may require disassembly.",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: security-relevant native logic is quoted as locatable+understandable with reasonable effort (descriptive JNI symbols and/or plaintext `.rodata` strings in a security-relevant lib). A FAIL stated with "likely"/"may" instead of a quoted readable example is INVALID -> `inconclusive`.
- **Native is not inherently obfuscated.** Plaintext strings + descriptive JNI exports make native security logic readable - that is a FAIL.
- **Security-relevant libs only.** Assess libs that implement security logic; ignore generic third-party native libs. If none -> `n/a`.
- **Disassembly limit.** Where the engine only has strings/symbols, judge on those and mark deeper assessment `inconclusive` with a disassembly note. `false_positive_risks` out-of-APK only.
- `pass`: native security logic is meaningfully obfuscated (stripped/renamed internal symbols, encrypted strings, obfuscated flow), quoted.
- `n/a`: no native libraries / no security-relevant native logic (state it).
- `inconclusive` if the assessment can't be grounded in quoted evidence / needs disassembly.

Self-check before emitting
Confirm: (1) the security-relevant native lib(s) are identified and quoted from evidence; (2) the obfuscation indicators (JNI symbols / plaintext strings / structure) are quoted; (3) the verdict reflects reverse-engineerability with reasonable effort; (4) generic non-security native libs were not assessed.
Hedge scan: "likely", "may", "appears", "probably", "might" without a quoted example -> `inconclusive`.
Before emitting: confirm the native evidence was read and the security lib's symbols/strings quoted, and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
