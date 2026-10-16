MASTG-TEST-0368

maswe_id       MASWE-0089
masvs_v2_id    MASVS-RESILIENCE-3
platform       android
title          Insufficient Obfuscation of Security-Relevant Java/Kotlin Code (static)

What this test looks for
A resilience-profile (R) app should obfuscate SECURITY-RELEVANT Java/Kotlin logic (integrity/root/debugger checks, attestation, anti-fraud, license/entitlement, key derivation) so it is not trivially reverse-engineered from decompiled DEX. This test FAILS if such logic can be identified, correlated, and understood with reasonable effort. This is a best-effort static assessment using obfuscation indicators. Verdict: `pass` (security-relevant logic is meaningfully obfuscated), `fail` (security-relevant logic is readable/locatable with reasonable effort - meaningful names and/or plaintext strings expose it), `n/a` (the app has no security-relevant Java/Kotlin logic to protect, or anti-static-analysis is not in scope - state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): identify whether the app HAS security-relevant Java/Kotlin logic (integrity/root/debug/attestation/anti-fraud/license/key handling). If none -> `n/a` (state how concluded). Then assess obfuscation of that logic.

Obfuscation indicators (per MASTG-KNOW-0033)
- Identifier renaming: are class/method/field names meaningless (`a`, `b`, `c`, `o0OO`) - R8/ProGuard renaming applied - or descriptive (`RootChecker.isRooted`, `LicenseValidator.verify`)?
- String literals: do plaintext strings (endpoint URLs, error messages, detection-artifact names like `/system/xbin/su`, `frida`, license keys) remain, letting an attacker grep to the security logic? String encryption/obfuscation hides these.
- Control flow: is the original logic easy to follow, or is there control-flow obfuscation / opaque predicates?
The FAIL condition: even with some renaming, the security-relevant logic is still locatable and understandable (e.g. via remaining plaintext strings) with reasonable effort.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the security-relevant logic and the indicator(s) that make it readable (descriptive names / plaintext strings) - or that show it is obfuscated. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>`; if decompilation is unreliable, note it and reason from smali. The `obfuscation.json` evidence may orient you (renaming ratio, plaintext-string stats); the verdict quotes actual code.
3. **No verdict by inference/hedge.** A FAIL requires quoting readable security-relevant logic (e.g. a `RootChecker` class with plaintext su-path strings). "probably not obfuscated" without a quoted example is NOT evidence -> `inconclusive`.
4. **Unresolved determinacy is `inconclusive`.** Obfuscation assessment is judgment-based ("reasonable effort") - where the app is clearly mixed, explain. `false_positive_risks` is out-of-APK only.

Procedure
1. Identify security-relevant Java/Kotlin logic: `grep -rEn "isRooted|rootbeer|isDebuggerConnected|SafetyNet|PlayIntegrity|attest|licen|entitle|fraud|verifySignature|integrity" jadx/sources/` and from `obfuscation.json`. Quote what you find. If none -> `n/a`.
2. For that logic, assess the obfuscation indicators: are names descriptive? Do plaintext strings (detection artifacts, endpoints, keys) reveal it? Is control flow plain? Quote examples.
3. Decide: security-relevant logic locatable+understandable with reasonable effort -> FAIL (quote the readable logic + the exposing indicator). Genuinely obfuscated (renamed + string-encrypted + non-trivial flow) such that it is not readily reverse-engineered -> PASS.
4. Owner: app (proprietary); a bundled RASP/obfuscation library is noted.
5. Budget ~3-6 reads (the security logic, names, strings, flow). Unresolved -> `inconclusive`.

Out-of-scope / static limits
This is a judgment call ("reasonable effort"); obfuscation strength is a spectrum. Identifier renaming ALONE (R8 default) is generally insufficient if plaintext strings still reveal the logic - that is the canonical FAIL. Native obfuscation is MASTG-TEST-0369. Decompilation may be incomplete -> note and use smali.

Output
List the security-relevant Java/Kotlin logic assessed - one L1 row per area with its disposition.
- Fail: L1 row plus L2 rows quoting the readable security-relevant logic and the exposing indicator (descriptive names / plaintext strings), plus owner.
- Pass: L1 row plus an L2 quoting the obfuscation (renamed identifiers + string encryption + non-trivial flow) of the security logic.

```
{
  "id": "obf-001",
  "description": "Finding (security logic not obfuscated): The app's root/integrity checks are in clearly-named classes with plaintext detection strings, so an attacker can locate and understand them quickly despite R8 renaming elsewhere.",
  "reference": "jadx/sources/com/example/app/security/RootChecker.java",
  "level": 1
},
{
  "id": "L2-obf-logic",
  "description": "Readable security logic (quoted): class RootChecker { boolean isRooted() { for (String p : new String[]{\"/system/xbin/su\", \"/sbin/su\"}) ... } } at RootChecker.java:14-40 - descriptive class/method names AND plaintext su-path strings reveal the entire check.",
  "reference": "jadx/sources/com/example/app/security/RootChecker.java:14-40",
  "level": 2
},
{
  "id": "L2-obf-strings",
  "description": "Exposing indicator (quoted): plaintext strings \"/system/xbin/su\", \"frida\", \"Magisk\" remain in the class; obfuscation.json reports 0% string encryption for this package. Owner: com.example.app (proprietary).",
  "reference": "obfuscation.json",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0368",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Security-relevant Java/Kotlin logic: <areas>. Obfuscation indicators: identifier-renaming <yes/no>, string encryption <yes/no>, control-flow obfuscation <yes/no>. Can security logic be reverse-engineered with reasonable effort? <yes -> fail / no -> pass / no such logic -> n/a>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: security-relevant Java/Kotlin logic is quoted as locatable+understandable with reasonable effort (descriptive names and/or plaintext strings exposing it). A FAIL stated with "likely"/"may" instead of a quoted readable example is INVALID -> `inconclusive`.
- **Renaming alone is usually insufficient.** If plaintext strings still lead an attacker to the security logic, that is a FAIL even with R8 identifier renaming.
- **Security-relevant logic required.** Obfuscation of non-security code is irrelevant; assess the security-relevant logic. If none exists -> `n/a`.
- **Judgment, stated.** Explain the "reasonable effort" reasoning; do not over-claim. `false_positive_risks` out-of-APK only.
- `pass`: security logic is meaningfully obfuscated (renamed + string-encrypted + non-trivial flow) so it is not readily reverse-engineered, quoted.
- `n/a`: no security-relevant Java/Kotlin logic / anti-static-analysis not in scope (state it).
- `inconclusive` if the assessment can't be grounded in quoted code, or decompilation is too unreliable.

Self-check before emitting
Confirm: (1) the security-relevant logic is identified and quoted; (2) the obfuscation indicators (names/strings/flow) are quoted; (3) the verdict reflects whether the logic is reverse-engineerable with reasonable effort; (4) renaming-only was not treated as sufficient when plaintext strings expose the logic.
Hedge scan: "likely", "may", "appears", "probably", "might" without a quoted example -> `inconclusive`.
Before emitting: confirm the security logic and obfuscation indicators were read and quoted, and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
