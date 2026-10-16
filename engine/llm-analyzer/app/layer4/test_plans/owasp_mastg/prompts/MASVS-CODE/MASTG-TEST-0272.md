MASTG-TEST-0272

maswe_id       MASWE-0076
masvs_v2_id    MASVS-CODE-3
platform       android
title          Dependencies with Known Vulnerabilities (Gradle project) - best-effort static SCA over detected libraries

NOTE - SOURCE-DEPENDENT TEST, BEST-EFFORT STATIC: MASTG-TEST-0272 as written scans the Gradle build environment of the Android Studio PROJECT (build.gradle dependency tree) with an SCA tool. A built APK does NOT contain Gradle build files, so authoritative dependency+CVE resolution is not possible from the APK alone. This prompt performs the best-effort static equivalent - enumerate the third-party libraries the engine DETECTED in the APK (with versions where resolvable) and flag any that are KNOWN-VULNERABLE versions, while clearly marking that a definitive verdict requires running an SCA tool (e.g. Gradle dependency scanning) against the project or its SBOM (see MASTG-TEST-0274).

What this test looks for
The app should not ship third-party components with known vulnerabilities. Statically from the APK, the proxy is the set of detected libraries + versions matched against known-vulnerable versions. Verdict: `pass` (detected libraries with resolvable versions are not known-vulnerable, within the limits below), `fail` (>=1 detected library is a known-vulnerable version), `n/a` (no third-party libraries detected - state this), or `inconclusive` (versions unresolved / authoritative SCA needed).

SHORT-CIRCUIT (decide first): consult the detected-library evidence (`detected_libraries.json`, `third_party_sdks.json`). If none detected -> `n/a` (state it).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the detected library name + version (from the evidence record) AND, for a finding, the specific known vulnerability/CVE and the affected-version range. No quoted version+CVE -> `unverified`/`inconclusive`.
2. **Read from the evidence/code, not guesses.** Cite `detected_libraries.json#<record>` / `third_party_sdks.json#<record>` (and any embedded version string in code/resources). Do not invent versions.
3. **No finding by inference/hedge.** A finding requires (a) a detected library at a specific version and (b) a known vulnerability affecting that version. "this library is often vulnerable" without a resolved version+CVE is NOT a finding -> `inconclusive`.
4. **Version unresolved -> inconclusive, not a guess.** Many libraries in an APK have no reliable version marker; if the version can't be pinned, the row is `inconclusive` (recommend SCA/SBOM). `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate detected libraries: read `detected_libraries.json` and `third_party_sdks.json` (LibScout/heuristics output) - names, versions, and confidence. Also `grep` resources/code for version markers (`*.version`, `BuildConfig`, `META-INF/*.version`, embedded `VERSION` constants). Quote what you find.
2. For each library with a RESOLVABLE version, assess whether that version is known-vulnerable (named CVE/advisory affecting that version range). Quote the library+version and the CVE/range. Unresolved version -> `inconclusive` row.
3. Be conservative: only assert a finding when the version is pinned AND a known vulnerability for that version is identifiable with reasonable confidence; otherwise `inconclusive` and recommend an SCA tool / SBOM (MASTG-TEST-0274).
4. Owner: third-party by definition; note the library and where it was detected.
5. Conclude per library: Finding (pinned vulnerable version + CVE, quoted); Compliant (pinned non-vulnerable version); Inconclusive (version unresolved / no reliable CVE data).
6. Budget ~2-4 reads per candidate (the evidence record, version markers). Unresolved -> `inconclusive` naming the library.

Out-of-scope / static limits
Authoritative dependency resolution requires the Gradle build (not in the APK); transitive deps and exact versions are frequently unrecoverable statically. This prompt cannot replace an SCA scan - it surfaces high-confidence matches and otherwise recommends MASTG-TEST-0274 (SBOM) / a Gradle SCA run. Native library CVEs may also need binary version fingerprinting.

Output
List **all** detected third-party libraries with a resolvable version - one L1 row per library with its disposition - plus an Observation row stating the static-SCA limitation. Always break out every Finding individually. Never sample findings.
- Observation: L1 row noting that a definitive verdict needs an SCA tool/SBOM; list libraries whose versions could not be resolved (inconclusive).
- Finding: L1 row plus L2 quoting the library+version and the known vulnerability (CVE + affected range), plus detection source.
- Compliant: L1 row plus L2 quoting the library+version shown not known-vulnerable.

```
{
  "id": "dep-001",
  "description": "Finding (known-vulnerable dependency): the app bundles an OkHttp version affected by a published advisory.",
  "reference": "detected_libraries.json",
  "level": 1
},
{
  "id": "L2-dep-ver",
  "description": "Detected library + version (quoted): okhttp 3.12.0 (detected_libraries.json#lib-okhttp, confidence 0.9; corroborated by META-INF/okhttp.version).",
  "reference": "detected_libraries.json#lib-okhttp",
  "level": 2
},
{
  "id": "L2-dep-cve",
  "description": "Known vulnerability (quoted): OkHttp < 4.9.2 is affected by CVE-2021-0341 (improper hostname verification in certain configurations); 3.12.0 falls in the affected range. Third-party (square.okhttp3).",
  "reference": "detected_libraries.json#lib-okhttp",
  "level": 2
},
{
  "id": "dep-incon",
  "description": "Inconclusive: 6 detected libraries have no resolvable version marker in the APK - an SCA tool / SBOM (MASTG-TEST-0274) is required to verify them.",
  "reference": "detected_libraries.json",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0272",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "L detected libraries, V with resolvable versions, N findings (known-vulnerable version + CVE), C compliant (version not vulnerable), I inconclusive (version unresolved). Authoritative check needs an SCA tool/SBOM. Any known-vulnerable dependency confirmed? <yes -> fail / no but unresolved remain -> inconclusive / none & all resolved safe -> pass / no libs -> n/a>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final (within the SCA limitation). `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 detected library with (a) an L2 quoting a pinned version AND (b) an L2 quoting a known vulnerability (CVE/advisory) affecting that version range. A finding asserted without a pinned version + identifiable CVE is INVALID -> `inconclusive`.
- **Pinned version required for a finding.** Do not flag a library by name alone; the version must be resolvable and the vulnerability must affect that version. Unresolved version -> `inconclusive`, recommend SCA/SBOM.
- **SCA limitation stated.** The rationale must note that the definitive verdict needs a Gradle SCA scan / SBOM (MASTG-TEST-0274), since the APK lacks build metadata.
- **No sampling / false_positive hygiene** as in the suite: every Finding broken out individually; `false_positive_risks` out-of-APK only (a backported fix the version string doesn't reflect, vendored/shaded code) - resolvable facts read from evidence, unresolved -> `inconclusive`.
- `pass`: all detected libraries with resolvable versions are not known-vulnerable (and the unresolved set is empty or noted), with L2 coverage.
- `n/a`: no third-party libraries detected (state it).
- `inconclusive` if versions are unresolved / no reliable CVE data / the verdict can't rest on quoted version+CVE.

Self-check before emitting (per finding)
For every Finding confirm: (1) the library and its pinned version are quoted from evidence; (2) a specific CVE/advisory and the affected-version range are quoted, covering that version; (3) the SCA limitation is stated in the rationale.
Hedge scan: "likely", "may", "appears", "probably", "might", "often vulnerable" -> downgrade to `inconclusive`.
Before any `pass`/`fail`/`n/a`/`inconclusive`: confirm the detected-library evidence was read, versions resolved where possible, every finding rests on a pinned version + identifiable CVE, and no `false_positive_risks` entry describes a resolvable in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
