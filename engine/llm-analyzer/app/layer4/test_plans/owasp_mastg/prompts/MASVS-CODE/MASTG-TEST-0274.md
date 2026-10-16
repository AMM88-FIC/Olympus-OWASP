MASTG-TEST-0274

maswe_id       MASWE-0076
masvs_v2_id    MASVS-CODE-3
platform       android
title          Dependencies with Known Vulnerabilities in the App's SBOM - best-effort static SCA over detected libraries

NOTE - SBOM-DEPENDENT TEST, BEST-EFFORT STATIC: MASTG-TEST-0274 as written relies on a Software Bill of Materials (CycloneDX SBOM) generated from the build or provided by the development team, uploaded to an SCA service to list dependencies + CVEs. This engine has no SBOM and no online SCA service. This prompt performs the best-effort static equivalent - reconstruct a partial component inventory from what the engine DETECTED in the APK (libraries + versions) and flag known-vulnerable versions, while clearly marking that the authoritative verdict requires a real SBOM + SCA service. (This is the SBOM-oriented sibling of MASTG-TEST-0272.)

What this test looks for
The app's components should be free of known vulnerabilities. Statically from the APK, the proxy is a reconstructed inventory of detected libraries + versions matched against known-vulnerable versions. Verdict: `pass` (the reconstructed inventory's resolvable-version components are not known-vulnerable, within the limits below), `fail` (>=1 component is a known-vulnerable version), `n/a` (no third-party components detected - state this), or `inconclusive` (versions unresolved / a real SBOM+SCA is needed).

SHORT-CIRCUIT (decide first): consult the detected-component evidence (`detected_libraries.json`, `third_party_sdks.json`). If none -> `n/a` (state it).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the component name + version AND, for a finding, the CVE/advisory + affected-version range. No quoted version+CVE -> `unverified`/`inconclusive`.
2. **Read from the evidence/code, not guesses.** Cite `detected_libraries.json#<record>` / `third_party_sdks.json#<record>` and any embedded version marker. Do not invent versions or CVEs.
3. **No finding by inference/hedge.** A finding requires (a) a detected component at a specific version and (b) a known vulnerability affecting that version. "commonly has CVEs" without a resolved version is NOT a finding -> `inconclusive`.
4. **Version unresolved -> inconclusive.** Reconstructing an SBOM from a built APK is lossy; unresolved versions -> `inconclusive` (recommend a real SBOM + SCA). `false_positive_risks` is out-of-APK only.

How this differs from MASTG-TEST-0272
0272 frames the source as the Gradle project; this test frames it as an SBOM. Both, absent the real artifact, fall back to the same APK-detected inventory here. Run whichever the plan selects; if both run, they should reconcile (same detected set). The PRIMARY recommendation of this test is: obtain/generate a CycloneDX SBOM and run it through an SCA service for the authoritative answer.

Procedure
1. Build a partial inventory: read `detected_libraries.json` + `third_party_sdks.json`; collect component names, versions, ecosystems (Maven coordinates where resolvable), and confidence. Add version markers from resources/code (`META-INF/*.version`, `BuildConfig`, embedded constants). Quote them.
2. For each component with a RESOLVABLE version, assess whether it is a known-vulnerable version (named CVE/advisory + affected range). Quote it. Unresolved version -> `inconclusive` row.
3. Be conservative: assert a finding only on a pinned version with an identifiable, version-matching vulnerability; otherwise `inconclusive` and recommend a real SBOM+SCA.
4. Owner: third-party; note the component and detection source.
5. Conclude per component: Finding (pinned vulnerable version + CVE); Compliant (pinned non-vulnerable version); Inconclusive (version unresolved / no reliable data).
6. Budget ~2-4 reads per candidate. Unresolved -> `inconclusive` naming the component.

Out-of-scope / static limits
A built APK is not an SBOM: shaded/renamed packages, stripped version metadata, transitive deps, and native components frequently defeat static inventory. This prompt surfaces high-confidence matches and otherwise recommends generating a CycloneDX SBOM + SCA scan. It cannot guarantee completeness.

Output
List **all** detected components with a resolvable version - one L1 row per component with its disposition - plus an Observation row stating the SBOM/SCA limitation and listing unresolved components. Always break out every Finding individually. Never sample findings.
- Observation: L1 row noting that the authoritative verdict needs a real SBOM + SCA service; list unresolved-version components (inconclusive).
- Finding: L1 row plus L2 quoting the component+version and the CVE + affected range, plus detection source.
- Compliant: L1 row plus L2 quoting the component+version shown not known-vulnerable.

```
{
  "id": "sbom-001",
  "description": "Finding (known-vulnerable component): a bundled Jackson-databind version is affected by published deserialization CVEs.",
  "reference": "detected_libraries.json",
  "level": 1
},
{
  "id": "L2-sbom-ver",
  "description": "Component + version (quoted): com.fasterxml.jackson.core:jackson-databind 2.9.8 (detected_libraries.json#lib-jackson, corroborated by META-INF/.../pom.properties version=2.9.8).",
  "reference": "detected_libraries.json#lib-jackson",
  "level": 2
},
{
  "id": "L2-sbom-cve",
  "description": "Known vulnerability (quoted): jackson-databind 2.9.x before 2.9.10.x has multiple polymorphic-deserialization RCE CVEs (e.g. CVE-2019-12384 and related); 2.9.8 is in the affected range. Third-party.",
  "reference": "detected_libraries.json#lib-jackson",
  "level": 2
},
{
  "id": "sbom-incon",
  "description": "Inconclusive: a real CycloneDX SBOM + SCA service is required for an authoritative inventory; 9 detected components have no resolvable version in the APK.",
  "reference": "detected_libraries.json",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0274",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "C detected components, V with resolvable versions, N findings (known-vulnerable + CVE), K compliant, I inconclusive (version unresolved). Authoritative verdict needs a CycloneDX SBOM + SCA service. Any known-vulnerable component confirmed? <yes -> fail / unresolved remain -> inconclusive / all resolved safe -> pass / no components -> n/a>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final (within the SBOM/SCA limitation). `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 component with (a) an L2 quoting a pinned version AND (b) an L2 quoting a known vulnerability (CVE/advisory) affecting that version range. A finding asserted without a pinned version + identifiable CVE is INVALID -> `inconclusive`.
- **Pinned version required for a finding.** Name-only flags are not findings. Unresolved version -> `inconclusive`.
- **SBOM/SCA limitation stated.** The rationale must recommend generating a CycloneDX SBOM and running an SCA service for the authoritative result.
- **No sampling / false_positive hygiene** as in the suite: every Finding broken out individually; `false_positive_risks` out-of-APK only (backported fixes, shaded code masking the real version) - resolvable facts read, unresolved -> `inconclusive`.
- `pass`: all components with resolvable versions are not known-vulnerable (unresolved set empty or noted), with L2 coverage.
- `n/a`: no third-party components detected (state it).
- `inconclusive` if versions are unresolved / no reliable CVE data / verdict can't rest on quoted version+CVE.

Self-check before emitting (per finding)
For every Finding confirm: (1) the component and pinned version are quoted from evidence; (2) a specific CVE/advisory + affected range covering that version is quoted; (3) the SBOM/SCA limitation is stated.
Hedge scan: "likely", "may", "appears", "probably", "might", "commonly vulnerable" -> downgrade to `inconclusive`.
Before any `pass`/`fail`/`n/a`/`inconclusive`: confirm the detected-component evidence was read, versions resolved where possible, every finding rests on a pinned version + identifiable CVE, and no `false_positive_risks` entry describes a resolvable in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
