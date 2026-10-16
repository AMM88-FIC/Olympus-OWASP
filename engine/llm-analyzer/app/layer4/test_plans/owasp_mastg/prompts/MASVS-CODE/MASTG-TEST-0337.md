MASTG-TEST-0337

maswe_id       MASWE-0088
masvs_v2_id    MASVS-CODE-4
platform       android
title          References to Object Deserialization of Untrusted Data (static)

What this test looks for
Reconstructing objects from serialized data that originates from an UNTRUSTED source (Intent/Bundle extras from other apps, IPC payloads, files, network responses) WITHOUT restricting allowed classes or validating the input can enable unsafe state changes or unintended behavior. This is a static, taint-style evaluation: untrusted serialized source -> deserialization sink without class filtering/validation. Verdict: `pass` (no deserialization of untrusted data without filtering/validation), `fail` (>=1 deserialization consumes untrusted data with no class restriction or validation), `n/a` (the app performs no object deserialization), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for the deserialization APIs below. If NONE appear -> `n/a` (state the search).

Deserialization sinks
`ObjectInputStream.readObject()`/`readUnshared()`, `Intent.getSerializableExtra(...)` / `Bundle.getSerializable(...)` (and the typed `getSerializable(key, Class)` overload - the SAFER form), `Parcelable` from untrusted intents (esp. nested/`getParcelableExtra` of attacker-controlled types), `readParcelable` with an attacker-controlled `ClassLoader`, JSON/XML/YAML deserializers configured with polymorphic type handling (Jackson `enableDefaultTyping`/`@JsonTypeInfo`, Gson with unsafe `RuntimeTypeAdapter`, SnakeYAML `new Yaml()` default constructor, XStream without allowlist), and third-party object mappers reconstructing arbitrary types.

Untrusted sources (taint sources)
`Intent`/`Bundle` extras received by an EXPORTED component (from any app), IPC (`Binder`/`Messenger`/AIDL) payloads from external callers, files in shared/external storage, `content://` data from other apps, and network responses. Data the app itself produced and stored in its private sandbox, deserialized with a fixed expected class, is lower risk (note it).

Safe handling (Compliant)
A class allowlist / type filter (`ObjectInputFilter` / `setObjectInputFilter`, the typed `getSerializable(key, ExpectedType.class)` / `getParcelable(key, T.class)` API-33+ overloads that enforce the type), validating the input before use, or deserializing only to a fixed, simple expected type with subsequent validation.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the untrusted source AND the deserialization sink, and the absence of class filtering/validation. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the source and sink, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) untrusted serialized input and (b) its deserialization with no filter/validation. "might deserialize attacker data" with no quoted source+sink is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the source's trust or the presence of a filter can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Enumerate sinks: `grep -rEn "readObject|readUnshared|getSerializableExtra|getSerializable|getParcelableExtra|readParcelable|enableDefaultTyping|JsonTypeInfo|RuntimeTypeAdapter|new Yaml\(|XStream|ObjectInputStream" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
2. For each sink, trace the data source: untrusted (exported-component intent, IPC, shared file, network) or app-internal. Quote source + sink.
3. For each untrusted-sourced sink, check for class filtering / type enforcement / validation between source and use. Absent -> finding; present (allowlist/typed-overload/validation) -> Compliant. Quote it.
4. Classify owner (proprietary vs library; OEM-aware; obfuscated -> proprietary). A deserialization gadget inside a bundled library fed untrusted app data is reported.
5. Conclude per sink: Finding (untrusted source + unfiltered deserialization, quoted); Compliant (trusted source, or filtered/validated); Unverified (trust/filter unresolved).
6. Budget ~2-4 reads per sink (the deserialize, the source, any filter). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Deserialization inside native code or a no-source SDK -> `unverified` (name the entry point). Whether a reachable gadget chain exists is a deeper analysis; the OWASP control fails on untrusted-data deserialization without filtering/validation. 

Output
List **all** deserialization sites consuming app data - one L1 row per site with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant trusted/filtered sites, but always break out every Finding and unverified site individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the untrusted source and the unfiltered deserialization sink, plus owner.
- Compliant: L1 row plus an L2 showing a trusted source, or a class filter/typed overload/validation.

```
{
  "id": "deser-001",
  "description": "Finding (deserialization of untrusted intent data): An exported activity deserializes a Serializable extra from any caller via readObject with no class filter.",
  "reference": "jadx/sources/com/example/app/ImportActivity.java",
  "level": 1
},
{
  "id": "L2-deser-source",
  "description": "Untrusted source (quoted): byte[] blob = getIntent().getByteArrayExtra(\"payload\"); in ImportActivity (exported=true in manifest) at ImportActivity.java:30-32 - data from any app.",
  "reference": "jadx/sources/com/example/app/ImportActivity.java:30-32",
  "level": 2
},
{
  "id": "L2-deser-sink",
  "description": "Unfiltered deserialization (quoted): ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob)); Object o = ois.readObject(); at lines 34-37 - no setObjectInputFilter / class allowlist; arbitrary types reconstructed. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/ImportActivity.java:34-37",
  "level": 2
},
{
  "id": "deser-ok-001",
  "description": "Compliant: internal cache deserialized with an ObjectInputFilter allowlist.",
  "reference": "jadx/sources/com/example/app/Cache.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0337",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "D deserialization sites, U consuming untrusted data, N findings (untrusted + no filter/validation), C compliant (trusted/filtered), V unverified. Any unfiltered deserialization of untrusted data? <no -> pass/n-a / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 site with (a) an L2 quoting untrusted serialized input AND (b) an L2 quoting its deserialization with no class filter / type enforcement / validation. A finding stated with "likely"/"may" instead of the quoted source+sink is INVALID -> `unverified`.
- **Untrusted source required.** Deserializing the app's OWN sandbox data to a fixed expected type is Compliant/lower-risk. The finding needs an external/untrusted source.
- **Filtering/validation clears it.** An `ObjectInputFilter` allowlist, the typed `getSerializable(key, Class)`/`getParcelable(key, Class)` overloads, or validating before use is Compliant.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the source untrusted? is there a filter?) resolved by reading, unresolved -> `unverified`.
- `pass`: no untrusted-data deserialization without filtering/validation, with L2 coverage.
- `n/a`: no deserialization APIs appear in code (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its source + sink L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the untrusted serialized source is quoted; (2) the deserialization sink is quoted with no class filter / type enforcement / validation; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the deserialization search was performed (n/a state it), every untrusted sink's source and filter state were read and quoted (unread -> `unverified`), no trusted/filtered site was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
