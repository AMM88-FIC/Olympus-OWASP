MASTG-TEST-0339

maswe_id       MASWE-0086
masvs_v2_id    MASVS-CODE-4
platform       android
title          SQL Injection in Content Providers (static)

What this test looks for
A `ContentProvider` that builds SQL queries from UNTRUSTED input (URI path segments, query parameters, selection/selectionArgs from external callers) by string concatenation - rather than parameterized queries - is vulnerable to SQL injection, letting a caller read/modify data beyond the intended scope. This is a static, taint-style evaluation: untrusted URI/selection input -> SQL built unsafely. Verdict: `pass` (provider SQL uses parameterization / safe APIs, no untrusted concatenation), `fail` (>=1 provider builds SQL by concatenating untrusted input, or uses `appendWhere`/raw SQL unsafely), `n/a` (the app declares no content providers that build SQL), or `inconclusive`.

SHORT-CIRCUIT (decide first): identify content providers (manifest `<provider>` + `ContentProvider` subclasses). If none build SQL -> `n/a` (state it).

Untrusted input (taint sources, inside the provider)
`uri.getPathSegments()`, `uri.getLastPathSegment()`, `uri.getQueryParameter(...)`, the `selection`/`selectionArgs`/`sortOrder` parameters of `query`/`update`/`delete` (caller-controlled), and any value derived from the incoming `Uri`.

Unsafe SQL sinks (Finding)
- String concatenation/`String.format` of untrusted input into a SQL string passed to `db.rawQuery(sql, ...)` / `db.execSQL(sql)` / `SQLiteQueryBuilder.setTables(...)` / a `selection` built by concatenation.
- `SQLiteQueryBuilder.appendWhere(<untrusted concatenation>)` (the classic provider pitfall) or `appendWhereEscapeString` misuse.
- Building `ORDER BY`/`LIMIT`/column lists from untrusted input (often not parameterizable - must be allowlisted).

Safe handling (Compliant)
Parameterized queries: `selection` with `?` placeholders + `selectionArgs`, `db.query(table, cols, "col=?", new String[]{value}, ...)`, `SQLiteQueryBuilder` with `appendWhereStandalone`/bound args, or strict allowlisting/validation of any identifier (column/table/order) that cannot be parameterized.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the untrusted input source AND the SQL sink showing concatenation (Finding) or parameterization (Compliant). No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the provider method, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) untrusted URI/selection input and (b) its concatenation into SQL. "probably injectable" with no quoted sink is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the input's source or the query construction can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Procedure
1. Identify providers: manifest `<provider>` + `ContentProvider` subclasses (`query`/`insert`/`update`/`delete`). `grep -rEn "extends ContentProvider|SQLiteQueryBuilder|appendWhere|rawQuery|execSQL|getPathSegments|getQueryParameter|getLastPathSegment" jadx/sources/`. If none build SQL -> short-circuit `n/a` (state the search).
2. For each provider method, trace untrusted input (URI segments/params, selection) into the SQL construction. Quote source + sink.
3. Classify: concatenated/`appendWhere`-unsafe -> finding; parameterized (`?` + selectionArgs) or allowlisted identifiers -> Compliant. Quote it.
4. Note whether the provider is EXPORTED (raises severity - any app can reach it; cross-ref MASTG-TEST-0355), but an internal provider built unsafely is still a code-quality finding.
5. Classify owner (proprietary vs library; OEM-aware; obfuscated -> proprietary).
6. Conclude per method: Finding (untrusted input concatenated into SQL, quoted); Compliant (parameterized/allowlisted); Unverified (input/construction unresolved).
7. Budget ~2-4 reads per provider method. Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
SQL built inside native code or a no-source SDK -> `unverified` (name the entry point). Provider EXPORT/permission posture is MASTG-TEST-0355; this test is the SQL INJECTION construction. Non-provider SQL (app's own internal DB with no untrusted input) is lower priority - note but focus on provider-reachable injection.

Output
List **all** provider SQL-building methods consuming caller input - one L1 row per method with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant parameterized methods, but always break out every Finding and unverified method individually. Never sample findings.
- Finding: L1 row plus L2 rows quoting the untrusted input source and the unsafe SQL construction (concatenation/appendWhere), plus export status and owner.
- Compliant: L1 row plus an L2 quoting the parameterized query / allowlisted identifier.

```
{
  "id": "sqli-001",
  "description": "Finding (SQL injection in a content provider): The provider concatenates a URI path segment into the WHERE clause via appendWhere, so a crafted content:// URI injects SQL.",
  "reference": "jadx/sources/com/example/app/NotesProvider.java",
  "level": 1
},
{
  "id": "L2-sqli-source",
  "description": "Untrusted input (quoted): String id = uri.getPathSegments().get(1); in NotesProvider.query at NotesProvider.java:40-42 - caller-controlled URI segment.",
  "reference": "jadx/sources/com/example/app/NotesProvider.java:40-42",
  "level": 2
},
{
  "id": "L2-sqli-sink",
  "description": "Unsafe SQL (quoted): qb.appendWhere(\"_id=\" + id); ... qb.query(db, projection, null, null, ...) at lines 44-50 - id concatenated into WHERE without parameterization; provider is exported (manifest:58). Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/NotesProvider.java:44-50",
  "level": 2
},
{
  "id": "sqli-ok-001",
  "description": "Compliant: provider uses a parameterized selection with bound args.",
  "reference": "jadx/sources/com/example/app/SafeProvider.java",
  "level": 1
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0339",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "P provider SQL methods consuming caller input, S safe (parameterized/allowlisted), N findings (untrusted concatenation / unsafe appendWhere), U unverified. Any provider SQL injectable from untrusted input? <no -> pass/n-a / yes -> fail>. <one or two sentences; note exported providers>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 provider method with (a) an L2 quoting untrusted URI/selection input AND (b) an L2 quoting its concatenation into SQL (rawQuery/execSQL/appendWhere/selection). A finding stated with "likely"/"may" instead of the quoted source+sink is INVALID -> `unverified`.
- **Parameterization clears it.** `?` placeholders + `selectionArgs`, or strict allowlisting of non-parameterizable identifiers, is Compliant.
- **Exported raises severity.** Note whether the provider is exported (any app reaches it; cross-ref MASTG-TEST-0355); an internal-only unsafe provider is still a finding (lower severity).
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (untrusted input? concatenated?) resolved by reading, unresolved -> `unverified`.
- `pass`: provider SQL is parameterized/allowlisted with no untrusted concatenation, with L2 coverage.
- `n/a`: no content providers build SQL (state it).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its input + unsafe-SQL L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the untrusted URI/selection input is quoted; (2) its concatenation into SQL (or unsafe appendWhere) is quoted; (3) export status noted; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm providers were identified, every provider SQL method's input and construction were read and quoted (unread -> `unverified`), no parameterized method was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
