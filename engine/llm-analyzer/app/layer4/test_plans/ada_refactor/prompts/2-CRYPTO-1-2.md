# MASTG-TEST-0001 — Testing Local Storage for Sensitive Data

**MASVS controls:** MSTG-STORAGE-1, MSTG-STORAGE-2, MASVS-STORAGE-1
**Platform:** Android
**Mode:** static analysis only (this engine cannot perform dynamic analysis)

## Verdict mode: CATALOG

Produce a complete inventory of every insecure-storage finding. Emit
one `evidence_table` row per distinct violation. Two records at the
same `source.path:line_start` are one row; two records at different
call sites are two rows even if they violate the same way. Group
findings in the rationale by attack surface (SharedPreferences,
SQLite, external storage, hardcoded secrets, etc.); the evidence_table
still contains every row.

A verdict that finds one violation and stops is incomplete and will
be rejected, even if that one violation alone justifies FAIL.

## What counts as a violation

Each is one row in `evidence_table`:

1. A call site that writes sensitive data to storage without encryption.
2. A call site that writes sensitive data to **external** storage,
   regardless of encryption.
3. A hardcoded credential, API key, secret key, or password in code or
   resources.
4. A SQLite or Realm database opened without encryption whose schema or
   surrounding code indicates sensitive content.
5. A SharedPreferences write of sensitive data without
   EncryptedSharedPreferences or equivalent.
6. Use of `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE` on any file
   containing app data.
7. A cryptographic key constructed by trivial obfuscation
   (XOR-of-Base64-halves, bit-flipping, custom scrambling) rather than
   via Android KeyStore.

## Relevant evidence

- **`storage_usage.json`** — every storage call site.
- **`strings.json`** — hardcoded credentials, keys, tokens.
- **`crypto_usage.json`** — key construction; flag any not routed
  through KeyStore.
- **`api_usages.json`** — `domain=file_io` for file I/O call sites.
- **`components.json`** — content providers and exported components.

The evidence acknowledgement shows the actual category vocabulary for
each file. Use those exact values in your filters — the names may
differ from what you'd guess (e.g. `shared_preferences`, not
`sharedprefs`).

## Required queries

Strings.json is mandatory for this test: rule 3 violations (hardcoded
secrets) live there, not in storage_usage. Surveying with
`count_evidence_records` is not enough — you must drill in with
`match_evidence_records`. Category names like `possible_secret` and
`suspicious_keyword` are extractor labels for buckets that often contain
real secrets; judge by the `value` field, not the category name.

Useful starting points:

- `count_evidence_records('storage_usage.json', group_by='category')`
- `match_evidence_records('storage_usage.json', {'category': 'external'})`
- `match_evidence_records('storage_usage.json', {'category': '^shared_preferences$'})`
- `match_evidence_records('strings.json', {'category': '^possible_secret$'}, limit=50)`
- `match_evidence_records('strings.json', {'category': '^suspicious_keyword$'}, limit=50)`
- `match_evidence_records('strings.json', {'value': 'secret|password|api[_-]?key|token|credential'}, case_insensitive=true, limit=50)`
- `match_evidence_records('api_usages.json', {'domain': '^file_io$'})`

## Verifying records

Use `read_file` at an L1 record's `source.path` and line range to
confirm context when the record alone is ambiguous. Prioritize records
whose category, value, or callsite name already strongly suggest
sensitivity; do not read source for every record.

## Verdict criteria

- **PASS** — no records meet any violation condition, or every sensitive
  storage routes through KeyStore-backed encryption and no sensitive
  data goes to external storage.
- **FAIL** — any record meets any violation condition. Severity scales
  with count, sensitivity of the data, and whether storage is
  internal-unencrypted (lower), external-unencrypted (higher), or
  hardcoded-secret (highest).
- **INCONCLUSIVE** — only if you cannot determine sensitivity for any
  call site AND no other clearly-sensitive violations exist. One clear
  violation makes the verdict FAIL regardless of uncertainty elsewhere.

## What NOT to do

- Do not skip records because "the violation is already established."
- Do not invent IDs. Cite only IDs returned by the evidence tools.
- Do not treat absence as compliance without confirming via
  `match_evidence_records` that the file actually lacks records of the
  expected type.
- Do not attempt dynamic analysis (running the app, checking
  `/data/data/`, Firebase URLs). This engine is static-only.