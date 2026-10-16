# MASTG-TEST-0001 — Testing Local Storage for Sensitive Data

**MASVS controls:** MSTG-STORAGE-1, MSTG-STORAGE-2, MASVS-STORAGE-1
**Platform:** Android
**Mode:** static analysis only

## Verdict mode: CATALOG

Produce a **complete inventory** of every place sensitive data is
stored insecurely. Finding one violation and stopping is incomplete
and will be rejected, even if that violation alone justifies FAIL.

One evidence_table row per distinct violation. Two records at the
same `source.path:line_start` are duplicates. Two records at different
call sites — even if they violate the same way — are distinct. Group
findings in the rationale by attack surface (SharedPreferences, SQLite,
external storage, hardcoded secrets, etc.); the evidence_table contains
every row.

## What counts as a violation

Each is one row:

1. A write of sensitive data to storage without encryption.
2. A write of sensitive data to **external** storage (regardless of
   encryption — external storage of sensitive data should be avoided).
3. A hardcoded credential, API key, secret key, or password in code
   or resources that grants the holder access to a backend service
   or to encrypted data. Public client identifiers (Firebase API keys,
   Google Maps keys, OAuth client_ids in public-client flows, mobile
   SDK app IDs from analytics/support/ads vendors) are not findings,
   even when high-entropy and opaque — they identify the app to the
   service, they do not authenticate the app's access. Distinguish
   by use: if the value is used at a service init call alongside a
   separate per-user authentication step (OAuth token, anonymous
   identity, signed request), it's a public identifier, not a secret.
4. A SQLite or Realm database opened without encryption, where the
   schema or surrounding code indicates sensitive content.
5. A SharedPreferences write of sensitive data not using
   EncryptedSharedPreferences or equivalent.
6. Use of `MODE_WORLD_READABLE` or `MODE_WORLD_WRITABLE`.
7. A cryptographic key built by trivial obfuscation (XOR, Base64-halves,
   custom scrambling) rather than via Android KeyStore.

## Pre-row checklist

Before adding any row, confirm all four. If any fails, drop the row.

1. **Maps to a numbered violation condition above.** If you can't name
   which one, the row doesn't belong in this test.
2. **The data is sensitive, by positive evidence.** Signals: variable
   or field names like `password`, `token`, `secret`, `key`,
   `credential`, `pin`, `cookie`, `session`, `auth`; taint flow from
   a credential input, auth response, KDF, or Keystore alias; or
   surrounding code naming the data as PII, payment, health, location.
   Absence of these signals means absence of evidence — drop the row.
3. **It's a storage concern.** Cryptographic primitive choice, network
   endpoints and URLs, logging output, and permission declarations
   belong to other tests and never appear here.
4. **The code is proprietary** — under the app's own package namespace,
   not a vendor SDK package. Third-party SDK findings are out of scope
   and do not appear in the evidence_table or the rationale.

A hardcoded URL is not by itself a storage finding. The only exception
is a URL whose own characters embed a credential (`user:pw@host`,
`?api_key=...`, `?token=...`) — there the URL IS the credential and
rule 3 applies.

## Where the evidence lives

- `storage_usage.json` — every storage call site; most violations.
- `strings.json` — hardcoded credentials, keys, tokens.
- `crypto_usage.json` — key constructions; flag any not routed through
  KeyStore.
- `api_usages.json` — `file_io` domain has File/FileOutputStream/
  FileInputStream/getCacheDir/getExternalCacheDirs.
- `components.json` — content providers.

## Required queries

**You must query `strings.json` before deciding the verdict.** Rule 3
violations live there, not in `storage_usage.json`. The extractor's
category vocabulary is typically `possible_secret`, `suspicious_keyword`,
and `content_uri` — these are extractor labels, not confidence claims.
Real credentials live in `possible_secret` records; you must drill in,
not just survey counts. Consult the vocabulary block in the evidence
acknowledgement for the exact values present.

Useful entry points:

- `count_evidence_records(file='storage_usage.json', group_by='category')`
- `match_evidence_records(file='storage_usage.json', filters={'category': 'external'})`
- `match_evidence_records(file='strings.json', filters={'category': '^possible_secret$'}, limit=50)`
- `match_evidence_records(file='strings.json', filters={'category': '^suspicious_keyword$'}, limit=50)`
- `match_evidence_records(file='strings.json', filters={'value': 'secret|password|api[_-]?key|token|credential'}, case_insensitive=true, limit=50)`
- `match_evidence_records(file='strings.json', filters={'value': '^[A-Za-z0-9+/=]{20,}$'}, limit=20)`

Use `read_file` on a record's source path and a few surrounding lines
when context alone is ambiguous. Prioritize records whose category,
value, or callsite name already suggests sensitivity.

## Verdict criteria

- **PASS** — no records meet any violation condition, OR every storage
  of sensitive data routes through KeyStore-backed encryption and no
  sensitive data is written to external storage.
- **FAIL** — any record meets any violation condition. Severity scales
  with count, data sensitivity, and surface (internal-unencrypted 
  external-unencrypted < hardcoded-secret-in-resources).
- **INCONCLUSIVE** — only if sensitivity cannot be determined for any
  call site AND no other clear violations exist. One clear violation
  anywhere makes the verdict FAIL.

## Do not

- Skip records because the verdict is already established.
- Invent IDs. Cite only IDs returned by evidence tools.
- Skip `strings.json`, or rely on `count_evidence_records` alone for it.
- Treat record absence as compliance without confirming via
  `match_evidence_records` that the file actually contains the expected
  record type.
- Attempt dynamic analysis. Any verdict step depending on runtime data
  is out of scope.