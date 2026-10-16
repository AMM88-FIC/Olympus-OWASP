MASTG-TEST-0007
masvs_v1_id	MSTG-STORAGE-6
masvs_v2_id	MASVS-PLATFORM-1
platform	android
title	Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app's content providers minimize exposure to other apps and harden their query implementations against injection and path traversal. Two surfaces are in scope: the **manifest declaration** of each `<provider>` (export and permission posture) and the **`ContentProvider` subclass implementation** (query/update/delete/file-access methods).

Static Analysis

Manifest analysis. Locate every `<provider>` element in `AndroidManifest.xml`. For each, determine:

- `android:exported` — explicit `"true"` is exported. Absent, the value defaults to `"true"` when an `<intent-filter>` is declared on the provider, or for `targetSdkVersion < 17`. Otherwise it defaults to `"false"`.
- `android:permission` (or `android:readPermission`/`android:writePermission`) — gating mechanism for cross-app access.
- `android:protectionLevel` of the referenced `<permission>` declaration — `signature` restricts; `normal`/`dangerous` do not.
- `<path-permission>` children — per-path overrides; verify every served path is covered.
- `android:grantUriPermissions` and `<grant-uri-permission>` children — verify grants are bounded.

Code analysis. For every class extending `android.content.ContentProvider`, inspect `query`, `update`, `delete`, `insert`, `openFile`, `openAssetFile`, and `openTypedAssetFile`:

- `selection` must be passed through the parameterized arguments (`selection` + `selectionArgs`); concatenation into raw SQL is a finding.
- `projection` should be filtered against an allow-list of known columns.
- `SQLiteQueryBuilder.setTables(...)` must not receive caller-controlled input.
- File-access methods must canonicalize caller-supplied paths and constrain them to a base directory.
- URI matchers interpreting caller-supplied segments as SQL identifiers must use an allow-list.

Description
The app shall limit content provider exposure and harden queries against injection attacks.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0007.

Verification
Output of the analysis shall demonstrate (a) that exported content providers are appropriately gated by signature-level permissions or explicit per-path permissions, and (b) that `ContentProvider` subclasses use parameterized SQL APIs and bounded file access.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every exported content provider whose exposure is broader than necessary, plus every content-provider implementation whose query handling is unhardened against injection. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `<provider>` exported (explicitly, implicitly via `<intent-filter>` on `targetSdkVersion < 17`, or pre-17 default) with no `android:permission`/`readPermission`/`writePermission` and no `<path-permission>` guard
- Each `<provider>` protected by a permission whose `<permission>` declaration uses `protectionLevel="normal"` or `"dangerous"` for an authority exposing data outside an enterprise-signing trust boundary
- Each `<provider>` with `<path-permission>` entries protecting a subset of paths while leaving sibling served paths unprotected (one row per unprotected sibling)
- Each `<provider>` with `android:grantUriPermissions="true"` lacking bounding `<grant-uri-permission>` children
- Each `<provider>` exporting an authority backing sensitive data regardless of permission guard, when surrounding evidence indicates the data is not intended to leave the app
- Each `query`/`update`/`delete` override concatenating `selection` into raw SQL instead of passing `selection` + `selectionArgs`
- Each `query` override passing caller-supplied `projection` to `SQLiteQueryBuilder.query(...)` without an allow-list filter
- Each `query` override calling `SQLiteQueryBuilder.setTables(...)` with caller-controlled input
- Each `openFile`/`openAssetFile`/`openTypedAssetFile` override resolving a caller-supplied path without canonicalization and base-directory containment
- Each `insert`/`update` override interpreting caller-supplied URI segments or `ContentValues` entries as SQL identifiers without an allow-list

Two records describing the same provider element or code site are duplicates and count as one. A single provider with both an exposure finding and a hardening finding produces two rows. The rationale should group findings by surface (manifest exposure: unprotected exports, weak permission level, path-permission gaps, unbounded URI grants; code hardening: selection concatenation, projection allow-list, dynamic table names, file-traversal, identifier injection).
