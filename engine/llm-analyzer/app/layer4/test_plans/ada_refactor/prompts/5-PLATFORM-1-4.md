MASTG-TEST-0030
masvs_v1_id	MSTG-PLATFORM-4
masvs_v2_id	MASVS-PLATFORM-1
platform	android
title	Testing for Vulnerable Implementation of PendingIntent
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app's `PendingIntent` constructions are safe. Each construction must (1) be immutable (or mutability explicitly justified) and (2) wrap an explicit base `Intent` (component or package set, not just an action).

Static Analysis
Identify every `PendingIntent` factory call:

- `PendingIntent.getActivity(...)`, `getActivities(...)`, `getService(...)`, `getForegroundService(...)`, `getBroadcast(...)`

For each call, evaluate:

- `flags` argument: must include `FLAG_IMMUTABLE`. On `targetSdkVersion >= 31`, omitting both `FLAG_IMMUTABLE` and `FLAG_MUTABLE` causes `IllegalArgumentException` at runtime.
- Base `Intent`: must be **explicit** (constructed with `new Intent(Context, Class)`, or `setClass`/`setComponent`/`setPackage` called). An action-only intent is implicit.
- `FLAG_GRANT_READ_URI_PERMISSION`/`FLAG_GRANT_WRITE_URI_PERMISSION` combined with mutability or implicit base intent amplify the risk.

Description
All Pending Intents shall be immutable or otherwise justified for mutability.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0030.

Verification
Pending Intents shall be immutable, and the app shall explicitly specify the destination of the base intent (package or component).

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every `PendingIntent` construction whose mutability or base-intent specificity does not meet the requirements. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `PendingIntent` factory call whose `flags` argument does not include `FLAG_IMMUTABLE`
- Each `PendingIntent` factory call on `targetSdkVersion >= 31` that specifies neither `FLAG_IMMUTABLE` nor `FLAG_MUTABLE` (also a runtime crash)
- Each `PendingIntent` factory call wrapping a base `Intent` that lacks a `Class<?>` constructor argument or a `setClass`/`setComponent`/`setPackage` call
- Each `PendingIntent` factory call combining `FLAG_MUTABLE` (or absent immutability flag) with an implicit base intent — one row covering the combined chain
- Each `PendingIntent` factory call attaching `FLAG_GRANT_READ_URI_PERMISSION`/`FLAG_GRANT_WRITE_URI_PERMISSION` to a base intent that is also mutable or implicit

Two records describing the same factory call at the same line are duplicates and count as one. A `PendingIntent` constructed in a helper and called from many places is one row at the helper. The rationale should group findings by surface (mutability flag absent, mutability flag absent on `targetSdkVersion >= 31`, implicit base intent, implicit-and-mutable chain, URI-grant amplification).
