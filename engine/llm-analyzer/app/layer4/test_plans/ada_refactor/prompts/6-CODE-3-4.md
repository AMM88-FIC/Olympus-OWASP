MASTG-TEST-0026
masvs_v1_id	MSTG-PLATFORM-2
masvs_v2_id	MASVS-CODE-4
platform	android
title	Testing Implicit Intents
masvs_v1_levels	L1, L2

Overview
This test evaluates two related concerns around implicit intents (intents without `setComponent`, `setPackage`, or `setClass(...)`):

1. **Outbound implicit intents.** An implicit intent carrying sensitive data can be received by any installed app with a matching `<intent-filter>`, leaking the data. Implicit intents must not carry sensitive data unless delivery is constrained by an explicit destination.
2. **Inbound result handling.** When the app calls `startActivityForResult(...)` with an implicit intent, the receiving app is chosen by the system or the user — potentially a malicious app. Any data the receiving app returns (a `Uri` in `onActivityResult`, extras, etc.) must be treated as untrusted: paths must be canonicalized, content URIs must be validated against an allow-list of trusted authorities, and the data must not be dereferenced (file open, content read, code load) without validation.

Static Analysis

Outbound implicit intents. For every `startActivity(...)`, `startActivityForResult(...)`, `sendBroadcast(...)`, `sendOrderedBroadcast(...)`, and `startService(...)` call, determine whether the wrapped `Intent` is implicit. An intent is implicit when it has an action set but lacks `setComponent(...)`, `setPackage(...)`, `setClass(...)`, or a `Class<?>` argument in the constructor. For each implicit-intent send, inspect the intent extras and data URI for sensitive content.

Inbound result handling. For every `onActivityResult(int requestCode, int resultCode, Intent data)` override, inspect the data flow from `data.getData()`, `data.getExtras()`, and `data.getStringExtra(...)` to its sinks:

- File-open sinks: `File`, `FileInputStream`, `ContentResolver.openInputStream(Uri)`, `ContentResolver.openFileDescriptor(Uri, ...)`. Returned `file://` URIs must be canonicalized and constrained to expected directories; returned `content://` URIs must be validated against an allow-list of trusted authorities.
- Native code sinks: `System.load(String)`, `System.loadLibrary(String)`, `Runtime.exec(...)`. Loading a native library from an attacker-supplied URI is arbitrary code execution.
- WebView sinks: `WebView.loadUrl(...)` with a URI from `onActivityResult` is a navigation into untrusted content.
- Database/intent reuse sinks: passing returned data into SQL composition, `startActivity` of another implicit intent, etc.

Description
Any use of implicit intents shall be appropriate for the app's functionality, and any return data shall be handled securely.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0026.

Verification
The analysis shall demonstrate that (a) implicit intents do not carry sensitive data unless delivery is constrained, and (b) data returned by other apps in `onActivityResult` is validated before reaching file, content, native-library-loading, or other sensitive sinks.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every outbound implicit intent that leaks sensitive data, plus every `onActivityResult` flow that dereferences attacker-controlled return data without validation. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `startActivity` / `startActivityForResult` / `sendBroadcast` / `startService` call dispatching an implicit intent whose extras or data URI carry sensitive content
- Each `onActivityResult` flow from `data.getData()` to a `File` / `FileInputStream` / `ContentResolver.openInputStream` / `openFileDescriptor` sink without canonicalization and base-directory containment
- Each `onActivityResult` flow from `data.getData()` to a `content://` resolution without validating the URI's authority against an allow-list of trusted providers
- Each `onActivityResult` flow from `data.getData()` or extras to `System.load` / `System.loadLibrary` / `Runtime.exec` / `ProcessBuilder`
- Each `onActivityResult` flow from returned data to a downstream sink (WebView load, SQL composition, outbound implicit intent) without validation

Two records describing the same call site at the same line are duplicates and count as one. The same `onActivityResult` reaching two distinct sinks counts as two rows. The rationale should group findings by direction (outbound implicit-intent leakage, inbound result dereference by sink type).
