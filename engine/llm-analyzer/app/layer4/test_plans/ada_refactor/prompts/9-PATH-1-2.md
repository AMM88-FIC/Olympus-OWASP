MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-4
masvs_v2_id    MASVS-PLATFORM-1
maswe_id       MASWE-0059
platform       android
title          Sensitive operations or data exposure via exported IPC entry points without caller verification

What this test looks for
A malicious app on the same device invokes an exported component of the app under test and triggers a sensitive operation — reading account or credential data, querying permission-protected content (contacts, call log, SMS, location, telephony identifiers), modifying user state, or returning private data to the caller — without the handler verifying who is calling. The vulnerability is the *absence* of a check, not the presence of a flow: the handler reaches a sensitive sink along a path that contains no caller-authentication call (or contains one whose result is discarded). The damage scales with the permissions the app holds.

Source code is the ground truth. Evidence files are indices into the code, useful for finding candidates and constraining search but not authoritative. A finding or a clean must be confirmed by reading the source — extractors miss things (interface dispatch, obfuscated wrappers, activity-aliases), and the call graph can show what *was* called but only the source shows what *was not* checked.

A note on activities. The Android platform gives activities no reliable programmatic caller-identity API: `Activity.getCallingPackage()` returns `null` unless the caller used `startActivityForResult`. The legitimate defense pattern for sensitive activities is therefore (a) the sensitive action runs only after a user tap in the UI, (b) the activity is gated by a signature-level permission, or (c) the activity rejects intents whose declared source is unexpected. An activity that performs a sensitive sink call directly in `onCreate` or `onNewIntent` with no UI gating and no signature permission is the canonical bug shape this test exists to catch.

Procedure

1. Enumerate exported proprietary components from `components.json`:
   ```
   match_evidence_records(
     file="components.json",
     filters={
       "exported.effective": "true",
       "name": "^(?!(androidx|com\\.google|com\\.facebook|com\\.bumptech|kotlin|kotlinx|okhttp3|okio|retrofit2|com\\.squareup|io\\.reactivex|com\\.amazon|com\\.adjust|com\\.appsflyer|com\\.crashlytics|io\\.branch|io\\.intercom|zendesk|com\\.zendesk|com\\.mixpanel|com\\.segment|com\\.onesignal|com\\.my\\.target|net\\.openid\\.appauth)\\.).+"
     },
     limit=100
   )
   ```

2. For each component, derive the handler method(s):
   - Activities and activity-aliases: `onCreate`, `onNewIntent`, `onActivityResult`. Aliases delegate to their `targetActivity`; analyze the target's handlers.
   - Services: `onStartCommand`, `onBind`, `onHandleIntent`. For bound services, identify the AIDL stub class and include its dispatched methods.
   - Receivers: `onReceive`.
   - Providers: `query`, `insert`, `update`, `delete`, `openFile`, `openAssetFile`, `openTypedAssetFile`, `call`.

3. For each handler, walk the call tree forward with `find_callees(methods=[...], max_depth=8)`. The call graph identifies *candidate* sinks AND *candidate* defenses — scan `transitive_callees_by_class.platform` for both. A handler whose call tree contains no verification FQN at all is a strong finding candidate; a handler whose call tree contains one may still discard the result. Either way the source determines the verdict.

4. **Read the source.** For every in-scope component, read the handler source and answer two questions on every path from the handler's entry to a sensitive sink: (a) does the path reach a sink at all, and (b) is a caller-verification call invoked on that path with its result used to gate the sink (early-return on mismatch, throw on mismatch, branch such that the sink is reached only on the verified branch)? Use `read_file` with line ranges. Follow callback patterns (`new MyCallback(this)` passed to RxJava `subscribe`, `Executor.submit`, etc.) manually by finding the callback class and reading its `apply` / `accept` / `run` / `onSuccess` method — both the sink and the defense may be on either side of the callback boundary.

5. Classify each defense observed on the path:
   - **Sufficient**: `Binder.getCallingUid()` followed by a check against a UID allowlist that gates the sink; `getCallingPackage()` (on providers and services, where it is reliable) followed by `PackageManager.checkSignatures` returning `SIGNATURE_MATCH` or signature digest comparison via `GET_SIGNATURES`/`GET_SIGNING_CERTIFICATES`; `checkCallingPermission` / `enforceCallingPermission` where the named permission is declared in this app's manifest at `signature` or `signatureOrSystem` (verify with `grep`); `AppOpsManager.checkPackage` to confirm package-name claim matches the UID. **Activity-specific**: the sensitive sink runs only inside a UI event handler bound to a user-tap (`View.OnClickListener.onClick`, dialog positive-button handler, fragment lifecycle tied to user input), or the activity calls `finish()` and returns early when the calling package is unexpected.
   - **Insufficient**: `getCallingPackage()` against a package-name allowlist without signature verification (package names are not authentication); `checkCallingPermission` against a `normal` or `dangerous` permission (any app can request these); checking `intent.getPackage()` or `intent.getComponent()` (caller-controlled); checking only that an intent extra is present without validating its contents against a server-issued or keystore-bound value; try/catch swallowing a `SecurityException` from a verification call without altering control flow; `Binder.getCallingUid() == Process.myUid()` used as a permissive check rather than an in-process-only gate.
   - **Special — not a defense**: `Binder.clearCallingIdentity()` is the *opposite* of a defense (suppresses caller identity for downstream platform calls). Its presence usually indicates the sink runs with the app's UID privileges on behalf of an unverified caller and warrants closer scrutiny, not a clean.
   - **None**: the handler reaches the sink with no verification call on the path. Finding.

Budget approximately 3-5 source reads per high-priority component (providers without permission, services with custom Binder interfaces, activities with intent filters performing account/contact/SMS/location operations), 1-2 per low-priority component (no intent filters, receivers without sensitive side effects). If the source walk exceeds the budget without resolving the verification question, mark the row `unverified` with the deepest unresolved call site named.

Priority order when token budget is limited: (1) content providers without signature permission — reliable `getCallingPackage`, common per-URI misconfigurations; (2) services without signature permission, especially bound services exposing AIDL interfaces; (3) activities and activity-aliases with intent filters — the canonical CVE shape; (4) broadcast receivers without signature permission; (5) activities without intent filters.

Sinks to look for

In `transitive_callees_by_class.platform` from `find_callees`, then confirmed in source by reachability from the handler entry:

- Account/credential reads: `android.accounts.AccountManager.getAccountsByType`, `getAccounts`, `getAuthToken`, `blockingGetAuthToken`, `peekAuthToken`, `getPassword`, `getUserData`.
- Permission-protected content queries: `android.content.ContentResolver.query` / `openInputStream` / `openFileDescriptor` where the URI resolves to `ContactsContract.*`, `CallLog.*`, `Telephony.Sms.*`, `Telephony.Mms.*`, `MediaStore.*`, `CalendarContract.*`, `UserDictionary.*`, `BlockedNumberContract.*` (confirm the URI family in source).
- Privileged platform service calls: `LocationManager.getLastKnownLocation`, `requestLocationUpdates`, `getCurrentLocation`; `TelephonyManager.getDeviceId` / `getImei` / `getSubscriberId` / `getLine1Number` / `getSimSerialNumber`; `BluetoothAdapter.getBondedDevices`; `WifiManager.getScanResults`.
- Internal credential reads: `SharedPreferences.getString/getInt/getLong/getBoolean` and `EncryptedSharedPreferences.*` where the key matches `(?i)(token|password|secret|key|auth|credential|session|cookie|api[_-]?key|jwt|bearer)` — confirm the key string is a constant in source, not a method parameter.
- Direct-side-effect sinks (count standalone, no outflow pairing required): `AccountManager.removeAccount` / `setPassword` / `setAuthToken` / `setUserData` / `invalidateAuthToken`; `ContentResolver.delete` / `update` / `insert` against app-owned URIs; `SharedPreferences.Editor.putString` with credential-shaped keys; `SmsManager.sendTextMessage` / `sendMultipartTextMessage` / `sendDataMessage`.
- Outflow sinks (count only when paired with a sensitive read on the same path): `Activity.setResult(int, Intent)` with extras from a sensitive source; `Context.sendBroadcast` / `sendOrderedBroadcast` with sensitive extras; `ContentProvider.query` return value populated with sensitive cursor fields (read the cursor construction); `PendingIntent.send` with sensitive extras; AIDL/Binder return values — identify the generated stub and read the method body.

Defense FQNs to scan as the secondary candidate signal: `Binder.getCallingUid`, `Binder.getCallingPid`, `Binder.clearCallingIdentity` (flag for scrutiny, not a defense), `Context.checkCallingPermission` / `checkCallingOrSelfPermission` / `enforceCallingPermission` / `enforceCallingOrSelfPermission`, `PackageManager.checkSignatures`, `PackageManager.getPackageInfo` (confirm signature flag in source), `AppOpsManager.checkPackage`, `ContentProvider.getCallingPackage`. The source read confirms whether the result is used to gate the sink — a `getCallingUid()` whose return value is logged and ignored is not a defense.

Out-of-scope rule
A component whose `permission` attribute references a signature-level or signatureOrSystem-level permission is out of scope. Confirm the protection level with `grep` on AndroidManifest.xml for the `<permission>` declaration. Custom permissions whose declaration is absent from this app's manifest may be defined by other apps at any protection level; treat these as in-scope.

Output

Emit a JSON object with the structure shown below. The evidence_table follows the same L1/L2 pattern as other MASTG tests: one L1 row per finding/clean conclusion, plus one or more L2 rows naming the specific source ranges that justified it.

Findings require L2 rows for:
- The handler entry point (where the call from outside arrives)
- Each propagation step from entry toward the sink that isn't obvious from the source already cited
- The sink (the specific line of the sensitive operation that runs without verification)
- The absence or insufficiency of verification (cite the line where the path leaves the handler with no verification call, or cite the verification call and explain why it doesn't gate the sink)

Cleans require L2 rows for:
- The handler entry point
- Either the terminus (no sensitive sink reachable, and why) or the gating verification (the call site and how its result gates the sink)

Example evidence_table structure (placeholder names — illustrating the L1/L2 pattern, not the answer to any specific APK):

```
{
  "id": "cmp-XXX",
  "description": "Finding: Exported activity com.example.app.AccountActivity reads the signed-in account's auth token in onCreate and returns it to the caller via setResult, with no caller verification and no UI gating.",
  "reference": "components.json#cmp-XXX",
  "level": 1
},
{
  "id": "L2-AccountActivity-source-1",
  "description": "Source code confirmation (Entry point): onCreate runs unconditionally on intent receipt; the action 'GET_TOKEN' is read from the intent and dispatched to fetchAndReturnToken without consulting getCallingPackage, checkCallingPermission, or any UI confirmation.",
  "reference": "jadx/sources/com/example/app/AccountActivity.java:34-52",
  "level": 2
},
{
  "id": "L2-AccountActivity-source-2",
  "description": "Source code confirmation (Sink): fetchAndReturnToken calls AccountManager.blockingGetAuthToken for the primary signed-in account at line 71, then constructs an Intent with the token as an extra and calls setResult(RESULT_OK, intent) at line 78. Both calls run on the path from onCreate with no preceding verification.",
  "reference": "jadx/sources/com/example/app/AccountActivity.java:65-82",
  "level": 2
},
{
  "id": "L2-AccountActivity-source-3",
  "description": "Source code confirmation (Absence of verification): The full body of onCreate, fetchAndReturnToken, and the constructor chain through BaseActivity.onCreate contains no call to Binder.getCallingUid, PackageManager.checkSignatures, checkCallingPermission, or AppOpsManager.checkPackage. The activity-specific UI-gating exception does not apply: the sink runs directly from the lifecycle method, not from a click handler or dialog response.",
  "reference": "jadx/sources/com/example/app/AccountActivity.java:34-82",
  "level": 2
}
```

For an alias of an already-analyzed component:

```
{
  "id": "cmp-YYY",
  "description": "Finding: Exported activity-alias com.example.app.AccountActivityAlias targets the vulnerable com.example.app.AccountActivity (cmp-XXX). Same handler; same finding.",
  "reference": "components.json#cmp-YYY",
  "level": 1
}
```

For a clean showing that the sink is reachable but gated by a sufficient verification:

```
{
  "id": "cmp-ZZZ",
  "description": "Clean: Exported provider com.example.app.SyncProvider exposes the user's sync state through its query method, but every code path to the cursor construction passes a Binder.getCallingUid + PackageManager.checkSignatures gate that rejects callers whose signature does not match this app's.",
  "reference": "components.json#cmp-ZZZ",
  "level": 1
},
{
  "id": "L2-SyncProvider-source-1",
  "description": "Source code confirmation (Entry and gating verification): The query method's first statement is enforceSameSignatureOrThrow(getContext(), Binder.getCallingUid()), which calls PackageManager.checkSignatures(callingUid, Process.myUid()) at SignatureGuard.java:18 and throws SecurityException on anything other than SIGNATURE_MATCH. The cursor construction and all branches returning sensitive data run only after this throw-on-mismatch.",
  "reference": "jadx/sources/com/example/app/SyncProvider.java:42-110",
  "level": 2
}
```

For a clean showing the sink is unreachable:

```
{
  "id": "cmp-WWW",
  "description": "Clean: Exported service com.example.app.LoggingService accepts intents in onStartCommand but performs only local log writes to a file in getCacheDir(). No account, content-resolver, or credential sinks are reachable from this handler.",
  "reference": "components.json#cmp-WWW",
  "level": 1
},
{
  "id": "L2-LoggingService-source-1",
  "description": "Source code confirmation (Entry and terminus): onStartCommand reads intent.getStringExtra(\"msg\") and appends it to a FileWriter on a constant path inside getCacheDir(). The call tree contains no AccountManager, no ContentResolver.query, no TelephonyManager, no SharedPreferences read with a credential-shaped key, and no setResult/sendBroadcast.",
  "reference": "jadx/sources/com/example/app/LoggingService.java:28-64",
  "level": 2
}
```

Full output object:

```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... rows as above ... ],
  "rationale": "N exported components enumerated, M findings, K clean, S out-of-scope, U unverified. <one or two sentences summarizing the unauthenticated-IPC pattern in plain English, naming the specific handler and sink involved>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules

- A finding requires at least one L2 row citing the source line where the sensitive sink runs, and at least one L2 row establishing the absence or insufficiency of caller verification on the path from the handler entry to that sink. "No verification call appears anywhere in the handler's source" is a valid absence claim only if the read covers the full handler body including any `super` chain into base classes.
- A clean requires at least one L2 row citing either where the sensitive sink stops being reachable (and from where) or where the gating verification call is invoked and how its result controls flow into the sink.
- For any defense claimed sufficient, the L2 description must state the verification API used, the value it compares against, and the control-flow effect of mismatch (throw, early return, or branch). A `getCallingPackage` check against a hardcoded package-name string without signature verification is not sufficient and must be classified as a finding.
- A `Binder.clearCallingIdentity()` call on the path from handler to sink is not a defense; if cited, it must be in a finding row or in an `unverified` row noting that the call's purpose was not resolved.
- For activities, "UI gating" as a defense requires an L2 row citing the specific UI event handler (click listener, dialog button, fragment lifecycle method) that the sensitive sink is reached from, and confirming that no path from `onCreate` / `onNewIntent` / `onResume` reaches the sink directly.
- An `unverified` row must name the deepest unresolved call site (`<ClassFQN>.<method>:<line>`).
- `false_positive_risks` is reserved for OEM-specific framework behavior, runtime config not in the bytecode (remote-config flags disabling the sensitive path, server-side feature gating), or hardware preconditions. Entries describing in-APK code (truncated analysis, unread methods) are invalid — those go in `unverified` rows.
- The verdict is `inconclusive` if the rationale's component count does not match `len(evidence_table)`'s L1 row count, if any `false_positive_risks` entry references in-APK code, or if any finding lacks the L2 rows specified above.

If you reach 39 tool iterations, you MUST provide an answer with the current information you have. A full iteration is comprised of:
- You make your tool calls
- You receive a response for all made tool calls from the user