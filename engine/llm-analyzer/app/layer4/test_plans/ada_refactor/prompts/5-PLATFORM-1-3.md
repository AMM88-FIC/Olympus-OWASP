MASTG-TEST-0029
masvs_v1_id	MSTG-PLATFORM-4
masvs_v2_id	MASVS-PLATFORM-1
platform	android
title	Testing for Sensitive Functionality Exposure Through IPC
masvs_v1_levels	L1, L2

Overview
This test evaluates whether IPC components — activities, services, broadcast receivers — expose sensitive functionality to other apps. Content providers are scoped to PLATFORM-1-1 and not re-enumerated here.

Static Analysis

Manifest analysis. For every `<activity>`, `<service>`, and `<receiver>`, determine whether it is exported (explicit `android:exported="true"`, or `<intent-filter>` declared and `exported` not explicitly `"false"` — on `targetSdkVersion >= 31`, `exported` must be explicit when an intent-filter is present). For each exported component, evaluate the `android:permission` gating and the `protectionLevel` of the referenced `<permission>` declaration.

Code analysis. For each exported component, inspect the relevant entry-point methods:

- Activities: `onCreate`, `onNewIntent` — verify entry-point authentication/authorization for activities that present logged-in functionality
- Services: `onBind`, `onStartCommand`, `Handler.handleMessage` (for Messenger-style services) — verify caller-identity check via `Binder.getCallingUid()` or permission for sensitive operations
- Receivers: `onReceive` — verify protection for sensitive actions

Also inspect dynamic receiver registrations (`Context.registerReceiver` without `broadcastPermission`, vs. correctly-scoped `LocalBroadcastManager.getInstance(context).registerReceiver`) and outbound broadcasts (`sendBroadcast`/`sendOrderedBroadcast`/`sendStickyBroadcast`) for `receiverPermission`, explicit `setPackage`/`setComponent`, or `LocalBroadcastManager` use.

Description
Any sensitive functionality exposed via IPC shall be intentional and at the minimum required level.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0029.

Verification
The analysis shall demonstrate (a) that no exported IPC component exposes sensitive functionality without commensurate access control, and (b) that broadcasts carrying sensitive data are scoped to authorized receivers.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every exported activity, service, or receiver that exposes sensitive functionality without commensurate protection, plus every outbound broadcast leaking sensitive data. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each exported `<activity>` whose `onCreate`/`onNewIntent` reaches authentication-protected screens or operations without an entry-point auth check
- Each exported `<service>` whose request handler (`onBind`/`onStartCommand`/`Messenger.handleMessage`) performs a sensitive operation (credential change, key/PIN management, crypto with app-managed keys, payment, account modification) without verifying caller identity
- Each exported `<receiver>` whose `onReceive` triggers a sensitive action (SMS dispatch, credential exfiltration, network request with stored auth, persistent state change) when invoked by any caller
- Each `Context.registerReceiver(receiver, filter)` (non-`LocalBroadcastManager` form) registering a receiver that handles sensitive actions, without a `broadcastPermission` argument
- Each `sendBroadcast`/`sendOrderedBroadcast` call carrying sensitive data in extras, action name, or URI, without `receiverPermission` and without `setPackage`/`setComponent` constraint
- Each `sendStickyBroadcast(...)` call carrying sensitive data
- Each exported component protected by a permission whose `<permission>` declaration uses `protectionLevel="normal"` or `"dangerous"` for an authority handling sensitive functionality outside an enterprise-signing trust boundary

Two records describing the same component element or call site are duplicates and count as one. A component with both an export-without-permission finding and a sensitive-handler finding produces two rows. The rationale should group findings by surface (activity auth bypass, service caller-identity gaps, receiver sensitive-action handling, dynamic receiver registration, unscoped outbound broadcasts, sticky broadcasts, weak protection-level on guard permissions).
