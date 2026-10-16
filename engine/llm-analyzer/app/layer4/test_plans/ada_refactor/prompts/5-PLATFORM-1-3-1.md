MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-1 (and MSTG-PLATFORM-2)
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          Sensitive functionality exposed via IPC is intentional and at the minimum necessary level (static)

What this test looks for
Every IPC mechanism the app exposes (exported activities, activity-aliases, services, broadcast receivers, content providers) must apply least privilege: exposed only when necessary, protected by an adequate permission when exposed, and not leaking sensitive functionality or data to other apps. This is a static, inventory-style evaluation over the manifest and each exposed component's code. Verdict: `pass` (no sensitive leak; exposed surface follows least privilege), `fail` (sensitive functionality/data exposed without justification or above the minimum necessary), `n/a` (the app exposes no IPC), or `inconclusive`.

EVIDENCE DISCIPLINE (applies to every row)
1. **Every verdict-affecting disposition must quote the code/manifest it rests on - Finding, Compliant, and dismissal alike.** A "leaks sensitive data" or "safe" conclusion with no quoted handler body / manifest line is an assertion -> `unverified`. Quote the manifest `<...>` entry for exposure and the handler lines for behavior.
2. **Read from the code, not the index.** An evidence index (`components.json`, etc.) locates candidates; cite `jadx/sources/...:<line-range>` of the actual handler body (the component's lifecycle/handler method), not the index record or line 1.
3. **A finding may not rest on inference, hedge words, or a hypothetical.** A leak finding requires quoting the actual path: where exported input is read (`getIntent()`/`onReceive`'s intent/`onStartCommand`/provider args) and where it reaches a sink or where sensitive data is returned to the caller. "likely", "may", "appears", "suggesting", "if an exported component were to call this", "could be reached" are NOT evidence -> the disposition is `unverified` (deepest unresolved point named), NOT a Finding. A sink/leak in a NON-exported or unreachable path is out of scope here, not a hypothetical finding.
4. **Unresolved determinacy is `unverified`, not a hedge.** A custom permission's protection level (may be declared in a companion app), whether returned data is sensitive, whether a component is truly reachable - if you cannot settle it from this APK, the row is `unverified`. `false_positive_risks` is for genuinely out-of-APK factors only; in-APK/cross-APK facts you did not resolve belong in `unverified` rows, never as Finding-plus-hedge or pass-plus-hedge.

Scope - what counts as EXPOSED
A component is exposed if other apps can invoke it: `android:exported="true"`, or implicitly exported per the per-type default below, or reachable through an `<intent-filter>`. Determine exposure from the manifest using the correct default for each type and targetSdk:
- Activities / activity-aliases / services / receivers: implicitly exported if they declare an `<intent-filter>`. On `targetSdk >= 31` the `android:exported` attribute is REQUIRED when an intent-filter is present (so it is explicit); below 31 an intent-filter implies exported=true unless `exported="false"`.
- Content providers: default exported=true on `targetSdk <= 16`, exported=false on `targetSdk >= 17`. (Unlike the other types, an intent-filter is not the trigger.)
Non-exported components are out of scope (not reachable by other apps) - summarize them in one line.

The good pattern (do not flag)
- A component with `exported="false"` (explicit, or the per-type default) and no intent-filter -> not exposed, out of scope.
- An exposed component protected by a **signature**/`signatureOrSystem`-level permission, confirmed in this app's `<permission android:protectionLevel=...>` declaration -> minimally exposed, Compliant on the exposure pillar.
- Library components configured per their design (e.g. `androidx.core.content.FileProvider` exported=false with scoped grants, `androidx.startup.InitializationProvider`, WorkManager/Firebase init providers, exported launcher activities with only MAIN/LAUNCHER filters) -> Compliant.
- A standard exported launcher Activity (MAIN + LAUNCHER) that exposes no sensitive data/action is the intended pattern, not a finding.

Failure modes (a finding when on an EXPOSED component)
- IPC1 - Exposed & unprotected sensitive surface: an exported component with no `android:permission` (or only an in-app-declared normal/dangerous permission) whose handler performs a sensitive action or returns sensitive data to the caller.
- IPC2 - Permission above/below need (least privilege): a sensitive surface exported with a weak/none permission where a signature permission is warranted; or over-broad `<grant-uri-permission>`/no path scoping.
- IPC3 - Sensitive data leak: the handler returns sensitive data (files, credentials, tokens, PII, internal state) to any caller, or writes it to a result/broadcast readable by others (e.g. a non-protected `sendBroadcast` of sensitive data, a `setResult` with sensitive extras).
- IPC4 - Dangerous action without authz: the handler performs a privileged/state-changing action (delete, export, send, auth) driven by caller input without a permission/caller check.
- IPC5 - Implicit/unintended export: exported by the per-type default (e.g. provider on targetSdk<=16, or an intent-filter component left exported) where the surface looks internal.

Procedure
1. Read `AndroidManifest.xml`: `targetSdkVersion`, every `<activity>`/`<activity-alias>`/`<service>`/`<receiver>`/`<provider>` with its `exported`, `permission`/`readPermission`/`writePermission`, intent-filters, `grantUriPermissions`, and all `<permission>` protectionLevels. Compute each component's effective exposure with the correct per-type default. Exclude well-known library components configured per design. If nothing is exposed, the verdict is `n/a`.
2. For each EXPOSED component, classify owner (proprietary vs library; prefix is a hint only; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary).
3. **Read the handler body** of each exposed proprietary component - activities: `onCreate`/`onNewIntent`/`onActivityResult`; aliases: the targetActivity's handlers; services: `onStartCommand`/`onBind`/`onHandleIntent`; receivers: `onReceive`; providers: `query`/`insert`/`update`/`delete`/`openFile`/`call`. Determine what it does with caller input and whether it returns/leaks sensitive data or performs a privileged action without an authz check. QUOTE the relevant lines.
4. Apply the permission rule: an exposed sensitive surface with no permission or an in-app normal/dangerous permission is IPC1/IPC2. A custom permission DECLARED here at signature level is adequate. A custom permission NOT declared in this app is `unverified` (level indeterminate - may be a companion-app signature permission or squattable), not a confident finding and not a pass.
5. Conclude per component: Finding (IPC1-IPC5 with the manifest exposure + the handler behavior quoted); Compliant (not exposed / signature-protected / library good-pattern / exposes nothing sensitive, with evidence); Unverified (handler body unread, permission level indeterminate, owner or reachability unresolved); documented candidate (a design-documented justification for an export - out-of-APK).
6. Budget ~2-4 reads per exposed component (manifest entry, permission decl, handler body) plus 1-2 call-graph hops for helpers. If exposure, permission level, owner, or the handler body can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
Component logic fully inside native code or a no-source SDK -> `unverified` (name the entry point). "Justification"/"minimum necessary" is partly a design-intent question; statically, judge by protection level, the sensitivity of the exposed behavior (read from code), and scoping - an unprotected sensitive surface is over-exposed regardless of claimed intent. The static verdict is made on what was determinable.

Output
List **all** EXPOSED IPC mechanisms - one L1 row per exposed component with its disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant exposed components by functionality (e.g. "signature-protected sync services - 5", "launcher/UI activities, no sensitive surface - 8") as one L1 row per group, but always break out every Finding, documented-candidate, and unverified component as its own individual L1 row. Never sample findings. (Non-exported components: one summary line; out of scope.)
- Finding: L1 row plus L2 rows for the exposure (manifest entry: type/exported/permission/filters, with the per-type default applied) and for the behavior (handler body quoted showing the sensitive leak/action and the absence of an authz check).
- Compliant: L1 row plus L2 for the protection (signature permission / not exposed / library good-pattern) and that the handler exposes nothing sensitive (quoted).
- Group: L1 summary plus an L2 naming references and the shared protection/benign behavior.

```
{
  "id": "ipc-001",
  "description": "Finding (IPC3 sensitive data leak): The exported service ExportService returns the contents of an app-private file named by the caller to any app, with no permission.",
  "reference": "AndroidManifest.xml (service .ExportService)",
  "level": 1
},
{
  "id": "L2-ExportService-exposure",
  "description": "Exposure: <service android:name=\".ExportService\" android:exported=\"true\"> with an <intent-filter> and NO android:permission. targetSdk=31 so exported is explicit. Any app can bind/start it.",
  "reference": "AndroidManifest.xml:140-147",
  "level": 2
},
{
  "id": "L2-ExportService-behavior",
  "description": "Behavior (body read, IPC3): onStartCommand does `String n = intent.getStringExtra(\"file\"); ... FileInputStream fis = new FileInputStream(new File(getFilesDir(), n)); ... setResultData(read(fis));` at lines 33-49 - returns app-private file contents named by the caller, no caller/permission check. Sensitive data leak (and path traversal via n).",
  "reference": "jadx/sources/com/example/app/ExportService.java:30-52",
  "level": 2
},
{
  "id": "ipc-launcher-group",
  "description": "Compliant group: 8 exported activities with only MAIN/LAUNCHER or share filters, exposing no sensitive data/action.",
  "reference": "AndroidManifest.xml (launcher/UI activities)",
  "level": 1
},
{
  "id": "L2-launcher-coverage",
  "description": "Good pattern: each is exported via MAIN+LAUNCHER (or SEND) only; onCreate renders UI and reads no caller-controlled sensitive input / returns nothing to the caller (quoted MainActivity.onCreate:30-60). References AndroidManifest.xml:60-138.",
  "reference": "jadx/sources/com/example/app/MainActivity.java:30-60",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-XXXX",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "T components declared, X exposed, N findings (by mode IPC1..IPC5), C compliant, U unverified, plus I non-exported (out of scope). targetSdk + permission posture: <summary>. <one or two sentences naming the components and exposures>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); set true only where exposure/behavior is runtime-driven (recorded `unverified`). It does not change `pass`/`fail`.
- `fail`: >=1 exposed component with (a) an L2 row showing exposure (manifest, correct per-type default applied, permission level checked against the `<permission>` declaration) AND (b) an L2 row with the handler BODY quoted showing a sensitive leak/privileged action without authz (IPC1-IPC5). A leak finding stated with "likely"/"may"/"if it were called"/a hypothetical instead of a quoted exported-input-to-sink/return path is INVALID -> `unverified`.
- **Scope gate.** A sink/leak in a NON-exported or unreachable component is out of scope for this test - not a finding and not a "if an exported component used this" hypothetical. The exposed entry point and its sensitive behavior must both be shown.
- **Read the body before flagging; quote it. Do not flag library/launcher good-patterns.** A component is a finding only if a body you read exposes sensitive behavior; benign/UI/non-sensitive handlers are Compliant. Correctly-configured library components and plain launcher activities are Compliant.
- **Per-type export default + permission level.** Activities/services/receivers: intent-filter implies exported (explicit on targetSdk>=31). Providers: exported default true on targetSdk<=16, false on >=17. A custom permission protects only at signature level confirmed in this app's `<permission>`; undeclared custom permission -> `unverified`, normal/dangerous in-app permission -> inadequate (IPC1/IPC2).
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` is out-of-APK only (design-documented export necessity, companion-app permission at a confirmed level, runtime-built behavior); in-APK facts (is the data sensitive? is it exported? is the permission adequate?) must be resolved by reading code/manifest, not hedged - unresolved -> `unverified`. Reject entries like "might be for internal use only", "might not be sensitive", "might be a deliberate choice".
- `pass`: components are exposed but every exposed surface is minimally exposed (not exported, signature-protected, library good-pattern, or exposes nothing sensitive) with L2 coverage and the targetSdk/permission posture summarized.
- `n/a`: no exposed component (manifest read; state this).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped/out-of-scoped without evidence, or if any `fail` lacks its exposure + quoted-behavior L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) exposure shown from the manifest with the correct per-type default and permission level checked against the `<permission>` declaration; (2) the handler BODY quoted showing the sensitive leak/privileged action and the absence of an authz check - on the EXPOSED component itself, not a hypothetical caller; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary), not a library good-pattern.
Hedge/hypothetical scan: search your findings for "likely", "may", "appears", "if ... were", "could be reached", "might" - a finding relying on these instead of a quoted exposed path is `unverified`.
Evidence-discipline gate (all rows): every Compliant/safe row quotes the handler body (not the index or a bare line range); every exposed component has its own quoted disposition; an unread handler is `unverified`.
Before any `pass`/`fail`: confirm no exposed component was concluded clean or flagged without a quoted body, no finding rests on a non-exported/hypothetical path, and no `false_positive_risks` entry describes an unresolved in-APK fact (convert to `unverified`). Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.