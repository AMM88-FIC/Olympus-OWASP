MASTG-TEST-0295

maswe_id       MASWE-0052
masvs_v2_id    MASVS-NETWORK-2
platform       android
title          GMS Security Provider Not Updated - ProviderInstaller missing or mishandled (static)

What this test looks for
To mitigate known SSL/TLS vulnerabilities on older devices, an app should update its security provider via Google Play Services before making network connections, using `ProviderInstaller.installIfNeeded(...)` (synchronous) or `installIfNeededAsync(...)` (async), AND handle the failure paths properly. This test checks whether the app performs the update and handles errors. Verdict: `pass` (the app calls ProviderInstaller before network use and handles exceptions/listener errors correctly), `fail` (the app does not update the provider, or calls it but mishandles errors - swallows exceptions / ignores the listener / does it after connections start), `n/a` (the provider update is genuinely out of scope - e.g. the app targets only modern API levels where Conscrypt is current AND makes no security-sensitive TLS on old devices; state the justification), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `ProviderInstaller`/`installIfNeeded`/`ProviderInstallListener`. If NONE appear -> the app does not update the provider -> lean `fail` (state the search), unless an `n/a` scoping justification holds (state it).

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the `ProviderInstaller` call (or its absence via searches) AND the exception/listener handling. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the call and its handlers, not an index record or line 1.
3. **No finding by inference/hedge.** A `fail` for mishandling requires quoting the swallow/ignore; a `fail` for absence requires showing the searches turned up no ProviderInstaller. "probably not updated" without searches is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** If handling can't be resolved, the row is `unverified`. `false_positive_risks` is out-of-APK only.

Correct vs incorrect handling
- **Synchronous `installIfNeeded(context)`**: must catch `GooglePlayServicesRepairableException` / `GooglePlayServicesNotAvailableException` and respond sensibly (prompt to update Play services, or fail closed for security-sensitive flows). Swallowing the exception and proceeding -> finding.
- **Async `installIfNeededAsync(context, listener)`**: the `ProviderInstallListener.onProviderInstallFailed(int errorCode, Intent recoveryIntent)` must handle the failure (recover or fail closed). An empty/ignoring `onProviderInstallFailed` -> finding.
- **Ordering**: the update should occur BEFORE security-sensitive network connections. Updating after connections start, or only on a code path that doesn't run first, weakens the control - note it.

Procedure
1. Enumerate: `grep -rEn "ProviderInstaller|installIfNeeded|installIfNeededAsync|ProviderInstallListener|onProviderInstallFailed|GooglePlayServicesRepairable" jadx/sources/`. If none -> short-circuit (state the search; `fail` unless `n/a` scoping holds).
2. If present, read the call site and its handlers. Confirm: the update is invoked (sync or async), exceptions/listener failures are handled (not swallowed), and it runs before network use. Quote each.
3. Decide: proper update + handling + ordering -> Compliant (`pass`); missing, swallowed, ignored, or mis-ordered -> finding (`fail`). Quote the gap.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). A library that updates the provider on the app's behalf counts if it actually runs - quote it.
5. Conclude: pass / fail / unverified. 
6. Budget ~2-4 reads (the call site, the catch/listener, the network-init ordering). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Provider handling inside native code or a no-source SDK -> `unverified` (name the entry point). Whether the device actually needed the update is runtime/device-specific. This test judges the presence + correct handling of the ProviderInstaller update statically.

Output
One L1 row for the ProviderInstaller usage (present/absent) plus one L1 row per handling concern. Always break out every mishandling individually. Never sample.
- Finding (absent): L1 row plus an L2 showing the searches found no ProviderInstaller.
- Finding (mishandled): L1 row plus L2 rows quoting the call and the swallowed exception / ignored listener / bad ordering.
- Compliant: L1 row plus L2 rows quoting the call, the proper handling, and the pre-network ordering.

```
{
  "id": "gms-001",
  "description": "Finding (security provider not updated): the app never calls ProviderInstaller, so older devices keep an outdated TLS provider with known weaknesses.",
  "reference": "jadx/sources/",
  "level": 1
},
{
  "id": "L2-gms-absent",
  "description": "Absence (quoted searches): grep for ProviderInstaller / installIfNeeded / installIfNeededAsync / ProviderInstallListener across jadx/sources/ returns no match - the GMS security provider is never updated. Owner: app (proprietary).",
  "reference": "jadx/sources/",
  "level": 2
},
{
  "id": "gms-ok-001",
  "description": "Compliant: app updates the provider synchronously at startup and handles failures.",
  "reference": "jadx/sources/com/example/app/App.java",
  "level": 1
},
{
  "id": "L2-gms-ok",
  "description": "Proper update (quoted): try { ProviderInstaller.installIfNeeded(this); } catch (GooglePlayServicesRepairableException e) { GoogleApiAvailability.getInstance().showErrorNotification(this, e.getConnectionStatusCode()); } catch (GooglePlayServicesNotAvailableException e) { /* fail closed */ } in onCreate() at App.java:30-40 - runs before any network call.",
  "reference": "jadx/sources/com/example/app/App.java:30-40",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0295",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "ProviderInstaller usage: <installIfNeeded / installIfNeededAsync / none>. Handling: <proper / swallowed / ignored listener>. Ordering: <before/after network>. Provider updated and handled correctly? <yes -> pass / no -> fail / out of scope -> n/a>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: the app does not call ProviderInstaller (shown via searches), OR it calls it but (a) swallows the `GooglePlayServices*Exception` and proceeds, (b) ignores `onProviderInstallFailed`, or (c) runs it after security-sensitive connections - quoted. A finding stated with "likely"/"may" instead of quoted evidence is INVALID -> `unverified`.
- **Both call and handling.** A present `installIfNeeded` with a swallowed exception is still a finding. Proper handling AND pre-network ordering are required for `pass`.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every mishandling broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (a library updates the provider first - only if quoted/proven) - in-APK facts (is it called? handled? ordered?) resolved by reading, unresolved -> `unverified`.
- `pass`: ProviderInstaller is called before network use with correct exception/listener handling, quoted.
- `n/a`: only with a stated scoping justification (modern-only target, no security-sensitive TLS on old devices).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale doesn't reconcile with L1 rows, if a mishandling was dropped, if any false_positive_risk references in-APK code, or if a `fail` lacks its quoted absence/mishandling evidence.

Self-check before emitting
Confirm: (1) ProviderInstaller presence/absence is shown via quoted code/searches; (2) if present, the exception/listener handling and the pre-network ordering are quoted; (3) the verdict matches (absent or mishandled or mis-ordered -> fail; correct -> pass).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the ProviderInstaller search was performed and shown, the handling/ordering were read where present (unread -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
