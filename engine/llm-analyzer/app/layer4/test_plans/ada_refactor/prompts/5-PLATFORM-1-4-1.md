MASTG-TEST-XXXX

masvs_v1_id    MSTG-PLATFORM-1
masvs_v2_id    MASVS-PLATFORM-1
platform       android
title          PendingIntents are immutable or their mutability is justified, with an explicit base Intent (static)

What this test looks for
PendingIntents must be immutable by default to prevent a receiving app from filling in/altering the wrapped Intent. Each `PendingIntent` creation must either set `FLAG_IMMUTABLE`, or - if `FLAG_MUTABLE` is genuinely required - pair the mutability with a clear justification AND a base Intent that is explicit (exact package, action, and component that will receive it). This is a static, inventory-style evaluation over every PendingIntent creation site. Verdict: `pass` (all PendingIntents immutable, or mutable-with-justification + explicit destination), `fail` (a mutable PendingIntent without justification, or without an explicit destination), `n/a` (the app uses no PendingIntents), or `inconclusive`.

EVIDENCE DISCIPLINE (applies to every row)
1. **Every verdict-affecting disposition quotes the code it rests on** - Finding, Compliant, dismissal alike. Quote the `PendingIntent.getActivity/getService/getBroadcast/getActivities(...)` call with its flags argument, and the construction of the base `Intent` it wraps. A disposition with no quoted call/flags is an assertion -> `unverified`.
2. **Read from the code, not the index.** An evidence index locates candidates; cite `jadx/sources/...:<line-range>` of the actual creation site and the base-Intent construction, not the index record or line 1.
3. **No finding by inference/hedge/hypothetical.** A finding requires quoting (a) the PendingIntent factory call and its flags integer, and (b) the base Intent showing it is implicit/under-specified. "likely mutable", "may be exploitable", "if the destination were implicit" are NOT evidence -> `unverified`. Resolve the flags and the Intent by reading; do not guess.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the flags are computed at runtime, or the base Intent is built elsewhere and you cannot trace it within budget, the row is `unverified` (deepest unresolved point named). `false_positive_risks` is out-of-APK only; in-APK facts you did not resolve go in `unverified` rows.

Two checks per PendingIntent
- MUTABILITY: the flags argument to the factory call. `FLAG_IMMUTABLE` (0x4000000 / 67108864) present -> immutable (good). `FLAG_MUTABLE` (0x2000000 / 33554432) present -> mutable (needs justification + explicit destination). NEITHER flag present -> see the targetSdk rule below.
- DESTINATION EXPLICITNESS of the wrapped base Intent: explicit if it sets an exact component - `new Intent(ctx, Foo.class)`, `setClass(...)`, `setComponent(...)`, or `setPackage(...)` with a specific action. Implicit/under-specified if it is `new Intent(ACTION)` / `new Intent()` with only an action or no component (the receiver is resolved at delivery and can be substituted).

targetSdk / API rule
- `targetSdk >= 31`: the platform REQUIRES `FLAG_IMMUTABLE` or `FLAG_MUTABLE` to be set explicitly - a factory call with NEITHER is itself a defect (Finding: missing explicit mutability; historically this was the mutable-by-default footgun and now fails at runtime). Immutable-by-default cannot be assumed from absence.
- `targetSdk < 31`: absence of `FLAG_IMMUTABLE` means mutable-by-default -> treat as mutable (Finding unless justified + explicit), unless a design justification is documented (out-of-APK - documented candidate). `FLAG_IMMUTABLE` explicitly set is Compliant regardless of targetSdk.

The good pattern (do not flag)
- `FLAG_IMMUTABLE` set on the factory call -> Compliant (the destination explicitness still matters only for mutable ones; an immutable PendingIntent cannot be altered, so an immutable + implicit intent is acceptable).
- **Mutable is NOT automatically a finding.** `FLAG_MUTABLE` is legitimately required by certain APIs - notification direct-reply / `RemoteInput`, `Notification.CallStyle`, bubbles, some `AlarmManager`/slices. A `FLAG_MUTABLE` PendingIntent whose base Intent is EXPLICIT (exact component/package+action) and whose use matches such an API is the justified good-pattern -> Compliant (record the justification observed in code). The fail is mutability WITHOUT an explicit destination, or without any such justification.
- Library-created PendingIntents (AndroidX `NotificationCompat`, WorkManager, media session, etc.) configured per the library's API are the library's responsibility; focus on proprietary creation sites.

Failure modes
- PI1 - Mutable + implicit destination: `FLAG_MUTABLE` (or neither flag on targetSdk<31) wrapping an implicit/under-specified base Intent - a malicious receiver can fill in the component and hijack the token. (The core finding.)
- PI2 - Mutable without justification: `FLAG_MUTABLE` set where no mutability-requiring API is involved and no design justification - over-permissive even if the destination is explicit.
- PI3 - Missing explicit mutability on targetSdk>=31: a factory call with neither `FLAG_IMMUTABLE` nor `FLAG_MUTABLE` (defect under the platform requirement).

Procedure
1. Read `targetSdkVersion` from the manifest. Enumerate PendingIntent creation sites, e.g. `grep -rEn "PendingIntent\.(getActivity|getActivities|getService|getForegroundService|getBroadcast)" jadx/sources/`. If there are none, the verdict is `n/a`.
2. For each site, read the flags argument and resolve it (constants OR the integer bitmask) to determine IMMUTABLE / MUTABLE / neither. Quote the call.
3. Trace and read the base Intent passed to that factory call - is it explicit (component/class/package+action) or implicit? Quote its construction. Follow a helper that builds the Intent once.
4. Classify owner (proprietary vs library; prefix is a hint; OEM/ROM vendor prefixes may be first-party; obfuscated/undecidable -> proprietary). Library-API-created PendingIntents per design are Compliant.
5. Conclude per site: Finding (PI1-PI3, with the flags and base-Intent quoted); Compliant (immutable, or mutable+justified+explicit); Unverified (flags runtime-computed, base Intent untraceable, owner unresolved); documented candidate (mutability justified only by an out-of-APK design doc).
6. Budget ~1-3 reads per site (the factory call, the base-Intent construction, any builder helper). If the flags or the base Intent can't be resolved within budget, mark it `unverified` naming the deepest unresolved point (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
PendingIntents created in native code or a no-source SDK -> `unverified` (name the entry point). A "justification" for mutability that exists only in a design document is out-of-APK; in-code evidence (the mutability-requiring API call) is judged directly. The static verdict is made on what was determinable.

Output
List **all** PendingIntents - one L1 row per creation site with its mutability + destination disposition. <=20 -> one L1 row each. >20 (collapse) -> group Compliant sites by functionality (e.g. "immutable notification PendingIntents - 11") as one L1 row per group, but always break out every Finding, documented-candidate, and unverified site as its own individual L1 row. Never sample findings.
- Finding: L1 row plus L2 rows for the flags (the factory call quoted, showing FLAG_MUTABLE / neither) and for the base Intent (quoted, showing implicit/under-specified destination), plus owner.
- Compliant: L1 row plus L2 for FLAG_IMMUTABLE (quoted), or for FLAG_MUTABLE + the explicit base Intent + the mutability-requiring API justification (quoted).
- Group: L1 summary plus an L2 naming references and the shared immutable/justified pattern.

```
{
  "id": "pi-001",
  "description": "Finding (PI1 mutable + implicit destination): A FLAG_MUTABLE PendingIntent wraps an implicit Intent (action only, no component), letting a malicious receiver redirect it.",
  "reference": "jadx/sources/com/example/app/NotifHelper.java",
  "level": 1
},
{
  "id": "L2-NotifHelper-flags",
  "description": "Mutability (call quoted): PendingIntent.getBroadcast(ctx, 0, i, PendingIntent.FLAG_MUTABLE) at line 58 - FLAG_MUTABLE set.",
  "reference": "jadx/sources/com/example/app/NotifHelper.java:54-60",
  "level": 2
},
{
  "id": "L2-NotifHelper-intent",
  "description": "Destination (base Intent quoted, implicit): Intent i = new Intent(\"com.example.ACTION_RETRY\"); at line 55 - action only, no setClass/setComponent/setPackage. A mutable PendingIntent over an implicit Intent is hijackable; no mutability-requiring API (plain broadcast, not RemoteInput).",
  "reference": "jadx/sources/com/example/app/NotifHelper.java:55-58",
  "level": 2
},
{
  "id": "pi-immutable-group",
  "description": "Compliant group: 11 immutable notification PendingIntents (FLAG_IMMUTABLE) with explicit destinations.",
  "reference": "jadx/sources/com/example/app/notify/",
  "level": 1
},
{
  "id": "L2-immutable-coverage",
  "description": "Good pattern: each is PendingIntent.getActivity(ctx, id, new Intent(ctx, DetailActivity.class), FLAG_IMMUTABLE) - FLAG_IMMUTABLE + explicit component (quoted NotifFactory.java:40-120). References (11 sites).",
  "reference": "jadx/sources/com/example/app/notify/NotifFactory.java:40-120",
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
  "rationale": "P PendingIntent sites enumerated, I immutable, M mutable (J justified+explicit, N findings), X neither-flag (targetSdk-dependent), U unverified. targetSdk: <n>. <one or two sentences naming the sites and dispositions>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 PendingIntent with (a) an L2 row quoting the factory call showing FLAG_MUTABLE (or neither flag on targetSdk<31, or neither on targetSdk>=31 = PI3) AND (b) for PI1, an L2 row quoting the base Intent showing an implicit/under-specified destination; or PI2 (mutable, no justification). A finding stated with "likely"/"may"/"if the destination were implicit" instead of the quoted flags + base Intent is INVALID -> `unverified`.
- **Mutable is not automatically a finding; immutable+implicit is fine.** A FLAG_MUTABLE PendingIntent with an explicit destination AND a mutability-requiring API (RemoteInput/CallStyle/bubble/etc., quoted) is Compliant. An immutable PendingIntent is Compliant regardless of base-Intent explicitness (it cannot be altered). The hijackable combination is mutable + implicit.
- **Read the flags and base Intent before flagging; quote both. Do not flag library-API PendingIntents.** Resolve integer bitmasks (FLAG_IMMUTABLE=0x4000000, FLAG_MUTABLE=0x2000000) as well as named constants.
- **targetSdk rule.** targetSdk>=31: neither flag = PI3 finding (explicit mutability required). targetSdk<31: neither flag = mutable-by-default (PI1/PI2 unless justified). FLAG_IMMUTABLE explicit = Compliant either way.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually (finding count = finding rows); undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only (a design-documented mutability justification, a flag chosen at runtime by server config) - in-APK facts (which flag? explicit destination?) resolved by reading, unresolved -> `unverified`. Reject "might be immutable in practice", "might be justified".
- `pass`: PendingIntents exist and every one is immutable, or mutable-with-justification + explicit destination, with L2 coverage and targetSdk recorded.
- `n/a`: no PendingIntent creation site (enumeration performed; state this).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows (finding count = finding rows), if any false_positive_risk references in-APK code, if a finding was dropped without evidence, or if any `fail` lacks its quoted flags + (for PI1) base-Intent L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the factory call and its flags argument are quoted and resolved (FLAG_MUTABLE / neither, not guessed); (2) for PI1, the base Intent is quoted showing an implicit/under-specified destination, and no mutability-requiring API justifies it; (3) owner decided from evidence (OEM-aware; obfuscated -> proprietary), not a library-API PendingIntent.
Hedge scan: "likely", "may", "appears", "if ... were", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`: confirm no site was concluded without quoting its flags and (for mutable) its base Intent; confirm immutable sites were not flagged for an implicit intent; confirm no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.