MASTG-TEST-0315

maswe_id       MASWE-0054
masvs_v2_id    MASVS-PLATFORM-3
platform       android
title          Sensitive Data Exposed via Notifications (static)

What this test looks for
Notifications are visible on the lock screen and Recents and can be shoulder-surfed, so the app must not place sensitive data (PII, OTPs, financial/health details, message bodies that are sensitive) in notification content (`setContentTitle`/`setContentText`/`setStyle`/`bigText`/messaging styles). This is a static, taint-style evaluation: sensitive source -> notification content sink. Verdict: `pass` (no sensitive data is placed in notifications), `fail` (>=1 notification includes sensitive data, subject to the minSdk/permission condition below), `n/a` (the app posts no notifications - state this), or `inconclusive`.

SHORT-CIRCUIT (decide first): `grep` for `Notification`/`NotificationCompat`/`setContentText`/`notify(`. If NONE appear -> `n/a` (no notifications; state the search).

The applicability condition (per OWASP)
The test fails if the app exposes sensitive data in a notification AND either:
- `minSdkVersion >= 33` and the `POST_NOTIFICATIONS` permission is declared, OR
- `minSdkVersion <= 32` (regardless of whether `POST_NOTIFICATIONS` is declared).
Resolve `minSdkVersion` and the `POST_NOTIFICATIONS` permission and apply this. (In practice: if the app can post notifications at all on its supported range and puts sensitive data in them, it fails - the condition mainly excludes apps that target only API 33+ but never declare the permission, i.e. cannot post.)

Sensitive data (taint sources)
PII (name/email/phone/government IDs), OTPs / verification codes, financial/payment data, health data, precise location, auth/session material, and message bodies whose content is sensitive. Non-sensitive content (generic "You have a new message", a brand name, a non-sensitive status) is not a finding.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the code it rests on.** Quote the sensitive value AND the notification content sink it reaches. No quoted code -> `unverified`.
2. **Read from the code, not the index.** Cite `jadx/sources/...:<line-range>` of the builder call and the data source, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the sensitive value and (b) its placement in a notification field. "probably shows the OTP" with no quoted setContentText is NOT evidence -> `unverified`. A generic notification text is Compliant.
4. **Unresolved determinacy is `unverified`, not a hedge.** If the content's sensitivity can't be resolved (a variable from an unresolved source), the row is `unverified`. `false_positive_risks` is out-of-APK only.

Notification content sinks
`Notification.Builder`/`NotificationCompat.Builder` `.setContentTitle(...)`, `.setContentText(...)`, `.setSubText(...)`, `.setTicker(...)`, `BigTextStyle.bigText(...)`, `MessagingStyle`/`InboxStyle` lines, custom `RemoteViews` text - and the value passed in. Also note `setVisibility(VISIBILITY_PUBLIC)` on a sensitive notification (shows full content on the lock screen) as an aggravating factor, vs `VISIBILITY_PRIVATE`/`SECRET` (hides on lock screen) which mitigates - but sensitive content in the notification body is the core issue.

Procedure
1. Resolve `minSdkVersion` (manifest / app_metadata.json) and whether `POST_NOTIFICATIONS` is declared (`grep -nE "minSdkVersion|POST_NOTIFICATIONS" jadx/resources/AndroidManifest.xml`). State both; apply the applicability condition.
2. Enumerate notification sites: `grep -rEn "NotificationCompat|Notification\.Builder|setContentTitle|setContentText|setSubText|bigText|MessagingStyle|notify\(" jadx/sources/`. If none -> short-circuit `n/a` (state the search).
3. For each notification, trace the values placed in content fields and whether any is sensitive (taint from a sensitive source). Quote value + sink. Generic/non-sensitive -> Compliant. Note `setVisibility` where relevant.
4. Owner: app (proprietary); a library posting notifications with app data is reported.
5. Conclude per notification: Finding (sensitive value in content + applicability condition met, quoted); Compliant (non-sensitive content); Unverified (sensitivity/source unresolved).
6. Budget ~2-4 reads per notification (the builder, the value source, 1-2 hops). Unresolved within budget -> `unverified` naming the deepest unresolved point.

Out-of-scope / static limits
Notification building inside native code or a no-source SDK -> `unverified` (name the entry point). Whether the lock screen actually shows it depends on user/device settings - the static finding is sensitive data placed in notification content. 

Output
List **all** notification content sites carrying app data - one L1 row per notification (or data category) with its disposition - plus an Observation row for `minSdkVersion` + `POST_NOTIFICATIONS`. <=20 -> one L1 row each. >20 (collapse) -> group Compliant generic notifications, but always break out every Finding individually. Never sample findings.
- Observation: L1 row with `minSdkVersion`, `POST_NOTIFICATIONS` declared?, and the applicability outcome.
- Finding: L1 row plus L2 rows quoting the sensitive value and the notification content sink, plus owner.
- Compliant: L1 row plus an L2 showing non-sensitive content.

```
{
  "id": "ntf-001",
  "description": "Finding (OTP exposed in a notification): The app posts the login OTP in the notification text, visible on the lock screen.",
  "reference": "jadx/sources/com/example/app/auth/OtpNotifier.java",
  "level": 1
},
{
  "id": "L2-ntf-source",
  "description": "Sensitive value (quoted): String code = response.getOtp(); at OtpNotifier.java:30 - one-time verification code.",
  "reference": "jadx/sources/com/example/app/auth/OtpNotifier.java:30",
  "level": 2
},
{
  "id": "L2-ntf-sink",
  "description": "Notification content (quoted): new NotificationCompat.Builder(ctx, CH).setContentTitle(\"Your code\").setContentText(\"Code: \" + code).setVisibility(VISIBILITY_PUBLIC) ...; notify(1, b.build()) at lines 33-40 - OTP in the body, public visibility. minSdkVersion=24 -> applicability condition met. Owner: com.example.app (proprietary).",
  "reference": "jadx/sources/com/example/app/auth/OtpNotifier.java:33-40",
  "level": 2
},
{
  "id": "ntf-ok-001",
  "description": "Compliant: message notification shows a generic text, not the message body.",
  "reference": "jadx/sources/com/example/app/msg/MsgNotifier.java",
  "level": 1
},
{
  "id": "L2-ntf-ok",
  "description": "Non-sensitive content (quoted): setContentText(\"You have a new message\") at MsgNotifier.java:28 - no sensitive data.",
  "reference": "jadx/sources/com/example/app/msg/MsgNotifier.java:28",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0315",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "minSdkVersion=<N>, POST_NOTIFICATIONS <declared/absent> -> applicability <met/not>. M notification sites, S placing sensitive data, N findings, C compliant (generic), U unverified. Any sensitive data in notifications (with applicability)? <no -> pass / n-a if no notifications / yes -> fail>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` is a non-binding flag (typically false); it does not change `pass`/`fail`.
- `fail`: >=1 notification with (a) an L2 quoting a sensitive value AND (b) an L2 quoting its placement in a notification content field, with the applicability condition (minSdk/permission) met and stated. A finding stated with "likely"/"may" instead of the quoted value+sink is INVALID -> `unverified`.
- **Apply the minSdk/POST_NOTIFICATIONS condition.** State minSdk and whether POST_NOTIFICATIONS is declared, and the resulting applicability. Use minSdkVersion (the least-secure supported environment), not targetSdkVersion.
- **Sensitivity required.** Generic notification text is Compliant. `setVisibility(VISIBILITY_PRIVATE/SECRET)` mitigates lock-screen exposure - note it, but sensitive content in the body remains the finding.
- **No sampling / ownership default (OEM-aware) / false_positive hygiene** as in the suite: every Finding broken out individually; undecidable/obfuscated owner -> proprietary; `false_positive_risks` out-of-APK only - in-APK facts (is the value sensitive? in the notification?) resolved by reading, unresolved -> `unverified`.
- `pass`: no sensitive data is placed in notifications, with L2 coverage.
- `n/a`: the app posts no notifications (short-circuit; state the search).
- `unverified` rows name the deepest unresolved point (or native/SDK entry point). Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if the applicability condition was not stated, if any false_positive_risk references in-APK code, or if any `fail` lacks its value + notification-sink L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the sensitive value is quoted and its category named; (2) its placement in a notification content field is quoted; (3) the minSdk/POST_NOTIFICATIONS applicability is stated and met; (4) owner decided from evidence (OEM-aware; obfuscated -> proprietary).
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the notification search was performed (n/a state it), minSdk + POST_NOTIFICATIONS resolved and applicability applied, every sensitive notification's value and sink were read and quoted (unread -> `unverified`), no generic notification was flagged, and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
