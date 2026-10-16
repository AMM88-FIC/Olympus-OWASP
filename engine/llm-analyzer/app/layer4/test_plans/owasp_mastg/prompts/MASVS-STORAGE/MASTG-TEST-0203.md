MASTG-TEST-0203

maswe_id       MASWE-0001
masvs_v2_id    MASVS-STORAGE-2
platform       android
title          Runtime Use of Logging APIs - sensitive data logged at runtime (dynamic; static approximation)

NOTE - DYNAMIC TEST, STATIC APPROXIMATION: MASTG-TEST-0203 is a dynamic test (runtime hooking of logging APIs to observe logcat). This static engine cannot observe runtime output, so this prompt performs the best-effort static equivalent - the same analysis as MASTG-TEST-0231. OVERRIDE: regardless of any rule below, ALWAYS set needs_dynamic_testing to true; the static verdict is indicative only and must be confirmed at runtime.

What this test looks for
The app must not emit sensitive data in plaintext to logcat or to log files in public external storage. This is a fully static evaluation: the criterion is that no logging sink receives a sensitive value in plaintext. It is a taint problem — a sensitive **source** value reaching a logging **sink** with no sufficient redaction in between is a finding. The test always applies (no N/A). The verdict is decided entirely from the static trace: `pass` (no sink statically receives sensitive data), `fail` (at least one does), or `inconclusive`.

Source is ground truth. A logging-call evidence index is a candidate list only — extractors miss wrapper loggers, whole-object `toString`, helper indirection, and logging configured to write to files. Confirm every finding/clean by reading the call site in `jadx/sources/` and tracing the logged argument to its origin.

What counts as a sensitive value (taint sources)
Credentials and secrets: passwords/PINs/passphrases, `accessToken`/`refreshToken`/JWT/session id, `apiKey`/secret, OTP secrets, recovery seed/mnemonic, private keys, `Authorization` header values. Financial: card number/PAN/expiry/CVV, IBAN/account. Identity/PII: government IDs (DNI/NIF/NIE/SSN/passport), device identifiers (IMEI, `getSubscriberId`, Android ID used as identity), precise location.
A value is tainted if it is: (a) read from a sensitive input field — an `EditText.getText()` whose field has a password `inputType` or a sensitive id/hint (same sensitivity signals as test 1.1.2.1); (b) returned by a sensitive API — `KeyStore`, `AccountManager.getPassword/getUserData`, `TelephonyManager.getImei/getDeviceId/getSubscriberId`, `getLastKnownLocation`, a SharedPreferences read of a secret key, an auth network response; (c) held in a variable/field whose name matches the secret tokens above; or (d) **a whole object whose `toString()`/Kotlin data-class auto-`toString` exposes any sensitive field** (e.g. logging a `User`, `LoginRequest`, or `Account` object — a common real leak). Read the object's class to confirm.

Logging sinks
- logcat: `android.util.Log.{v,d,i,w,e,wtf,println}`, `android.util.Slog`, `android.util.EventLog`, `System.out`/`System.err.println`, `Throwable.printStackTrace()`.
- Wrappers/frameworks routing to logcat: `timber.log.Timber.*`, `org.slf4j` / Logback-Android, and any app-internal logger that ultimately calls one of the above (follow the wrapper to its body once).
- Public-storage log files: writes to `Environment.getExternalStoragePublicDirectory(...)`, `getExternalStorageDirectory()`, or MediaStore shared collections of log-like content; logging frameworks configured with a file appender under public external storage. App-private internal storage and app-scoped `getExternalFilesDir()` are out of scope (not public); note the latter as low priority only.

Procedure
1. Enumerate sinks from the evidence index if present, then confirm with grep, e.g. `grep -rEn "Log\.(v|d|i|w|e|wtf)|Slog\.|System\.(out|err)|printStackTrace|Timber\.|getExternalStoragePublicDirectory|getExternalStorageDirectory" jadx/sources/`.
2. For each sink, identify the dynamic arguments (skip calls whose arguments are all string literals).
3. Trace each dynamic argument to its origin — local assignment, parameter, field, or helper return — and decide if it is tainted per the source rules (including whole-object `toString`). Read helper bodies and concatenation operands; a tag-only or message-only constant with a tainted concatenated operand is still a finding.
4. Classify the defense between source and sink:
   - Sufficient: the sensitive value is hashed, fully masked, or replaced by a non-reversible placeholder before the sink (e.g. only last 4 digits, `"***"`, a one-way hash).
   - Insufficient: partial masking that still logs the secret, a redactor applied to a different variable, or masking only of display not of the logged string.
   - None: the tainted value reaches the sink directly.
   - Mitigating but not sufficient on its own: the call is gated by `if (BuildConfig.DEBUG)` or a debug flag. Note it and the build type; in a release artifact a DEBUG-gated call is effectively dead, which the verdict may weigh, but record it.
5. Budget ~1–3 reads per sink touching a dynamic value. If a backward trace within the bytecode can't be resolved within budget, mark it `unverified` naming the deepest unresolved site (`<ClassFQN>.<method>:<line>`).

Out-of-scope / static limits
- Remote crash/analytics telemetry (Crashlytics, Sentry) is a different leakage vector, not logcat or public storage — out of scope here; note if it logs secrets but do not base the verdict on it.
- Logging that occurs in native code, via reflection, or inside a third-party SDK with no decompiled source cannot be traced statically. Record such a sink as an `unverified` row (naming the entry point or SDK method that hands data to the unanalyzable path); it does not become a finding or a clean. The static verdict is made on what was determinable; do not defer the verdict to runtime.

Output
JSON object as below; evidence_table uses the L1/L2 pattern.
- Finding (a sink logging a sensitive value): L1 row plus L2 rows for the sink line, the taint source / why the argument is sensitive, and the defense (absent/insufficient) with the reason.
- Clean (PASS): one L1 conclusion plus L2 rows for enumeration coverage (how many sinks, that each dynamic-argument sink was traced) and, for any sink that touched a plausibly sensitive value, where it is redacted or terminates as non-sensitive.

```
{
  "id": "log-001",
  "description": "Finding: AuthManager.login logs the user password in plaintext to logcat. The value comes from the password EditText and reaches Log.d with no redaction.",
  "reference": "jadx/sources/com/example/app/AuthManager.java",
  "level": 1
},
{
  "id": "L2-AuthManager-source",
  "description": "Taint source: pwd = binding.etPassword.getText().toString(); etPassword has android:inputType=\"textPassword\" (sensitive input field).",
  "reference": "jadx/sources/com/example/app/AuthManager.java:51-58",
  "level": 2
},
{
  "id": "L2-AuthManager-sink",
  "description": "Sink (None defense): Log.d(TAG, \"login pwd=\" + pwd) at line 63 concatenates the tainted pwd directly; no masking/hashing between source and sink. Call is not DEBUG-gated.",
  "reference": "jadx/sources/com/example/app/AuthManager.java:60-66",
  "level": 2
},
{
  "id": "log-clean",
  "description": "Clean example: no logging sink receives a sensitive value. The two sinks that touch credentials log only a SHA-256 hash.",
  "reference": "jadx/sources/com/example/app/",
  "level": 1
},
{
  "id": "L2-clean-coverage",
  "description": "Coverage and terminus: 31 Log/Timber/System.out sinks enumerated; the 7 with dynamic arguments were traced. SessionLogger.log(token) at TokenStore.java:88 logs Hashing.sha256(token), not the token (Sufficient). Remaining sinks log constants or non-sensitive ids.",
  "reference": "jadx/sources/com/example/app/TokenStore.java:80-92",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0203",
  "verdict": "fail" | "pass" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "K logging sinks enumerated, D with dynamic arguments traced, N findings, R redacted/clean, U unverified. <one or two sentences naming the classes, methods and values involved>",
  "needs_dynamic_testing": true,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The static `pass`/`fail` is final and never deferred to runtime. This is the static approximation of a dynamic test, so `needs_dynamic_testing` is ALWAYS `true` (per the OVERRIDE note above) to flag that runtime confirmation is warranted; it does not change the static `pass`/`fail`.
- `fail`: ≥1 sink with an L2 row showing a tainted value reaches it (passed as/concatenated into an argument) AND an L2 row showing the defense is None or Insufficient. "Reaches the sink" means the tainted value is an argument or part of one — not merely that a logger exists nearby.
- `pass`: every sink with a dynamic argument was traced and none receives a sensitive value (each terminates at a non-sensitive origin or sufficient redaction), with L2 coverage. A DEBUG-gated sink logging a secret is reported, not silently passed.
- Whole-object logging counts: cite the class showing the `toString`/data-class fields that expose the secret.
- `unverified` rows name the deepest unresolved site (or the entry point handing data to native/reflection/no-source code). Such sinks are neither findings nor cleans.
- `false_positive_risks` is for factors outside the static artifact only (a value that looks sensitive by name but is non-secret at runtime, server-controlled log verbosity, OEM logcat behavior). In-APK gaps (truncated/unread/unresolved code) go in `unverified` rows.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK code, or if any `fail` lacks its two L2 rows.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.