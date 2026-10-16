MASTG-TEST-0003
masvs_v1_id	MSTG-STORAGE-3
masvs_v2_id	MASVS-STORAGE-1
platform	android
title	Sensitive Data in Logs
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app emits sensitive data to logcat or to log files written in public locations. Internal-only log files within the app sandbox are out of scope; only emissions reaching logcat or public/external storage are findings.

Static Analysis
Locate every logging call site and trace its arguments back to their sources to determine sensitivity:

- `android.util.Log.*` (`v`, `d`, `i`, `w`, `e`, `wtf`)
- `java.util.logging.Logger`
- `System.out.print*`, `System.err.print*`, `Throwable.printStackTrace()`
- Custom logging facilities (app-internal `SecureLog`-style wrappers) that ultimately emit to logcat

A logging argument is sensitive when surrounding context (variable names, taint signals, source flow from credentials/tokens/PII APIs) indicates sensitivity. Speculation alone is not enough.

Description
The app shall not log sensitive data to publicly accessible places.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0003.

Verification
The analysis shall demonstrate that sensitive data is not emitted to logcat, `System.out`/`System.err`, `printStackTrace`, custom loggers reaching public destinations, or log files in public locations.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every call site that emits sensitive data to logcat or to a public log file. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `android.util.Log.*` call site whose arguments include sensitive data
- Each `java.util.logging.Logger` call site whose arguments include sensitive data
- Each `System.out.print*`, `System.err.print*`, or `Throwable.printStackTrace()` call that emits sensitive data
- Each custom logging facility call site that emits sensitive data to logcat or a public location
- Each write of a log file to external storage or other public/world-readable locations

Two records describing the same call site at the same line are duplicates and count as one. The rationale should group findings by surface (`Log.*`, `System.out`/`System.err`, `printStackTrace`, custom loggers, public log files).
