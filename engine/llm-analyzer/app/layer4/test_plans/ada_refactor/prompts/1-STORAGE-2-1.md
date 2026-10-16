MASTG-TEST-0006
masvs_v1_id	MSTG-STORAGE-5
masvs_v2_id	MASVS-STORAGE-1
platform	android
title	Keyboard Cache Disabled for Sensitive Inputs
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app disables keyboard caching on input fields that handle sensitive data. Android's soft keyboard caches words typed into text fields to power autocompletion and spell-check. For fields accepting credentials, PINs, or other secrets, this cache is a disclosure risk.

Static Analysis
For every sensitive `EditText` (or subclass), verify that `android:inputType` is set to a value that suppresses keyboard caching. The canonical values are `textNoSuggestions`, `textPassword`, `textVisiblePassword`, `numberPassword`, and `textWebPassword`. Code paths that re-enable suggestions at runtime via `setInputType(InputType.TYPE_CLASS_TEXT)` on a previously-protected field are also findings.

The app's `minSdkVersion` matters: some inputType constants require an API level above older mins and are silently ignored on older devices.

Description
The keyboard cache shall be disabled on text inputs that process sensitive data.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0006.

Verification
The analysis shall demonstrate that all sensitive input fields use a non-caching `inputType`, and that no code path re-enables suggestions on those fields.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every sensitive input field in the app whose keyboard cache is not properly disabled. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each sensitive `EditText` declared in layout XML without `android:inputType` set to a non-caching value (`textNoSuggestions`, `textPassword`, `textVisiblePassword`, `numberPassword`, or `textWebPassword`)
- Each `setInputType(...)` call that re-enables suggestions on a previously-protected sensitive field
- Each sensitive field whose chosen `inputType` constant requires an API level above the app's `minSdkVersion` (silently ignored on older devices)

Two records describing the same field at the same location are duplicates and count as one. The rationale should group findings by surface (XML-declared, code-overridden, minSdk-version mismatch).
