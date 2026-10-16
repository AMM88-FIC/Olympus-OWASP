MASTG-TEST-0001-PRIVACY
masvs_v2_id	MASVS-PRIVACY-1
platform	android
title	Minimizing Access to Sensitive Data and Resources

Overview
This test evaluates whether the app declares only the permissions it actually needs to function. Each `<uses-permission>` (and `<uses-permission-sdk-23>`) entry in the merged manifest must correspond to an API call somewhere in the app's code that requires that permission. Permissions declared without a corresponding usage indicate over-privileging — either developer carelessness, dead code from previous app versions, or permissions pulled in by third-party SDKs that the app doesn't itself rely on.

Static Analysis
For every `<uses-permission>` declaration in the merged `AndroidManifest.xml`, determine whether any code path in the app calls an API that requires that permission. The Android framework's permission-to-API mapping is well-documented: for example, `READ_CONTACTS` requires calls into `ContactsContract`, `ACCESS_FINE_LOCATION` requires `LocationManager.requestLocationUpdates(...)` or `FusedLocationProviderClient.getLastLocation(...)`, `CAMERA` requires `Camera` / `CameraManager` / `CameraX` calls, etc.

A permission whose required APIs are not invoked anywhere in app code (Java/Kotlin or native) is a candidate violation. A permission whose only invocations come from third-party SDK code may still be a violation if the host app does not exercise the SDK feature requiring it.

Pay particular attention to dangerous-protection-level permissions (those that prompt the user at runtime), since these have direct user-privacy impact. Normal-protection-level permissions (e.g. `INTERNET`, `ACCESS_NETWORK_STATE`) carry less privacy impact and are commonly required for general app function.

Description
The app shall minimize access to sensitive data and resources provided by the platform.

Evaluation Procedures
Using static and runtime analysis, monitor permission declarations against actual API usage.

Verification
The app shall adhere to the least-privilege principle: every declared permission corresponds to an API call the app actually makes. Permissions present in the manifest without a corresponding usage are flagged for developer justification.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every permission declared in the merged manifest that has no corresponding API usage in the app. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `<uses-permission>` declaration whose required APIs are not invoked anywhere in app code (Java/Kotlin)
- Each `<uses-permission>` declaration whose only invocations occur in third-party SDK code without the host app exercising the corresponding SDK feature
- Each `<uses-permission>` requested at a broader scope than the app's actual usage requires (e.g. `WRITE_EXTERNAL_STORAGE` declared when only read paths are exercised, `ACCESS_FINE_LOCATION` declared when only coarse location is used)

Two records describing the same permission declaration are duplicates and count as one. A permission used only from one SDK and only along one code path counts as one row, not many. The rationale should group findings by category (unused dangerous permissions, SDK-only permissions, over-broad permissions) and identify which API the permission would have authorized.
