MASTG-TEST-0039
masvs_v1_id	MSTG-CODE-2
masvs_v2_id	MASVS-RESILIENCE-4
platform	android
title	Testing whether the App is Debuggable
masvs_v1_levels	R

Overview
This test evaluates whether the APK ships with the `android:debuggable` attribute set to `"true"` on the `<application>` tag. A debuggable app permits `run-as <package>` shell access on any device, allows attaching JDWP debuggers in production, and exposes internal state to anyone with adb access. Release builds must have this attribute unset (default `false`) or explicitly `false`.

Static Analysis
Inspect the `<application>` tag in `AndroidManifest.xml`. The relevant attribute is `android:debuggable`. The default is `false` when the attribute is omitted; an explicit `android:debuggable="true"` is the only failure mode for this test.

Description
The app shall not be debuggable if installed from outside of commercial app stores.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0039.

Verification
The application's `<application android:debuggable="...">` attribute shall be either absent or set to `false`.

Verdict scope
This test is binary. The verdict is a yes/no on whether the manifest's `<application>` element declares `android:debuggable="true"`. The evidence_table cites the manifest record and the attribute value. There is no enumeration to do beyond that.
