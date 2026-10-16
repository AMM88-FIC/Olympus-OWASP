MASTG-TEST-0002-PRIVACY
masvs_v2_id	MASVS-PRIVACY-2
platform	android
title	Transparency of Data Collection and Usage

Overview
This test evaluates whether the app is transparent with users about the personal data it collects and transmits. The required disclosures live in two places: the Play Store Data Safety Section and the app's privacy policy. The app's actual behavior — which data it reads from device APIs and which data it transmits over the network — must match those disclosures.

Static analysis can establish the **observed** side of this comparison: which categories of personal data the app accesses and which leave the device. It cannot fetch the Play Store Data Safety Section or evaluate the privacy policy text against the observed behavior; that comparison requires external evidence. A static-only verdict for this test is typically `partial_static_only`.

Static Analysis
Enumerate data-access call sites in the app code that read categories of personal data. The categories the Play Data Safety taxonomy distinguishes include:

- **Personal identifiers**: name, email, phone, address (input fields, account APIs)
- **Device identifiers**: `Settings.Secure.ANDROID_ID`, advertising ID via `AdvertisingIdClient`, `Build.SERIAL`, IMEI via `TelephonyManager.getDeviceId()` / `getImei()`, MAC address
- **Location**: `LocationManager`, `FusedLocationProviderClient`, `getLastKnownLocation`
- **Contacts**: `ContactsContract` queries
- **Sensor data**: camera (`CameraX`, `Camera`), microphone (`AudioRecord`, `MediaRecorder`), accelerometer/gyroscope, biometric APIs
- **App activity**: in-app purchases, search queries, page views — typically logged through analytics SDKs
- **Files**: external storage reads, `MediaStore` queries

For each access, follow the data flow to its sinks. The relevant sink is **outbound network transmission** — the data leaves the device. Sites that read but do not transmit are not transparency findings under this test (though they may be relevant to other tests).

Privacy-policy presence. Inspect the manifest and resources for a privacy-policy URL — typically a `meta-data` entry, a string resource referenced from settings UI, or a hardcoded URL in code. The presence of such a mechanism is a positive indicator; absence is a violation.

Description
The app shall be transparent about data collection and usage.

Evaluation Procedures
Perform a match between data practices displayed in the Play Store Data Safety Section and the app's privacy policy. Check for data types transmitted over the network that aren't declared to users.

Verification
The analysis shall demonstrate that all categories of personal data the app collects and transmits are disclosed in the app's privacy policy or in an equivalent in-app mechanism.

Verdict scope
This test is catalog-style with a known static-analysis limitation. Its purpose is to give an analyst a complete inventory of every category of personal data the app collects and transmits, plus the presence or absence of a privacy-policy mechanism. The disclosure-comparison step itself requires external evidence (Play Data Safety Section, privacy policy text) that the static pipeline does not have access to; the static finding lists what the app does, and an external reviewer compares that list against the disclosures.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each call site reading a category of personal data (per the Play Data Safety taxonomy above) whose data flows to an outbound network sink
- Each network-transmission call site sending a personal-data payload to a remote endpoint, when the data flow originates from a personal-data API
- The absence of any privacy-policy mechanism in the app — flag once per evaluation when no policy URL, in-app policy screen, or equivalent is found

Two records describing the same call site at the same line are duplicates and count as one. The same data category collected at multiple sites and transmitted from a single endpoint counts as one row at the transmission site (or one row per data category if they are distinct categories funneled through the same endpoint). The rationale should group findings by data category and identify, for each, the collection site and the transmission destination.
