MASTG-TEST-0008
masvs_v1_id	MSTG-STORAGE-7
masvs_v2_id	MASVS-PLATFORM-3
platform	android
title	Checking for Sensitive Data Disclosure Through the User Interface
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app's UI surfaces leak sensitive data — by displaying it in cleartext within input fields where masking is expected, or by including it in notification content visible on the lock screen and in the notification shade.

Static Analysis

Input fields. For every sensitive `EditText` (or subclass: `TextInputEditText`, `AppCompatEditText`, custom subclasses):

- Layout XML: `android:inputType` must be `textPassword`, `numberPassword`, or `textWebPassword`. `textVisiblePassword` is only acceptable as the post-toggle state.
- Code overrides: `EditText.setInputType(...)` and `EditText.setTransformationMethod(...)` calls reachable on the field's normal flow (not behind a user toggle) are findings.
- "Show password" toggles: must restore masking on pause/submit; must not persist cleartext state across activity restarts.

Sensitivity follows from field hint, label, autofill hints (`AUTOFILL_HINT_PASSWORD`, `AUTOFILL_HINT_CREDIT_CARD_NUMBER`), and surrounding context.

Notifications. For every `NotificationCompat.Builder`/`Notification.Builder` chain:

- `setContentTitle`/`setContentText`/`setSubText`/`setTicker` and `setStyle` (`BigTextStyle.bigText`/`MessagingStyle.addMessage`/`InboxStyle.addLine`) — the strings are visible on the lock screen and in the notification shade
- `setVisibility(int)` — sensitive content should use `VISIBILITY_SECRET` or `VISIBILITY_PRIVATE` with a clean `setPublicVersion(...)`; default is `VISIBILITY_PUBLIC`
- `setPublicVersion(...)` — the public-version builder must itself be free of sensitive content

Description
The app shall by default mask data in the User Interface when it is known to be sensitive.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0008.

Verification
Passwords, PINs, credit card information, and data commonly found on government IDs must be properly masked in input fields and suppressed in notifications. Sensitive data shall only be displayed in cleartext through an explicit user action, with masking restored on completion.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every UI surface that discloses sensitive data without proper masking or suppression. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each sensitive `EditText` declared in layout XML without `android:inputType` set to `textPassword`/`numberPassword`/`textWebPassword`
- Each `EditText.setInputType(...)` call overriding a sensitive field's masked state to a non-password type on a path reachable without an explicit user toggle
- Each `EditText.setTransformationMethod(null)` (or `setTransformationMethod(SingleLineTransformationMethod.getInstance())`) on a sensitive field on a path reachable without an explicit user toggle
- Each "show password" toggle implementation that flips masking permanently or persists the unmasked state across activity restarts
- Each sensitive `EditText` whose autofill hints declare a sensitive type but whose `inputType` is not the corresponding password variant
- Each `NotificationCompat.Builder`/`Notification.Builder` chain whose content arguments carry sensitive data without `setVisibility(VISIBILITY_SECRET)` or `setVisibility(VISIBILITY_PRIVATE)` with a clean `setPublicVersion(...)`
- Each `Notification.Builder` chain that sets `setVisibility(VISIBILITY_PUBLIC)` explicitly while the content includes sensitive data
- Each `setPublicVersion(...)` call whose argument builder itself includes sensitive content
- Each notification posted via `NotificationManager.notify(...)` whose builder is composed from untrusted-but-potentially-sensitive sources without inspection

Two records describing the same field declaration or notification builder at the same line are duplicates and count as one. A single screen with both an unmasked password field and a leaky notification produces two rows. The rationale should group findings by surface (XML inputType masking, code-side overrides, show-password toggle implementation, autofill-hint vs inputType mismatch, notification content leakage, notification visibility, public-version content).
