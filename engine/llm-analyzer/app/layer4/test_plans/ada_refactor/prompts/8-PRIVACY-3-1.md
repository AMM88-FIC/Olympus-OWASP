MASTG-TEST-0003-PRIVACY
masvs_v2_id	MASVS-PRIVACY-3
platform	android
title	User Ability to Request Data Deletion

Overview
This test evaluates whether the app provides users with an in-app mechanism to request deletion of their personal data. The mechanism may be implemented as a dedicated activity (e.g. an "Account Settings → Delete Account" screen), as a deep link to a deletion URL launched from within the app, or as an explicit in-app form that submits a deletion request to the backend.

The static signal is the presence of code or resources implementing such a mechanism: string resources containing deletion-related labels, activities or fragments named for account/data deletion, network call sites targeting deletion endpoints, or links to a deletion URL the app exposes from its UI.

Static Analysis
Inspect the app's resources and code for a deletion mechanism:

- String resources (`res/values/strings.xml` and locales) containing labels such as "Delete account", "Delete data", "Remove my data", "Eliminar cuenta", or equivalents in the app's locales
- Activities, fragments, or settings-screen entries named for deletion (e.g. `DeleteAccountActivity`, `AccountDeletionFragment`)
- Outbound network calls targeting deletion endpoints (HTTP DELETE, or POST/PUT to URLs containing `delete`, `account/delete`, `users/delete`, etc.)
- Manifest meta-data or in-app links pointing to a deletion URL hosted by the app's backend or app-store listing

Description
Users shall have the ability to request their data to be deleted via an in-app mechanism.

Evaluation Procedures
Review the app for an in-app mechanism that allows users to modify and delete their personal data.

Verification
The app shall provide an in-app mechanism through which users can modify and delete their personal data — implemented as a dedicated UI flow, a deep link to a deletion endpoint, or an in-app link to a deletion URL.

Verdict scope
This test is binary. The verdict is a yes/no on whether the app provides any in-app data-deletion mechanism — a deletion screen, a deletion deep link, a deletion URL exposed from the UI, or an outbound deletion network call reachable from a UI entry point. The evidence_table cites the resource, manifest, or code records supporting the determination. There is no enumeration to do beyond that.
