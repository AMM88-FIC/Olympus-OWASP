MASTG-TEST-0021
masvs_v2_id	MASVS-AUTH-1
platform	android
title	Proof Key for Code Exchange (PKCE) in OAuth/OIDC Code Grants

Overview
This test evaluates whether the app implements PKCE for OAuth 2.0 authorization-code grants and OpenID Connect authorization-code flows. PKCE is not relevant to client-credentials grants, resource-owner-password grants, refresh-token-only flows, or implicit grants — those flows do not produce findings under this test, even when present in the app.

If the app uses no OAuth/OIDC authorization-code flows, the verdict is `not_applicable`.

Static Analysis
Identify every OAuth 2.0 / OIDC authorization-code flow in the app:

- Hosts contacted via OAuth library calls (AppAuth, OkHttp-based builders) — authorization endpoints, token endpoints
- WebView-hosted flows constructed from URL strings or query-parameter builders
- `response_type=code` parameter in any URL composition

For each flow, verify presence of `code_challenge` (authorization request), `code_verifier` (token exchange), and `code_challenge_method=S256` (not `plain`).

Description
PKCE shall be implemented for OAuth 2.0 / OIDC authorization-code grants.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0021.

Verification
The analysis shall demonstrate that every OAuth/OIDC authorization-code flow in the app includes the PKCE parameters (`code_challenge`, `code_verifier`, `code_challenge_method=S256`).

Verdict scope
This test is catalog-style with a `not_applicable` short-circuit. Its purpose is to give an analyst a complete inventory of every OAuth/OIDC authorization-code flow lacking PKCE. A verdict that finds one example and stops is incomplete.

If the app uses no OAuth/OIDC authorization-code flows, the verdict is `not_applicable`. The unit of enumeration is the distinct authorization-code flow, identified by the triple (authorization endpoint host, client_id, redirect_uri).

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each OAuth/OIDC authorization-code flow whose authorization request does not include a `code_challenge` parameter
- Each OAuth/OIDC authorization-code flow whose token exchange does not include a `code_verifier` parameter
- Each OAuth/OIDC authorization-code flow that sends `code_challenge_method=plain` rather than `S256`
- Each WebView-hosted OAuth/OIDC authorization-code flow constructed from URL/query-parameter builders that lack PKCE plumbing

Two records describing the same flow at the same construction site are duplicates and count as one. The rationale should group findings by identity provider or by OAuth client library (AppAuth, custom OkHttp builder, WebView-based).
