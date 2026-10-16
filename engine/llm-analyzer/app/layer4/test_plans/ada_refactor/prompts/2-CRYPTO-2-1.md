MASTG-TEST-0019
masvs_v1_id	MSTG-CRYPTO-2
masvs_v2_id	MASVS-CRYPTO-2
platform	android
title	Purposes of Cryptographic Keys
masvs_v1_levels	L1, L2

Overview
This test evaluates whether each cryptographic key is used consistently with its defined purpose. The unit of analysis is the key, traced from where it is generated/imported to every site where it is used.

Static Analysis
For each key, inspect:

- KeyStore-backed keys: `KeyProperties.PURPOSE_*` flags declared on `KeyGenParameterSpec`/`KeyProtection` versus actual uses (`Cipher`/`Mac`/`Signature` operations)
- Asymmetric keys: direction of use (private-for-signing/decryption-to-self, public-for-encryption/signature-verification)
- Symmetric keys: whether the same key is used across multiple cryptographic purposes (content encryption AND HMAC integrity, content encryption AND key wrapping)
- Name-vs-use mismatch: variables/classes named for one purpose (e.g. `signingKey`) used at sites with another purpose

Description
Each cryptographic key shall be used only for its defined purpose.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0019.

Verification
The analysis shall demonstrate that no key is used outside its declared purpose, and that distinct cryptographic purposes use distinct keys.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every key used outside its defined purpose. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each KeyStore-backed key whose actual use does not match its declared `KeyProperties.PURPOSE_*` flags
- Each asymmetric private key used to perform encryption (rather than signing or decryption-to-self)
- Each asymmetric public key used to perform decryption (rather than encryption or signature verification)
- Each symmetric key used across two or more distinct cryptographic purposes (e.g. content encryption AND MAC integrity, content encryption AND key wrapping)
- Each KeyStore-backed key generated without `setPurposes(...)` constraints whose downstream uses span multiple purposes
- Each key whose declared business purpose (variable/class naming) does not match the cryptographic operation at the use site

Two records describing the same key used at the same call site at the same line are duplicates and count as one. The same key misused at two distinct call sites counts as two rows. The rationale should group findings by surface (KeyStore purpose mismatch, asymmetric direction reversal, symmetric reuse across purposes, missing purpose constraints, name-vs-use mismatch).
