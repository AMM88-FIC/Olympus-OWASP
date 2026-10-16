MASTG-TEST-0015
masvs_v1_id	MSTG-CRYPTO-3
masvs_v2_id	MASVS-CRYPTO-1
platform	android
title	Testing the Configuration of Cryptographic Standard Algorithms
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app configures cryptographic primitives against industry best practice — block-cipher mode and padding, hash choice, MAC choice, signature parameters, provider selection, and IV reuse. Custom (non-platform) crypto is also a finding when standard primitives exist. Symmetric algorithm choice and key sourcing are scoped to CRYPTO-1-2.

Static Analysis
For each `Cipher`, `MessageDigest`, `Mac`, `Signature`, and KeyStore-backed key configuration, inspect the algorithm string, mode, padding, provider, and IV source.

Description
Cryptographic primitives shall be configured according to industry best practices.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0015.

Verification
The analysis shall demonstrate that block-cipher modes are authenticated or paired with MACs, padding choices are appropriate, hash and signature schemes use modern algorithms, providers are not legacy, IVs are unique where required, and no hand-rolled crypto is used where standard primitives exist.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every misconfigured cryptographic primitive. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `Cipher.getInstance(...)` requesting ECB mode for a block cipher
- Each `Cipher.getInstance(...)` for a confidentiality-and-integrity context using a non-AEAD mode (CBC, CTR, OFB, CFB) without a paired MAC at the same flow
- Each `Cipher.getInstance(...)` requesting `NoPadding` for confidentiality, or `PKCS1Padding` for RSA where OAEP is required
- Each `Cipher.getInstance(...)` with an explicit non-default provider that is not KeyStore-related (Conscrypt/AndroidOpenSSL is default; specifying `BC`, `Crypto`, or a legacy provider is a finding)
- Each `MessageDigest.getInstance(...)` requesting a weak hash (`MD5`, `SHA-1`, `MD2`, `MD4`) in a security-sensitive context
- Each `Mac.getInstance(...)` requesting a MAC built on a weak hash (`HmacMD5`, `HmacSHA1`)
- Each `Signature.getInstance(...)` requesting weak parameters (`MD5withRSA`, `SHA1withRSA`, `NONEwithRSA`, RSA-PKCS1v1.5 for new-key signing where PSS is expected)
- Each `KeyGenParameterSpec` / `KeyPairGenerator` / `KeyGenerator` pinning a flagged primitive
- Each custom (non-platform) crypto implementation reachable from app code (hand-rolled cipher, hash, MAC, XOR "encryption")
- Each `Cipher`/`Mac`/`MessageDigest`/`Signature` using `IvParameterSpec` initialized from a hardcoded, all-zero, or constant IV in a context where IV uniqueness is required

Two records describing the same call site at the same line are duplicates and count as one. A single misconfigured factory call reused across many sites is one row at the construction site. The rationale should group findings by primitive (mode, padding, hash, MAC, signature, provider, custom crypto, IV reuse).
