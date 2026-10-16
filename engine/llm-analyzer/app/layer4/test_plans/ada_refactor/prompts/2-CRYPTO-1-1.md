MASTG-TEST-0013
masvs_v1_id	MSTG-CRYPTO-6
masvs_v2_id	MASVS-CRYPTO-1
platform	android
title	Testing Random Number Generation
masvs_v1_levels	L1, L2

Overview
This test evaluates whether the app uses cryptographically secure random number generation for security-sensitive purposes. Use of weak RNGs for non-security purposes (UI animations, jitter, sampling) is out of scope; only uses producing tokens, nonces, IVs, salts, keys, or other unpredictability-required values count.

Static Analysis
Locate every RNG instantiation and call site, and determine whether each is used in a security-sensitive context (downstream taint into crypto APIs, surrounding context, variable names suggesting token/nonce/key/salt/IV/sessionID):

- `java.util.Random` (or derived/wrapping classes)
- `Math.random()`
- `SecureRandom` constructed with a fixed, hardcoded, derived, or otherwise non-default seed
- Custom PRNG implementations (linear congruential, XOR-shift, time-based, etc.)
- Third-party RNG classes not documented as cryptographically secure

Description
The app shall make use of cryptographically secure random number generators.

Evaluation Procedures
Follow the testing procedures outlined in MASTG-TEST-0013.

Verification
The analysis shall demonstrate that all security-sensitive randomness is produced by a properly-seeded `SecureRandom` (or equivalent cryptographically-secure RNG), and that weak RNGs are not used in such contexts.

Verdict scope
This test is catalog-style. Its purpose is to give an analyst a complete inventory of every weak-RNG use in a security-sensitive context. A verdict that finds one example and stops is incomplete.

Treat each of the following as a distinct violation worth a separate evidence_table row:

- Each `java.util.Random` instantiation used in a security-sensitive context
- Each `Math.random()` call used in a security-sensitive context
- Each `SecureRandom` instance constructed with a fixed, hardcoded, derived, or low-entropy seed
- Each custom PRNG implementation used in a security-sensitive context
- Each use of a third-party RNG class not documented as cryptographically secure, in a security-sensitive context

Two records describing the same call site at the same line are duplicates and count as one. An RNG instance constructed once and reused across many draws is one row at the construction site unless a draw site introduces an independent weakness (e.g. re-seeding with a constant before each draw). The rationale should group findings by RNG class (`java.util.Random`, seeded `SecureRandom`, custom PRNG, third-party).
