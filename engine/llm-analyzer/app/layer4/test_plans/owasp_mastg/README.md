# OWASP MASTG v2 test plan (`owasp_mastg`)

Static-analysis port of the OWASP MASTG **`tests-beta/android/`** test set
(the MASVS v2 / MASWE-based catalogue) for this engine's Layer 4 verdict
flow. **107 test cases** across all 8 MASVS categories.

Source of truth: <https://github.com/OWASP/owasp-mastg/tree/master/tests-beta/android>

## Layout

```
owasp_mastg/
├── tests.toml                       # manifest: test_id -> handler (llm prompt | programmatic)
├── prompts/MASVS-<CATEGORY>/        # LLM prompt files (101)
└── functions/                       # programmatic Python handlers (6) + __init__.py
```

Each LLM prompt is named `MASTG-TEST-XXXX.md` and emits a structured verdict
JSON whose `test_id` matches the filename. Programmatic handlers expose
`run(job_id, evidence_dir) -> dict` returning the same verdict shape.

## Running / filtering

`--test-filter` (and `[paths].test_filter`) matches the test_id **or** the
`category` label, so:

```bash
python run_parallel.py --config config-gemini.ini --test-filter crypto      # all CRYPTO
python run_parallel.py --config config-gemini.ini --test-filter 'network|crypto'   # both (parallel runner = regex)
python run_parallel.py --config config-gemini.ini --test-filter MASTG-TEST-0202    # one test
```

### Output layout

Per-test verdicts are written grouped by category, so a run's progress is
legible at a glance instead of a flat list of numeric IDs:

```
<output_dir>/
├── _summary.json              # run aggregate (stays at the root)
├── CRYPTO/MASTG-TEST-0204.json
├── NETWORK/MASTG-TEST-0217.json
├── PLATFORM/MASTG-TEST-0364.json
└── ...
```

Tests with no `category` (e.g. the older `ada_refactor` plan) keep writing to
the output root, so this is backward compatible. `create_website.py` recurses
into these subfolders (`rglob`), so report generation is unaffected.

## Summary

| MASVS category | Tests | Controls touched |
|----------------|------:|------------------|
| STORAGE        | 12 | STORAGE-1, STORAGE-2 |
| CRYPTO         | 12 | CRYPTO-1, CRYPTO-2 |
| NETWORK        | 18 | NETWORK-1, NETWORK-2 |
| AUTH           |  5 | AUTH-2 |
| PLATFORM       | 22 | PLATFORM-1, PLATFORM-2, PLATFORM-3 |
| CODE           | 13 | CODE-1..4 |
| RESILIENCE     | 18 | RESILIENCE-1..4 |
| PRIVACY        |  7 | PRIVACY-1, PRIVACY-3 |
| **Total**      | **107** | (101 LLM + 6 programmatic) |

## Conventions

- **`(dynamic; static approximation)`** — OWASP test is dynamic (hooks /
  traffic capture / device filesystem). Implemented as a best-effort static
  equivalent that ALWAYS sets `needs_dynamic_testing: true` and names its
  static sibling. (19 tests.)
- **placeholder → best-effort static** — OWASP ships the test as
  `status: placeholder` (no procedure). Implemented as a best-effort static
  check with an honest header note. Placeholders: CRYPTO 0309/0310,
  NETWORK 0237/0238/0239, PLATFORM 0292/0293/0294, PRIVACY 0255/0256/0257.
- **`(programmatic)`** — deterministic evidence check run as a Python handler
  under `functions/` (no LLM): native PIC/canaries/symbols, signature
  version/key-size, debuggable flag.
- **Verdict vocabulary** — `pass` / `fail` / `n/a` / `inconclusive`, plus
  `unverified` evidence rows; every finding quotes the code/config it rests on.
- **Cross-listing** — MASTG-TEST-0381 (PendingIntent) is cross-listed upstream
  in both MASVS-CODE and MASVS-PLATFORM; registered **once** under PLATFORM.

> Mapping notes: `MASWE-0066` spans CODE-4 (intent tests 0372–0374) and
> PLATFORM-1 (0381) — the `masvs_v2_id` tracks each test's category, mirroring
> OWASP's own cross-listing. `MASWE-0117` spans PRIVACY-1 (permission
> minimization) and PRIVACY-3 (rationale/transparency). All other
> MASWE→MASVS mappings are 1:1.

## Test inventory

Legend: **L** = LLM prompt · **P** = programmatic handler · *dyn* = dynamic
test rendered as a static approximation · *ph* = upstream placeholder
implemented best-effort.

### MASVS-STORAGE (12)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0200 L *dyn* | MASWE-0007 | STORAGE-2 | Files Written to External Storage (sensitive unencrypted files in shared storage) |
| MASTG-TEST-0201 L *dyn* | MASWE-0007 | STORAGE-2 | Runtime Use of APIs to Access External Storage |
| MASTG-TEST-0202 L | MASWE-0007 | STORAGE-2 | References to APIs/Permissions for External Storage (unencrypted) |
| MASTG-TEST-0203 L *dyn* | MASWE-0001 | STORAGE-2 | Runtime Use of Logging APIs (sensitive data logged) |
| MASTG-TEST-0231 L | MASWE-0001 | STORAGE-2 | References to Logging APIs (sensitive data to logs) |
| MASTG-TEST-0216 L *dyn* | MASWE-0004 | STORAGE-2 | Sensitive Data Not Excluded From Backup |
| MASTG-TEST-0262 L | MASWE-0004 | STORAGE-2 | References to Backup Configurations Not Excluding Sensitive Data |
| MASTG-TEST-0207 L *dyn* | MASWE-0006 | STORAGE-1 | Unencrypted Sensitive Data in App-Sandbox Files |
| MASTG-TEST-0287 L *dyn* | MASWE-0006 | STORAGE-1 | Unencrypted Sensitive Data via SharedPreferences |
| MASTG-TEST-0304 L | MASWE-0006 | STORAGE-1 | Unencrypted Sensitive Data via SQLite |
| MASTG-TEST-0305 L | MASWE-0006 | STORAGE-1 | Unencrypted Sensitive Data via Jetpack DataStore |
| MASTG-TEST-0306 L | MASWE-0006 | STORAGE-1 | Unencrypted Sensitive Data via Android Room |

### MASVS-CRYPTO (12)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0204 L | MASWE-0027 | CRYPTO-1 | Insecure Random API Usage (weak PRNG) |
| MASTG-TEST-0205 L | MASWE-0027 | CRYPTO-1 | Non-random Sources Usage (time/counter as randomness) |
| MASTG-TEST-0208 L | MASWE-0009 | CRYPTO-1 | Insufficient Key Sizes |
| MASTG-TEST-0212 L | MASWE-0014 | CRYPTO-2 | Hardcoded Cryptographic Keys |
| MASTG-TEST-0221 L | MASWE-0020 | CRYPTO-1 | Broken Symmetric Encryption Algorithms |
| MASTG-TEST-0232 L | MASWE-0020 | CRYPTO-1 | Broken Symmetric Encryption Modes (ECB) |
| MASTG-TEST-0312 L | MASWE-0020 | CRYPTO-1 | Explicit Security Provider (non-default JCA) |
| MASTG-TEST-0350 L *dyn* | MASWE-0020 | CRYPTO-1 | Runtime Use of Broken Symmetric Encryption Modes |
| MASTG-TEST-0307 L | MASWE-0012 | CRYPTO-2 | Asymmetric Key Pairs Used For Multiple Purposes |
| MASTG-TEST-0308 L *dyn* | MASWE-0012 | CRYPTO-2 | Runtime Use of Asymmetric Key Pairs (multiple purposes) |
| MASTG-TEST-0309 L *ph* | MASWE-0022 | CRYPTO-1 | Reused Initialization Vectors (static/predictable IV) |
| MASTG-TEST-0310 L *dyn ph* | MASWE-0022 | CRYPTO-1 | Runtime Use of Reused Initialization Vectors |

### MASVS-NETWORK (18)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0217 L | MASWE-0050 | NETWORK-1 | Insecure TLS Protocols Allowed in Code |
| MASTG-TEST-0218 L *dyn* | MASWE-0050 | NETWORK-1 | Insecure TLS Protocols in Network Traffic |
| MASTG-TEST-0233 L | MASWE-0050 | NETWORK-1 | Hardcoded HTTP URLs |
| MASTG-TEST-0235 L | MASWE-0050 | NETWORK-1 | App Configurations Allowing Cleartext Traffic |
| MASTG-TEST-0236 L *dyn* | MASWE-0050 | NETWORK-1 | Cleartext Traffic Observed on the Network |
| MASTG-TEST-0237 L *ph* | MASWE-0050 | NETWORK-1 | Cross-Platform Framework Cleartext Traffic |
| MASTG-TEST-0238 L *dyn ph* | MASWE-0050 | NETWORK-1 | Runtime Network APIs Transmitting Cleartext |
| MASTG-TEST-0239 L *ph* | MASWE-0050 | NETWORK-1 | Low-level APIs (raw sockets) custom HTTP |
| MASTG-TEST-0242 L | MASWE-0047 | NETWORK-2 | Missing Certificate Pinning in NSC |
| MASTG-TEST-0243 L | MASWE-0047 | NETWORK-2 | Expired Certificate Pins in NSC |
| MASTG-TEST-0244 L *dyn* | MASWE-0047 | NETWORK-2 | Missing Certificate Pinning in Network Traffic |
| MASTG-TEST-0234 L | MASWE-0052 | NETWORK-2 | Missing Hostname Verification with SSLSockets |
| MASTG-TEST-0282 L | MASWE-0052 | NETWORK-2 | Unsafe Custom Trust Evaluation (TrustManager) |
| MASTG-TEST-0283 L | MASWE-0052 | NETWORK-2 | Incorrect Hostname Verification |
| MASTG-TEST-0284 L | MASWE-0052 | NETWORK-2 | Incorrect SSL Error Handling in WebViews |
| MASTG-TEST-0285 L | MASWE-0052 | NETWORK-2 | Outdated Android Version Trusting User CAs (minSdk<24) |
| MASTG-TEST-0286 L | MASWE-0052 | NETWORK-2 | NSC Trust in User-Provided CAs |
| MASTG-TEST-0295 L | MASWE-0052 | NETWORK-2 | GMS Security Provider Not Updated |

### MASVS-AUTH (5)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0326 L | MASWE-0045 | AUTH-2 | Fallback to Non-Biometric Authentication (DEVICE_CREDENTIAL) |
| MASTG-TEST-0327 L | MASWE-0044 | AUTH-2 | Event-Bound Biometric Auth (no CryptoObject) |
| MASTG-TEST-0329 L | MASWE-0044 | AUTH-2 | Auth without Explicit User Action (setConfirmationRequired(false)) |
| MASTG-TEST-0330 L | MASWE-0044 | AUTH-2 | Keys with Extended Validity Duration |
| MASTG-TEST-0328 L | MASWE-0046 | AUTH-2 | Biometric Enrollment Changes (setInvalidatedByBiometricEnrollment(false)) |

### MASVS-PLATFORM (22)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0355 L | MASWE-0064 | PLATFORM-1 | Unauthorized DB Access through Content Providers |
| MASTG-TEST-0356 L *dyn* | MASWE-0064 | PLATFORM-1 | Runtime Unauthorized DB Access through Providers |
| MASTG-TEST-0357 L | MASWE-0064 | PLATFORM-1 | Oversharing of File-Based Content Providers |
| MASTG-TEST-0364 L | MASWE-0119 | PLATFORM-1 | Exported & Unprotected Activities |
| MASTG-TEST-0365 L | MASWE-0062 | PLATFORM-1 | Exported & Unprotected Services |
| MASTG-TEST-0366 L | MASWE-0063 | PLATFORM-1 | Exported & Unprotected Broadcast Receivers |
| MASTG-TEST-0381 L | MASWE-0066 | PLATFORM-1 | Insecure PendingIntent Creation (cross-listed w/ CODE) |
| MASTG-TEST-0250 L | MASWE-0069 | PLATFORM-2 | Content Provider Access in WebViews |
| MASTG-TEST-0251 L *dyn* | MASWE-0069 | PLATFORM-2 | Runtime Content Provider Access in WebViews |
| MASTG-TEST-0252 L | MASWE-0069 | PLATFORM-2 | Local File Access in WebViews |
| MASTG-TEST-0253 L *dyn* | MASWE-0069 | PLATFORM-2 | Runtime Local File Access in WebViews |
| MASTG-TEST-0334 L | MASWE-0069 | PLATFORM-2 | Native Code Exposed Through WebViews (JS bridge) |
| MASTG-TEST-0320 L *dyn* | MASWE-0118 | PLATFORM-2 | WebViews Not Cleaning Up Sensitive Data |
| MASTG-TEST-0258 L | MASWE-0053 | PLATFORM-3 | Keyboard Caching Attributes in UI |
| MASTG-TEST-0316 L | MASWE-0053 | PLATFORM-3 | Auth Data in Text Input Fields (unmasked) |
| MASTG-TEST-0340 L | MASWE-0053 | PLATFORM-3 | Overlay Attack Protections (tapjacking) |
| MASTG-TEST-0315 L | MASWE-0054 | PLATFORM-3 | Sensitive Data Exposed via Notifications |
| MASTG-TEST-0291 L | MASWE-0055 | PLATFORM-3 | Screen Capturing Prevention (FLAG_SECURE) |
| MASTG-TEST-0289 L *dyn* | MASWE-0055 | PLATFORM-3 | Sensitive Content in Backgrounding Screenshots |
| MASTG-TEST-0292 L *ph* | MASWE-0055 | PLATFORM-3 | setRecentsScreenshotEnabled (Recents screenshot) |
| MASTG-TEST-0293 L *ph* | MASWE-0055 | PLATFORM-3 | setSecure in SurfaceViews |
| MASTG-TEST-0294 L *ph* | MASWE-0055 | PLATFORM-3 | SecureFlagPolicy in Compose Dialogs |

### MASVS-CODE (13)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0222 **P** | MASWE-0116 | CODE-4 | Position Independent Code (PIC) Not Enabled |
| MASTG-TEST-0223 **P** | MASWE-0116 | CODE-4 | Stack Canaries Not Enabled |
| MASTG-TEST-0245 L | MASWE-0077 | CODE-1 | References to Platform Version APIs |
| MASTG-TEST-0382 L *dyn* | MASWE-0075 | CODE-2 | Use of Enforced Updating APIs |
| MASTG-TEST-0272 L | MASWE-0076 | CODE-3 | Dependencies with Known Vulnerabilities (Gradle) |
| MASTG-TEST-0274 L | MASWE-0076 | CODE-3 | Dependencies with Known Vulnerabilities (SBOM) |
| MASTG-TEST-0337 L | MASWE-0088 | CODE-4 | Object Deserialization of Untrusted Data |
| MASTG-TEST-0338 L | MASWE-0082 | CODE-4 | Integrity/Authenticity of Local Storage Data |
| MASTG-TEST-0339 L | MASWE-0086 | CODE-4 | SQL Injection in Content Providers |
| MASTG-TEST-0372 L | MASWE-0066 | CODE-4 | Implicit Intents for Internal Communication |
| MASTG-TEST-0373 L | MASWE-0066 | CODE-4 | Internal Component Unintentionally Exported |
| MASTG-TEST-0374 L | MASWE-0066 | CODE-4 | Implicit Intents Carrying Sensitive Extras |
| MASTG-TEST-0375 L *dyn* | MASWE-0083 | CODE-4 | Missing Validation of Data Returned from Implicit Intents |

### MASVS-RESILIENCE (18)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0247 L | MASWE-0008 | RESILIENCE-1 | Secure Screen Lock Detection APIs |
| MASTG-TEST-0249 L *dyn* | MASWE-0008 | RESILIENCE-1 | Runtime Secure Screen Lock Detection |
| MASTG-TEST-0324 L | MASWE-0097 | RESILIENCE-1 | Root Detection Mechanisms |
| MASTG-TEST-0325 L *dyn* | MASWE-0097 | RESILIENCE-1 | Runtime Root Detection |
| MASTG-TEST-0351 L *dyn* | MASWE-0099 | RESILIENCE-1 | Emulator Detection |
| MASTG-TEST-0224 **P** | MASWE-0104 | RESILIENCE-2 | Insecure APK Signature Version (v1-only) |
| MASTG-TEST-0225 **P** | MASWE-0104 | RESILIENCE-2 | Insecure APK Signature Key Size (RSA<2048) |
| MASTG-TEST-0226 **P** | MASWE-0067 | RESILIENCE-2 | Debuggable Flag Enabled |
| MASTG-TEST-0227 L | MASWE-0067 | RESILIENCE-2 | Debugging Enabled for WebViews |
| MASTG-TEST-0265 L | MASWE-0094 | RESILIENCE-2 | References to StrictMode APIs |
| MASTG-TEST-0263 L *dyn* | MASWE-0094 | RESILIENCE-2 | Logging of StrictMode Violations |
| MASTG-TEST-0264 L *dyn* | MASWE-0094 | RESILIENCE-2 | Runtime Use of StrictMode APIs |
| MASTG-TEST-0288 **P** | MASWE-0093 | RESILIENCE-3 | Debugging Symbols in Native Binaries |
| MASTG-TEST-0368 L | MASWE-0089 | RESILIENCE-3 | Insufficient Obfuscation of Java/Kotlin Code |
| MASTG-TEST-0369 L | MASWE-0089 | RESILIENCE-3 | Insufficient Obfuscation of Native Code |
| MASTG-TEST-0341 L *dyn* | MASWE-0107 | RESILIENCE-4 | Hook / Instrumentation Detection |
| MASTG-TEST-0352 L | MASWE-0101 | RESILIENCE-4 | Debugging Detection APIs |
| MASTG-TEST-0353 L *dyn* | MASWE-0101 | RESILIENCE-4 | Runtime Use of Debugging Detection APIs |

### MASVS-PRIVACY (7)

| Test | MASWE | MASVS | Title |
|------|-------|-------|-------|
| MASTG-TEST-0254 L | MASWE-0117 | PRIVACY-1 | Dangerous App Permissions (vs feature justification) |
| MASTG-TEST-0255 L *ph* | MASWE-0117 | PRIVACY-1 | Permission Requests Not Minimized |
| MASTG-TEST-0257 L *ph* | MASWE-0117 | PRIVACY-1 | Not Resetting Unused Permissions |
| MASTG-TEST-0256 L *ph* | MASWE-0117 | PRIVACY-3 | Missing Permission Rationale |
| MASTG-TEST-0318 L | MASWE-0112 | PRIVACY-3 | SDK APIs Known to Handle Sensitive User Data |
| MASTG-TEST-0319 L *dyn* | MASWE-0112 | PRIVACY-3 | Runtime Use of SDK APIs Handling Sensitive Data |
| MASTG-TEST-0206 L *dyn* | MASWE-0108 | PRIVACY-3 | Undeclared PII in Network Traffic |

## Programmatic handler evidence dependencies

| Handler | Test | Reads |
|---------|------|-------|
| `code_pic_0222.run` | 0222 | `native_binaries.json` → `security_features.pie` |
| `code_canary_0223.run` | 0223 | `native_binaries.json` → `security_features.stack_canary` (+ memory-safe-lib allowlist) |
| `res_sig_version_0224.run` | 0224 | `app_metadata.json` → `signing_schemes` + `min_sdk` |
| `res_sig_keysize_0225.run` | 0225 | `app_metadata.json` → `certificates[].key_size_bits` / `key_algorithm` |
| `res_debuggable_0226.run` | 0226 | `manifest_findings.json` → `flags.debuggable` |
| `res_native_symbols_0288.run` | 0288 | `native_binaries.json` → `security_features.symbols_stripped` |
