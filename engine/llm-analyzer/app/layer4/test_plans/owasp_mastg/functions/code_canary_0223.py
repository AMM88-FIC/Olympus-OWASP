"""MASTG-TEST-0223: Stack Canaries Not Enabled.

Deterministic check over the Layer 3 ``native_binaries.json`` evidence, so
this is a programmatic handler rather than an LLM prompt.

The Layer 3 native-binary builder sets ``security_features.stack_canary =
true`` when a library imports ``__stack_chk_fail`` / ``__stack_chk_guard``
(the stack smashing protector symbols). NDK libraries enable canaries by
default; custom C/C++ libraries may not.

EXPECTED FALSE POSITIVES (treated as pass, per the OWASP test notes): some
libraries legitimately have no ``__stack_chk_fail`` symbol even though they
are safe:
  * Memory-safe languages - Flutter's Dart engine (libflutter.so/libapp.so)
    mitigates buffer overflows differently and uses no stack canaries.
  * React Native libraries are built with -fstack-protector-strong but the
    symbol is optimized out / absent (empty .so, or no stack-buffer calls):
    libhermes, libjsc, libreact*, libfbjni, libfolly, libyoga, and the
    documented empty/no-buffer ones (libruntimeexecutor.so,
    libreact_render_debug.so, libreact_utils.so, libreact_config.so,
    libreact_debug.so).
  * The STL runtime libc++_shared.so.
Libraries whose name matches one of these patterns are reported but do NOT
cause a failure; they are surfaced in false_positive_risks for manual
review of the original source / compiler flags.

Verdict:
  * ``n/a``  - the app ships no native libraries.
  * ``pass`` - every native library either has a stack canary, or is a
               documented expected-false-positive.
  * ``fail`` - at least one non-allowlisted native library lacks a canary.

Records are de-duplicated by library name (one library, many ABIs).
"""
import json
from pathlib import Path

TEST_ID = "MASTG-TEST-0223"

# Name substrings for libraries that may legitimately lack __stack_chk_fail.
# Matched case-insensitively against the library file name.
_SAFE_NO_CANARY = (
    "libflutter.so", "libapp.so",                 # Flutter (Dart, memory-safe)
    "libhermes", "libjsc", "libreact", "libfbjni",  # React Native runtime
    "libfolly", "libyoga", "libjsi",
    "libc++_shared.so",                            # STL runtime
    "libruntimeexecutor.so", "libreact_render_debug.so",
    "libreact_utils.so", "libreact_config.so", "libreact_debug.so",
)


def _is_expected_fp(name: str) -> bool:
    n = (name or "").lower()
    return any(pat in n for pat in _SAFE_NO_CANARY)


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for MASTG-TEST-0223 (stack canaries in native libs)."""
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / "native_binaries.json"

    base = {
        "test_id": TEST_ID,
        "certainty_percent": "No-LLM",
        "needs_dynamic_testing": False,
        "false_positive_risks": [],
    }

    if not path.is_file():
        return {
            **base,
            "verdict": "n/a",
            "evidence_table": [{
                "id": "canary-000",
                "description": (
                    "No native_binaries.json evidence found; the app appears "
                    "to ship no native libraries, so stack canaries do not "
                    "apply."
                ),
                "reference": "native_binaries.json",
                "level": 1,
            }],
            "rationale": (
                "No native_binaries.json was produced for this job, indicating "
                "the APK contains no native libraries. MASTG-TEST-0223 (stack "
                "canaries) is not applicable."
            ),
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - never crash the batch
        return {
            **base,
            "verdict": "inconclusive",
            "evidence_table": [{
                "id": "canary-err",
                "description": f"Could not parse native_binaries.json: {exc}.",
                "reference": "native_binaries.json",
                "level": 1,
            }],
            "rationale": (
                f"native_binaries.json could not be read/parsed ({exc}); "
                "stack-canary status is undetermined."
            ),
        }

    records = data.get("records") or []
    if not records:
        return {
            **base,
            "verdict": "n/a",
            "evidence_table": [{
                "id": "canary-000",
                "description": (
                    "native_binaries.json contains zero native-library "
                    "records; the app ships no native code."
                ),
                "reference": "native_binaries.json#records",
                "level": 1,
            }],
            "rationale": (
                "No native libraries are present (0 records). "
                "MASTG-TEST-0223 (stack canaries) is not applicable."
            ),
        }

    # De-duplicate by library name; keep the first record per name.
    seen: dict[str, dict] = {}
    for rec in records:
        name = rec.get("name") or (rec.get("paths") or ["<unknown>"])[0]
        if name not in seen:
            seen[name] = rec

    findings: list[tuple[str, dict]] = []        # non-allowlisted, no canary
    expected_fp: list[str] = []                  # allowlisted, no canary
    compliant: list[str] = []                    # canary present
    for name, rec in seen.items():
        sf = rec.get("security_features") or {}
        if sf.get("stack_canary", False):
            compliant.append(name)
        elif _is_expected_fp(name):
            expected_fp.append(name)
        else:
            findings.append((name, rec))

    evidence_table: list[dict] = []
    for i, (name, rec) in enumerate(findings, 1):
        paths = rec.get("paths") or []
        abis = rec.get("abis") or []
        evidence_table.append({
            "id": f"canary-{i:03d}",
            "description": (
                f"Finding: native library '{name}' has no stack canary "
                f"(security_features.stack_canary = false; no "
                f"__stack_chk_fail import) and is not a known memory-safe / "
                f"empty library. ABIs: {abis or 'n/a'}. Rebuild with "
                f"-fstack-protector-strong."
            ),
            "reference": (
                f"native_binaries.json#records[{name}] "
                f"({paths[0] if paths else 'unknown path'})"
            ),
            "level": 1,
        })

    if expected_fp:
        evidence_table.append({
            "id": "canary-fp",
            "description": (
                f"{len(expected_fp)} library/libraries lack a canary but match "
                f"documented expected-false-positive patterns (memory-safe "
                f"runtime / empty .so), treated as pass: "
                f"{', '.join(sorted(expected_fp))}. Confirm via original "
                f"source / compiler flags."
            ),
            "reference": "native_binaries.json#records",
            "level": 1,
        })

    if compliant:
        evidence_table.append({
            "id": "canary-ok",
            "description": (
                f"{len(compliant)} native library/libraries have stack "
                f"canaries (stack_canary=true): "
                f"{', '.join(sorted(compliant)[:20])}"
                f"{' ...' if len(compliant) > 20 else ''}."
            ),
            "reference": "native_binaries.json#records",
            "level": 1,
        })

    false_positive_risks = []
    if expected_fp:
        false_positive_risks.append(
            "Libraries treated as expected-false-positives "
            f"({', '.join(sorted(expected_fp))}) lack __stack_chk_fail but may "
            "be memory-safe (Dart/Flutter), built with "
            "-fstack-protector-strong with the symbol optimized out (React "
            "Native), or effectively empty. Confirm with the original source "
            "and compiler flags."
        )

    if findings:
        verdict = "fail"
        rationale = (
            f"{len(findings)} of {len(seen)} native library/libraries lack a "
            f"stack canary and are not documented false positives: "
            f"{', '.join(n for n, _ in findings)}. "
            f"{len(compliant)} have canaries; {len(expected_fp)} are expected "
            f"false positives (passed). Custom C/C++ libraries without "
            f"-fstack-protector-strong fail MASTG-TEST-0223."
        )
    else:
        verdict = "pass"
        rationale = (
            f"All evaluable native libraries have stack canaries "
            f"({len(compliant)} with canaries) or are documented "
            f"expected-false-positives ({len(expected_fp)}). "
            f"MASTG-TEST-0223 passes."
        )

    return {**base, "verdict": verdict, "evidence_table": evidence_table,
            "rationale": rationale, "false_positive_risks": false_positive_risks}
