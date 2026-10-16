from pathlib import Path

try:
    import ujson as json
except ImportError:
    import json


# ---------------------------------------------------------------------------
# Test: native binary compiler protections (PIE/PIC + stack canary)
# MSTG-CODE-9 / MASVS-CODE-4
#
# Reads the pre-digested native_binaries.json evidence file (schema with a
# top-level "records" array; each record carries security_features.pie and
# security_features.stack_canary as booleans). No ELF parsing - the extractor
# (pyelftools) already pulled the facts.
#
# PASS - every native .so has PIE (security_features.pie == true) AND a stack
#        canary (security_features.stack_canary == true).
# N/A  - the APK contains no native libraries (no records).
# FAIL - at least one .so lacks PIE or lacks a stack canary.
# INCONCLUSIVE - records exist but none could be read (missing fields).
#
# The spec also allows N/A-with-justification when a 3rd-party native lib
# legitimately cannot be compiled with these protections. That is an
# out-of-artifact fact a static check cannot decide, so this script reports the
# technical FAIL and names the offending binaries for a human to downgrade.
# ---------------------------------------------------------------------------


def _binary_path(record):
    paths = record.get("paths")
    if isinstance(paths, list) and paths:
        return paths[0]
    src = record.get("source") or {}
    if src.get("path"):
        return src["path"]
    return record.get("name", "(unknown)")


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for the native-binary compiler-protections test.

    The dict shape mirrors the LLM-test output so downstream consumers can
    treat programmatic and LLM verdicts uniformly.
    """
    result = {
        "test_id": "CODE-X-X",  # set to the real MASA id for this test
        "verdict": "",
        "certainty_percent": "Non-LLM",
        "evidence_table": [],
        "rationale": "",
    }

    evidence_path = str(Path(evidence_dir) / "native_binaries.json")
    print(evidence_path)

    with open(evidence_path) as json_data:
        native = json.load(json_data)

    records = native.get("records", []) or []

    analyzed = []      # records where both pie and stack_canary are present booleans
    undetermined = []  # records missing security_features / the two fields
    for rec in records:
        sf = rec.get("security_features") or {}
        pie = sf.get("pie")
        canary = sf.get("stack_canary")
        entry = {
            "id": rec.get("id", "?"),
            "path": _binary_path(rec),
            "arch": rec.get("machine") or (rec.get("abis") or ["?"])[0],
            "pie": pie,
            "stack_canary": canary,
        }
        if isinstance(pie, bool) and isinstance(canary, bool):
            entry["compliant"] = pie and canary
            analyzed.append(entry)
        else:
            undetermined.append(entry)

    # ----- verdict -----
    if not records:
        verdict = "N/A"
    elif not analyzed and undetermined:
        verdict = "INCONCLUSIVE"
    else:
        failing = [e for e in analyzed if not e["compliant"]]
        verdict = "FAIL" if failing else "PASS"
    result["verdict"] = verdict

    # ----- evidence_table (one L1 row per native binary) -----
    idx = 0
    for e in analyzed:
        idx += 1
        if e["compliant"]:
            desc = (f"Native library {e['path']} ({e['arch']}) has PIE/PIC enabled "
                    f"and stack-smashing protection (stack canary) present. Compliant.")
        else:
            missing = [n for n, v in (("PIE/PIC", e["pie"]),
                                      ("stack canary", e["stack_canary"])) if not v]
            desc = (f"Native library {e['path']} ({e['arch']}) is MISSING "
                    f"{' and '.join(missing)} (pie={e['pie']}, stack_canary={e['stack_canary']}).")
        result["evidence_table"].append({
            "id": e["id"],
            "description": desc,
            "reference": f"native_binaries#{e['id']}.security_features",
            "level": 1,
        })
    for e in undetermined:
        idx += 1
        result["evidence_table"].append({
            "id": e["id"],
            "description": (f"Native library {e['path']} could not be evaluated: "
                            f"security_features.pie / stack_canary not present in the evidence. "
                            f"Protection status undetermined."),
            "reference": f"native_binaries#{e['id']}.security_features",
            "level": 1,
        })

    # ----- rationale -----
    if verdict == "N/A":
        result["rationale"] = ("The APK contains no native libraries (the native_binaries "
                               "evidence has no records). The compiler-protection requirement "
                               "does not apply, so the verdict is N/A.")
    elif verdict == "INCONCLUSIVE":
        result["rationale"] = (f"{len(undetermined)} native library record(s) were present but "
                               f"did not carry the pie/stack_canary fields, so no protection "
                               f"status could be determined; the verdict is INCONCLUSIVE.")
    elif verdict == "PASS":
        result["rationale"] = (f"All {len(analyzed)} native library/libraries have PIE/PIC and "
                               f"stack-smashing protection (stack canary) enabled. Compiler "
                               f"security features are present across all binaries; verdict PASS.")
    else:  # FAIL
        failing = [e for e in analyzed if not e["compliant"]]
        parts = []
        for e in failing:
            missing = [n for n, v in (("PIE/PIC", e["pie"]),
                                      ("stack canary", e["stack_canary"])) if not v]
            parts.append(f"{e['path']} ({e['arch']}) missing {', '.join(missing)}")
        rationale = (f"{len(failing)} of {len(analyzed)} native binaries lack a required "
                     f"compiler protection: " + "; ".join(parts) + ". "
                     f"PIE/PIC and stack-smashing protection must both be enabled on every "
                     f"native binary, so the verdict is FAIL.")
        if undetermined:
            rationale += f" Additionally, {len(undetermined)} record(s) could not be evaluated."
        rationale += (" Note: if a failing binary is a third-party native library that "
                      "legitimately cannot be compiled with these protections (e.g. a tiny stub "
                      "with no stack buffers) and this is documented, an assessor may downgrade "
                      "to N/A with justification.")
        result["rationale"] = rationale

    print(result)
    return result