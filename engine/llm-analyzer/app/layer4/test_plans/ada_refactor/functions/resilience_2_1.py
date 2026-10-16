from pathlib import Path

try:
    import ujson as json
except ImportError:
    import json


# ---------------------------------------------------------------------------
# Test: production build disables debug symbols (native binaries)
# MSTG-CODE-3 / MASVS-CODE-4
#
# Reads native_binaries.json (top-level "records" array; each record carries
# security_features.symbols_stripped as a boolean, and usually a top-level
# "stripped" flag). No ELF parsing - the extractor already pulled the fact.
#
# PASS - every native .so has its symbols stripped (no debug symbols that aid
#        static analysis), OR there are no native libraries (no debug symbols
#        present at all -> requirement vacuously satisfied).
# FAIL - at least one native .so retains debug symbols (symbols_stripped false).
# INCONCLUSIVE - records exist but none carry the symbols_stripped field.
#
# SCOPE: this decides the NATIVE-binary symbol-strip status, which is what the
# native_binaries evidence contains. Java/DEX debug info and android:debuggable
# are not in this evidence file and are out of scope for this script.
#
# Third-party libraries that cannot be stripped must be DOCUMENTED (per the
# spec). That justification is an out-of-artifact fact a static check cannot
# decide, so this script reports the technical FAIL and names the offending
# binaries for a human to apply any documented justification.
# ---------------------------------------------------------------------------


def _binary_path(record):
    paths = record.get("paths")
    if isinstance(paths, list) and paths:
        return paths[0]
    src = record.get("source") or {}
    if src.get("path"):
        return src["path"]
    return record.get("name", "(unknown)")


def _stripped_value(record):
    """Return the symbols-stripped boolean, or None if not present.

    Prefers security_features.symbols_stripped; falls back to the top-level
    'stripped' flag if the nested one is absent.
    """
    sf = record.get("security_features") or {}
    val = sf.get("symbols_stripped")
    if isinstance(val, bool):
        return val
    top = record.get("stripped")
    if isinstance(top, bool):
        return top
    return None


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for the debug-symbols-stripped (native) test.

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

    analyzed = []      # records with a usable symbols_stripped boolean
    undetermined = []  # records missing the field
    for rec in records:
        stripped = _stripped_value(rec)
        entry = {
            "id": rec.get("id", "?"),
            "path": _binary_path(rec),
            "arch": rec.get("machine") or (rec.get("abis") or ["?"])[0],
            "stripped": stripped,
        }
        if isinstance(stripped, bool):
            entry["compliant"] = stripped
            analyzed.append(entry)
        else:
            undetermined.append(entry)

    # ----- verdict -----
    # No N/A in this test's spec: no native libraries means no debug symbols
    # are present, so the production build satisfies the requirement -> PASS.
    if not records:
        verdict = "PASS"
    elif not analyzed and undetermined:
        verdict = "INCONCLUSIVE"
    else:
        retaining = [e for e in analyzed if not e["compliant"]]
        verdict = "FAIL" if retaining else "PASS"
    result["verdict"] = verdict

    # ----- evidence_table (one L1 row per native binary) -----
    for e in analyzed:
        if e["compliant"]:
            desc = (f"Native library {e['path']} ({e['arch']}) is stripped "
                    f"(symbols_stripped=true): no debug symbols. Compliant.")
        else:
            desc = (f"Native library {e['path']} ({e['arch']}) RETAINS debug symbols "
                    f"(symbols_stripped=false), aiding static analysis.")
        result["evidence_table"].append({
            "id": e["id"],
            "description": desc,
            "reference": f"native_binaries#{e['id']}.security_features.symbols_stripped",
            "level": 1,
        })
    for e in undetermined:
        result["evidence_table"].append({
            "id": e["id"],
            "description": (f"Native library {e['path']} could not be evaluated: "
                            f"symbols_stripped / stripped not present in the evidence. "
                            f"Debug-symbol status undetermined."),
            "reference": f"native_binaries#{e['id']}.security_features.symbols_stripped",
            "level": 1,
        })

    # ----- rationale -----
    if verdict == "PASS" and not records:
        result["rationale"] = ("The APK contains no native libraries, so no native debug "
                               "symbols are present; the production build satisfies the "
                               "requirement. Verdict PASS. (Scope: native binaries only.)")
    elif verdict == "INCONCLUSIVE":
        result["rationale"] = (f"{len(undetermined)} native library record(s) were present but "
                               f"did not carry the symbols_stripped field, so the debug-symbol "
                               f"status could not be determined; the verdict is INCONCLUSIVE.")
    elif verdict == "PASS":
        result["rationale"] = (f"All {len(analyzed)} native library/libraries are stripped of "
                               f"debug symbols (symbols_stripped=true). The production build "
                               f"contains no native debug symbols; verdict PASS. "
                               f"(Scope: native binaries only.)")
    else:  # FAIL
        retaining = [e for e in analyzed if not e["compliant"]]
        names = "; ".join(f"{e['path']} ({e['arch']})" for e in retaining)
        rationale = (f"{len(retaining)} of {len(analyzed)} native binaries retain debug symbols "
                     f"(symbols_stripped=false): " + names + ". "
                     f"The production build must not ship native debug symbols, so the verdict "
                     f"is FAIL.")
        if undetermined:
            rationale += f" Additionally, {len(undetermined)} record(s) could not be evaluated."
        rationale += (" Note: third-party native libraries that cannot be stripped must be "
                      "documented; if a failing binary is such a documented case, an assessor "
                      "may downgrade accordingly. (Scope: native binaries only.)")
        result["rationale"] = rationale

    print(result)
    return result