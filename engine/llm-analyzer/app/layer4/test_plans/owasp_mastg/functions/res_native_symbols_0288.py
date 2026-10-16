"""MASTG-TEST-0288: Debugging Symbols in Native Binaries.

Deterministic check over native_binaries.json (Layer 3), so this is a
programmatic handler rather than an LLM prompt. (Mirrors the existing
ada_refactor resilience_3_1 handler.)

OWASP evaluation: the test fails if debugging information is present in any
native binary. Debug symbols expose function/variable names and source
references that aid reverse engineering. The Layer 3 builder records
``security_features.symbols_stripped`` (and a top-level ``stripped``) per .so.

Verdict:
  * ``fail``         - at least one native .so retains debug symbols
                       (symbols_stripped = false).
  * ``pass``         - every native .so is stripped, OR there are no native
                       libraries (no native debug symbols present).
  * ``inconclusive`` - records exist but none carry the stripped field.

Records are de-duplicated by library name (one library, many ABIs).
"""
import json
from pathlib import Path

TEST_ID = "MASTG-TEST-0288"


def _stripped(rec: dict):
    sf = rec.get("security_features") or {}
    val = sf.get("symbols_stripped")
    if isinstance(val, bool):
        return val
    top = rec.get("stripped")
    if isinstance(top, bool):
        return top
    return None


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for MASTG-TEST-0288 (native debugging symbols)."""
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / "native_binaries.json"

    base = {
        "test_id": TEST_ID,
        "certainty_percent": "No-LLM",
        "needs_dynamic_testing": False,
        "false_positive_risks": [],
    }

    if not path.is_file():
        return {**base, "verdict": "pass",
                "evidence_table": [{"id": "sym-000",
                    "description": "No native_binaries.json evidence; the app "
                                   "ships no native libraries, so no native "
                                   "debug symbols are present.",
                    "reference": "native_binaries.json", "level": 1}],
                "rationale": "No native libraries are present, so there are no "
                             "native debug symbols. MASTG-TEST-0288 passes "
                             "vacuously."}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "sym-err",
                    "description": f"Could not parse native_binaries.json: {exc}.",
                    "reference": "native_binaries.json", "level": 1}],
                "rationale": f"native_binaries.json could not be parsed ({exc})."}

    records = data.get("records") or []
    if not records:
        return {**base, "verdict": "pass",
                "evidence_table": [{"id": "sym-000",
                    "description": "native_binaries.json has zero records; no "
                                   "native libraries are present.",
                    "reference": "native_binaries.json#records", "level": 1}],
                "rationale": "No native libraries (0 records); no native debug "
                             "symbols. MASTG-TEST-0288 passes vacuously."}

    seen: dict[str, dict] = {}
    for rec in records:
        name = rec.get("name") or (rec.get("paths") or ["<unknown>"])[0]
        if name not in seen:
            seen[name] = rec

    retaining: list[str] = []   # not stripped -> has debug symbols
    stripped_ok: list[str] = []
    undetermined: list[str] = []
    evidence_table = []
    for name, rec in seen.items():
        st = _stripped(rec)
        paths = rec.get("paths") or []
        ref = (f"native_binaries.json#records[{name}]"
               f".security_features.symbols_stripped")
        if st is True:
            stripped_ok.append(name)
        elif st is False:
            retaining.append(name)
            evidence_table.append({
                "id": f"sym-{len(retaining):03d}",
                "description": (f"Finding: native library '{name}' RETAINS "
                                f"debug symbols (symbols_stripped=false), "
                                f"aiding reverse engineering. "
                                f"({paths[0] if paths else 'unknown path'})"),
                "reference": ref, "level": 1})
        else:
            undetermined.append(name)
            evidence_table.append({
                "id": f"sym-u-{name}",
                "description": (f"Native library '{name}' could not be "
                                f"evaluated: stripped status not in evidence."),
                "reference": ref, "level": 1})

    if stripped_ok:
        evidence_table.append({
            "id": "sym-ok",
            "description": (f"{len(stripped_ok)} native library/libraries are "
                            f"stripped (no debug symbols): "
                            f"{', '.join(sorted(stripped_ok)[:20])}"
                            f"{' ...' if len(stripped_ok) > 20 else ''}."),
            "reference": "native_binaries.json#records", "level": 1})

    if retaining:
        verdict = "fail"
        rationale = (f"{len(retaining)} of {len(seen)} native library/libraries "
                     f"retain debug symbols (symbols_stripped=false): "
                     f"{', '.join(retaining)}. Production native binaries must "
                     f"be stripped; MASTG-TEST-0288 fails."
                     + (f" {len(undetermined)} record(s) were undetermined."
                        if undetermined else ""))
    elif not stripped_ok and undetermined:
        verdict = "inconclusive"
        rationale = (f"{len(undetermined)} native library record(s) lack the "
                     f"stripped field; native debug-symbol status is "
                     f"undetermined.")
    else:
        verdict = "pass"
        rationale = (f"All {len(stripped_ok)} native library/libraries are "
                     f"stripped of debug symbols. MASTG-TEST-0288 passes."
                     + (f" ({len(undetermined)} record(s) undetermined.)"
                        if undetermined else ""))

    return {**base, "verdict": verdict, "evidence_table": evidence_table,
            "rationale": rationale}
