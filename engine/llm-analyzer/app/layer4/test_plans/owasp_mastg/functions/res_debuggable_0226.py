"""MASTG-TEST-0226: Debuggable Flag Enabled in the AndroidManifest.

Deterministic check over manifest_findings.json (Layer 3), so this is a
programmatic handler rather than an LLM prompt. (Mirrors the existing
ada_refactor resilience_2_1 handler.)

OWASP evaluation: the test fails if android:debuggable is explicitly set to
true. A debuggable production build lets attackers attach a debugger, inspect
internals, and bypass controls. If the flag is absent it defaults to false.

Verdict:
  * ``fail``         - flags.debuggable is true.
  * ``pass``         - flags.debuggable is false / absent.
  * ``inconclusive`` - manifest_findings.json missing / no debuggable field.
"""
import json
from pathlib import Path

TEST_ID = "MASTG-TEST-0226"


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for MASTG-TEST-0226 (debuggable flag)."""
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / "manifest_findings.json"

    base = {
        "test_id": TEST_ID,
        "certainty_percent": "No-LLM",
        "needs_dynamic_testing": False,
        "false_positive_risks": [],
    }

    if not path.is_file():
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "dbg-err",
                    "description": "manifest_findings.json not found; the "
                                   "debuggable flag could not be determined.",
                    "reference": "manifest_findings.json", "level": 1}],
                "rationale": "No manifest_findings.json was produced; the "
                             "debuggable flag is undetermined."}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "dbg-err",
                    "description": f"Could not parse manifest_findings.json: {exc}.",
                    "reference": "manifest_findings.json", "level": 1}],
                "rationale": f"manifest_findings.json could not be parsed ({exc})."}

    flags = data.get("flags") or {}
    raw = flags.get("debuggable")
    if raw is None:
        # Field absent -> Android treats debuggable as false by default.
        debuggable = False
        note = " (flag absent; defaults to false)"
    else:
        debuggable = bool(raw)
        note = ""

    verdict = "fail" if debuggable else "pass"
    evidence_table = [{
        "id": "dbg-001",
        "description": f"android:debuggable = {debuggable}{note}.",
        "reference": "manifest_findings.json#flags.debuggable",
        "level": 1,
    }]
    if debuggable:
        rationale = ("The AndroidManifest sets android:debuggable=true. A "
                     "debuggable production build lets an attacker attach a "
                     "debugger, inspect internals, and bypass security controls; "
                     "MASTG-TEST-0226 fails.")
    else:
        rationale = ("android:debuggable is false" + note + ", as expected for "
                     "a production build. MASTG-TEST-0226 passes.")

    return {**base, "verdict": verdict, "evidence_table": evidence_table,
            "rationale": rationale}
