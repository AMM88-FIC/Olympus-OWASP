from pathlib import Path


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for CODE-1-1.

    The dict shape mirrors the LLM-test output: every field the verdict
    engine writes to disk for an LLM run must also appear here, so
    downstream consumers (the report generator, etc.) can treat
    programmatic and LLM verdicts uniformly.
    """

    result = {
        "test_id": "CODE-1-1", 
        "verdict": "", 
        "certainty_percent": 100,
        "evidence_table": [],
        "rationale": "",
        }

    return result