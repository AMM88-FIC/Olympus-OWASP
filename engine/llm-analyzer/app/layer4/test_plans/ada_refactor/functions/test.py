"""
Hello-world programmatic test handler.

Demonstrates the contract a programmatic test must satisfy:

  - Export a callable named in tests.toml (here: `run`)
  - Signature: run(job_id: str, evidence_dir: Path) -> dict
  - Return value: a verdict dict matching the LLM-test output shape

The handler can read evidence files from `evidence_dir` to make decisions,
but does not call the model. Anything you can decide deterministically
from L1 evidence is a candidate for a programmatic test.

This example doesn't actually inspect anything — it just returns a fixed
"pass" verdict so you can verify the framework end-to-end. Replace the
body with real logic once you confirm the dispatch works.
"""
from pathlib import Path


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a hello-world pass verdict.

    The dict shape mirrors the LLM-test output: every field the verdict
    engine writes to disk for an LLM run must also appear here, so
    downstream consumers (the report generator, etc.) can treat
    programmatic and LLM verdicts uniformly.
    """
    return {
        "test_id": "HELLO-WORLD",
        "verdict": "pass",
        "certainty_percent": 100,
        "evidence_table": [
            {
                "id": "hello-001",
                "description": (
                    f"Hello world from the programmatic handler. "
                    f"Job ID: {job_id!r}. "
                    f"Evidence directory: {evidence_dir}."
                ),
                "reference": "functions/hello_world.py:run",
                "level": 1,
            },
        ],
        "rationale": (
            "This is a placeholder programmatic test. It always returns "
            "pass with 100% certainty and does not inspect any evidence. "
            "Its purpose is to verify that the test-plan dispatcher "
            "correctly imports the handler module, invokes the function, "
            "and writes the returned dict to disk under the expected "
            "output filename."
        ),
        "mapped_maswe": [],
        "recommended_mastg_tests": [],
        "needs_dynamic_testing": False,
        "false_positive_risks": [
            "This handler does not inspect any evidence and always "
            "returns pass. It is a framework smoke test, not a real "
            "security assessment.",
        ],
    }