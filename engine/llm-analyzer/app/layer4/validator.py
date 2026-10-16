"""
validator.py — gap validation over Olympus output.

Two things live here, and nothing else:

  build_validation_prefix(output)   turn an Olympus result into the text that
                                    goes in front of the test's own prompt
  GapValidator.preflight(config)    refuse to validate when it would be
                                    meaningless (no evidence, no APK)

The actual running is `EngineAPI.validate()`, which calls the ordinary engine
with that prefix. There is no separate validation pipeline, because validation
is not a separate pipeline: it is the existing per-test flow with a re-scoped
system prompt and one extra input. Evidence delivery, the 13 navigator tools,
the schema, verdict parsing, retry and recovery are all reused untouched.

Why full evidence access rather than reviewing the output on its own: **a gap is
by definition absent from the output.** You cannot detect an omission by reading
only what was written — you need to see what was there to be found. Reviewing
the output in isolation (which `app/layer4/verifier.py` does, for the in-session
case) can catch internal inconsistency but never "Olympus never looked at X",
which is the whole point here.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.layer4.verdict_engine import RunConfig
from app.olympus import OlympusTestOutput


VALIDATION_PREFIX_TEMPLATE = """\
# Existing analysis to verify

Another static-analysis tool (Olympus) has already evaluated this test case on \
this application and produced the result below. Your task is NOT to repeat its \
work uncritically, and NOT to trust it.

Verify it. Using the evidence files and the navigator tools available to you, \
establish for yourself whether every check this test case requires was \
actually performed, and whether the conclusions drawn are supported by the \
application's actual code and configuration.

Pay particular attention to what is MISSING. A conclusion can be internally \
coherent and still rest on checks that were never carried out — those gaps are \
the primary thing you are looking for. Where you find one, perform the missing \
check yourself and let it inform your final answer.

## Olympus result for {test_id}

```
{olympus_output}
```

{warning_block}
---

# Test case

What follows is the test case specification. Apply it in full.

"""

_WARNING_TEMPLATE = """\
> Note on the result above: {warnings}
> Treat it as potentially incomplete and rely on your own verification.

"""


def build_validation_prefix(output: OlympusTestOutput) -> str:
    """Render the Olympus output as a prompt prefix.

    The RAW payload is what reaches the model, deliberately: the adapter's
    typed fields are best-effort guesses about a format that is not finalised,
    and the model should judge what Olympus actually said rather than this
    code's interpretation of it.
    """
    warning_block = (
        _WARNING_TEMPLATE.format(warnings="; ".join(output.warnings))
        if output.warnings else ""
    )
    return VALIDATION_PREFIX_TEMPLATE.format(
        test_id=output.test_id or "(unknown test id)",
        olympus_output=output.as_text(),
        warning_block=warning_block,
    )


class GapValidator:
    """Namespace for validation checks. Stateless — nothing to construct."""

    @staticmethod
    def preflight(config: RunConfig) -> list[str]:
        """Return human-readable reasons validation would be meaningless.

        Evidence is the one that matters: this approach is only as good as the
        evidence the model can reach, and validating against an empty evidence
        directory would produce confident-looking output backed by nothing.
        Fail loudly instead of quietly.
        """
        problems: list[str] = []

        evidence_dir = config.evidence_dir
        if not evidence_dir or not Path(evidence_dir).is_dir():
            problems.append(f"Evidence directory not found: {evidence_dir}")
        elif not any(Path(evidence_dir).glob("*.json")):
            problems.append(
                f"Evidence directory {evidence_dir} contains no *.json — "
                f"validation would run with no evidence to check against."
            )

        if not config.apk_root or not Path(config.apk_root).is_dir():
            problems.append(f"APK root not found: {config.apk_root}")

        return problems


# ============================================================
#  Review-block invariants
# ============================================================

OBFUSCATED_CERTAINTY_CAP = 70


def _is_obfuscated(evidence_dir: Path | str | None) -> bool | None:
    """Read `obfuscation.is_obfuscated`. None when unknown."""
    if not evidence_dir:
        return None
    path = Path(evidence_dir) / "obfuscation.json"
    if not path.is_file():
        return None
    try:
        return bool(json.loads(path.read_text(encoding="utf-8"))
                    .get("is_obfuscated"))
    except (json.JSONDecodeError, OSError):
        return None


def check_review_invariants(
    verdict: dict,
    prior_verdict: str | None,
    *,
    evidence_dir: Path | str | None = None,
) -> list[str]:
    """Return the ways a review verdict contradicts itself.

    The reviewer system prompt states these rules under "Self-verification
    before emitting". A prompt cannot enforce anything, and a model that has not
    done the work will still emit a confident answer — the observed failure was
    `verdict: not_applicable`, `certainty_percent: 100`, `evidence_table: []`,
    and a discrepancy with `evidence_ids: []`, which every rule below rejects.
    Empty citations are the reliable tell: a model that actually inspected the
    evidence has record IDs to name.

    Returns [] when the verdict is self-consistent. Callers decide whether to
    reject, retry, or record.
    """
    problems: list[str] = []
    table = verdict.get("evidence_table") or []
    certainty = verdict.get("certainty_percent")
    review = verdict.get("review") or {}
    agreement = (review.get("agreement") or "").strip().lower()
    discrepancies = review.get("discrepancies") or []

    if isinstance(certainty, (int, float)) and certainty >= 90 and not table:
        problems.append(
            f"certainty_percent is {certainty} but evidence_table is empty — "
            f"high confidence requires cited evidence"
        )

    for i, d in enumerate(discrepancies):
        if not isinstance(d, dict):
            problems.append(f"discrepancies[{i}] is not an object")
            continue
        dtype = (d.get("type") or "").strip().lower()
        if dtype in ("omission", "unsupported") and not (d.get("evidence_ids") or []):
            problems.append(
                f"discrepancies[{i}] is {dtype!r} with no evidence_ids — a "
                f"claim about what the evidence does or does not contain must "
                f"cite the records that establish it"
            )

    if agreement == "confirmed" and discrepancies:
        problems.append(
            "agreement is 'confirmed' but discrepancies is non-empty — use "
            "'confirmed_with_gaps' or 'corrected'"
        )

    own = (verdict.get("verdict") or "").strip().lower()
    prior = (prior_verdict or "").strip().lower()
    if prior and own and own != prior:
        if not discrepancies:
            problems.append(
                f"verdict {own!r} differs from the prior verdict {prior!r} but "
                f"no discrepancy is recorded — a silent disagreement is not a "
                f"review"
            )
        elif not any(d.get("changes_verdict") for d in discrepancies
                     if isinstance(d, dict)):
            problems.append(
                f"verdict {own!r} differs from the prior verdict {prior!r} but "
                f"no discrepancy is marked changes_verdict"
            )

    if agreement == "corrected" and prior and own and own == prior:
        problems.append(
            f"agreement is 'corrected' but the verdict {own!r} matches the "
            f"prior verdict"
        )

    # --- certainty calibration, per the prompt's own numeric caps ---
    #
    # "Calibrating certainty" states hard caps, not preferences. A model can
    # reach the right verdict and still ignore them: the observed run answered
    # MASTG-TEST-0232 correctly with `certainty_percent: 100` on an app whose
    # obfuscation.json says is_obfuscated=true, where the cap is 70. An
    # unjustified 100 is worse than a wrong verdict caught early, because a
    # reader has no reason to look twice.
    if isinstance(certainty, (int, float)):
        if certainty >= 90 and not (verdict.get("false_positive_risks") or []):
            problems.append(
                f"certainty_percent is {certainty} but false_positive_risks is "
                f"empty — at that band the prompt requires a stated reason no "
                f"plausible failure mode exists"
            )
        obfuscated = _is_obfuscated(evidence_dir)
        if obfuscated and certainty > OBFUSCATED_CERTAINTY_CAP:
            problems.append(
                f"certainty_percent is {certainty} but the app is obfuscated "
                f"(obfuscation.is_obfuscated=true), where 'Calibrating "
                f"certainty' caps it at {OBFUSCATED_CERTAINTY_CAP}"
            )

    return problems
