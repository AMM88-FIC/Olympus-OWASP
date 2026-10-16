"""
verifier.py — Optional verdict verifier ("second opinion") for the engine.

When enabled, after the analyst session produces a verdict, a SEPARATE,
stateless LLM call reviews it: does the cited evidence and the rationale
actually support the stated verdict and certainty? Is it self-consistent?

The verifier sees only the verdict (and optionally the test prompt) — not the
raw app evidence — so it judges the verdict's INTERNAL soundness, not ground
truth. If it rejects, its comments are nudged back into the original analyst
session, which still holds the full evidence/tool context and can revise.

This module is backend-agnostic: it is handed a ``backend_factory`` (a
zero-arg callable returning a fresh Backend whose system prompt is the
verifier prompt). Each review uses a fresh session, so a single Verifier
instance is safe to share across worker threads.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import ujson


# ============================================================
#  Default verifier system prompt
# ============================================================

DEFAULT_VERIFIER_SYSTEM_PROMPT = """\
You are a senior application-security reviewer acting as a verifier. You \
receive ONE structured verdict produced by an automated Android static- \
analysis engine for a single OWASP MASTG test case. Your job is to judge \
whether the verdict is internally sound.

You do NOT have access to the raw app evidence. Judge only what is in the \
verdict object: do the rows in `evidence_table` and the `rationale` \
logically support the stated `verdict` and `certainty_percent`? Is the \
verdict self-consistent and free of contradictions? Are required fields \
present and coherent?

Reject (acceptable=false) when, for example:
  - the rationale does not actually support the verdict, or contradicts it;
  - certainty is high but the cited evidence is thin, irrelevant, or empty;
  - the evidence_table is empty/placeholder while a confident verdict is \
claimed;
  - required fields are missing, malformed, or mutually inconsistent;
  - the conclusion overreaches what the evidence can support.

Be strict but fair: if the verdict is coherent and adequately supported by \
its own cited evidence and reasoning, accept it.

Respond with ONLY a JSON object, no prose, no markdown fences:
{
  "acceptable": true | false,
  "comments": "<empty string if acceptable; otherwise specific, actionable \
concerns the analyst must address to make the verdict defensible>"
}
"""


# ============================================================
#  Result type
# ============================================================

@dataclass
class ReviewResult:
    acceptable: bool
    comments: str
    raw: str
    parse_error: bool = False
    usage: dict = field(default_factory=dict)


def _usage_dict(usage) -> dict:
    """Flatten a backend Usage object to a dict, dropping None fields."""
    if usage is None:
        return {}
    return {
        k: v for k, v in {
            "prompt_tokens": getattr(usage, "prompt_tokens", None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "total_tokens": getattr(usage, "total_tokens", None),
            "cached_tokens": getattr(usage, "cached_tokens", None),
        }.items() if v is not None
    }


# ============================================================
#  Lenient JSON parsing of the verifier's reply
# ============================================================

def _parse_review(text: str) -> ReviewResult:
    """Parse the verifier's reply. Fails OPEN (acceptable=True) on unparseable
    output so a flaky verifier never blocks a run or loops forever."""
    if not text or not text.strip():
        return ReviewResult(True, "", text or "", parse_error=True)
    cleaned = text.strip()
    cleaned = re.sub(r"<\|[^|]*\|>\w*", "", cleaned).strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if "\n" in cleaned:
            cleaned = cleaned.split("\n", 1)[1]
        if "```" in cleaned:
            cleaned = cleaned.rsplit("```", 1)[0]
        cleaned = cleaned.strip()

    first_brace = cleaned.find("{")
    if first_brace < 0:
        return ReviewResult(True, "", text, parse_error=True)
    try:
        parsed, _ = json.JSONDecoder().raw_decode(cleaned, first_brace)
    except Exception:
        return ReviewResult(True, "", text, parse_error=True)
    if not isinstance(parsed, dict) or "acceptable" not in parsed:
        return ReviewResult(True, "", text, parse_error=True)

    acceptable = bool(parsed.get("acceptable"))
    comments = str(parsed.get("comments") or "").strip()
    return ReviewResult(acceptable=acceptable, comments=comments, raw=text)


# ============================================================
#  Verifier
# ============================================================

class Verifier:
    """Stateless verdict reviewer. ``backend_factory()`` must return a fresh
    Backend configured with the verifier system prompt."""

    def __init__(
        self,
        *,
        backend_factory,
        max_rounds: int = 1,
        include_test_prompt: bool = True,
        verbose: bool = False,
        log_fn=None,
    ):
        self.backend_factory = backend_factory
        # Number of revision attempts. 0 = review-only (audit): the verdict is
        # reviewed and the outcome recorded, but the analyst is never asked to
        # revise. 1+ = that many review→revise→re-review cycles.
        self.max_rounds = max(0, int(max_rounds))
        self.include_test_prompt = include_test_prompt
        self.verbose = verbose
        self.log = log_fn or (lambda *a, **k: None)

    # ---------- the review call ----------

    def review(self, verdict: dict, *, test_prompt: str | None = None) -> ReviewResult:
        backend = self.backend_factory()
        request = self._build_request(verdict, test_prompt)

        if self.verbose:
            self._log_block("Verifier ► request sent", request)

        try:
            result = backend.send_user_message(request, label="verifier")
        except Exception as exc:  # noqa: BLE001 — never let the verifier crash a test
            self.log(f"    ⚠ verifier call failed ({type(exc).__name__}: "
                     f"{exc}); treating verdict as acceptable.", color="yellow")
            return ReviewResult(True, "", f"<error: {exc}>", parse_error=True)

        usage = _usage_dict(result.usage)
        if self.verbose:
            cached = (f" cached={usage['cached_tokens']}"
                      if "cached_tokens" in usage else "")
            self.log(
                f"  ► verifier tokens: "
                f"prompt={usage.get('prompt_tokens', '?')} "
                f"completion={usage.get('completion_tokens', '?')} "
                f"total={usage.get('total_tokens', '?')}{cached}",
                color="cyan",
            )
            self._log_block("Verifier ◄ response", result.text or "<empty>")

        review = _parse_review(result.text)
        review.usage = usage
        return review

    # ---------- verbose logging ----------

    def _log_block(self, title: str, body: str) -> None:
        bar = "─" * max(4, 52 - len(title))
        self.log(f"  ┌─ {title} {bar}", color="dim")
        for line in ((body or "").splitlines() or [""]):
            self.log(f"  │ {line}", color="dim")
        self.log("  └" + "─" * 54, color="dim")

    # ---------- request / nudge text ----------

    def _build_request(self, verdict: dict, test_prompt: str | None) -> str:
        verdict_json = ujson.dumps(verdict, indent=2)
        parts = []
        if self.include_test_prompt and test_prompt:
            parts.append(
                "=== Test case the analyst was assessing ===\n"
                + test_prompt.strip()
            )
        parts.append("=== Verdict to review ===\n" + verdict_json)
        parts.append(
            "Review the verdict per your instructions and respond with the "
            "JSON object {\"acceptable\": bool, \"comments\": str}."
        )
        return "\n\n".join(parts)

    def build_nudge(self, review: ReviewResult) -> str:
        """Message sent back into the analyst session when a verdict is
        rejected, asking it to revise."""
        return (
            "An independent reviewer assessed your verdict and did NOT accept "
            "it. Their concerns:\n\n"
            f"{review.comments}\n\n"
            "Please address these concerns directly. You may use the available "
            "tools to gather or re-check evidence if needed, then emit a "
            "corrected FINAL verdict JSON with all required fields (verdict, "
            "certainty_percent, evidence_table, rationale, etc.). Output only "
            "the verdict JSON."
        )
