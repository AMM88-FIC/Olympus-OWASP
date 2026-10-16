"""
olympus/client.py — adapter over Olympus's test output.

This is the ONLY module that is allowed to know what Olympus's output looks
like. Everything downstream consumes `OlympusTestOutput`, so when the real
format is confirmed, `normalize_olympus_output` is the one function to change
and nothing else moves.

What is known today (from the maintainer, 2026-09-10):

  - Olympus emits files or CLI text now, and will probably return JSON.
  - Its test identifiers are expected to line up with the plan's test ids
    (MASTG-TEST-XXXX). If they turn out not to, the mapping belongs HERE, as
    an id-translation step — not scattered through the validator.

Everything marked ASSUMPTION below is a guess that has not been confirmed.
They are written down rather than absorbed silently so that confirming the
format is a matter of checking a short list.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


class OlympusError(Exception):
    """Raised when Olympus output cannot be located or understood. The
    validator surfaces this rather than validating against nothing."""


# ============================================================
#  Normalised view
# ============================================================

@dataclass
class OlympusTestOutput:
    """One finished Olympus test result, normalised.

    `raw` is always the untouched payload as received. The validator sends
    `raw` to the model — the model should judge what Olympus actually said, not
    this adapter's interpretation of it. The typed fields exist for routing and
    logging, and are best-effort.
    """
    test_id: str
    raw: dict | str
    verdict: str | None = None
    rationale: str | None = None
    finished: bool = True
    source_path: Path | None = None
    warnings: list[str] = field(default_factory=list)

    def as_text(self) -> str:
        """Render the raw payload for inclusion in a prompt."""
        if isinstance(self.raw, str):
            return self.raw
        return json.dumps(self.raw, indent=2, ensure_ascii=False)


# ASSUMPTION: if Olympus returns JSON, a verdict-ish field will be spelled one
# of these. Used only for logging/routing; `raw` is what reaches the model, so
# guessing wrong here degrades a log line, not the analysis.
_VERDICT_KEYS = ("verdict", "result", "status", "outcome")
_RATIONALE_KEYS = ("rationale", "reason", "explanation", "details", "summary")
_TEST_ID_KEYS = ("test_id", "testId", "id", "test", "case_id")


def _first_str(payload: dict, keys) -> str | None:
    for k in keys:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def normalize_olympus_output(
    raw: dict | str | bytes, *, test_id: str = "", source_path: Path | None = None,
) -> OlympusTestOutput:
    """Map whatever Olympus produced onto `OlympusTestOutput`.

    **This is the single mapping point for Olympus's format.** It is
    deliberately permissive: an unrecognised shape is carried through in `raw`
    with a warning rather than rejected, because the model can read prose that
    this function cannot parse, and a validation run should not fail because a
    key was renamed.
    """
    warnings: list[str] = []

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OlympusError(f"Olympus output is not UTF-8: {exc}") from exc

    # CLI-text path: try JSON first, keep the text if it isn't.
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                raw = json.loads(text)
            except json.JSONDecodeError:
                warnings.append(
                    "Output looked like JSON but did not parse; kept as text."
                )
        else:
            warnings.append(
                "Output is plain text, not JSON — typed fields unavailable, "
                "raw text forwarded to the model."
            )

    if isinstance(raw, list):
        # ASSUMPTION: a list means "records for one test"; wrap it so the shape
        # downstream is always a dict or a string.
        raw = {"records": raw}
        warnings.append("Output was a JSON array; wrapped as {'records': [...]}.")

    if isinstance(raw, dict):
        resolved_id = test_id or _first_str(raw, _TEST_ID_KEYS) or ""
        return OlympusTestOutput(
            test_id=resolved_id,
            raw=raw,
            verdict=_first_str(raw, _VERDICT_KEYS),
            rationale=_first_str(raw, _RATIONALE_KEYS),
            source_path=source_path,
            warnings=warnings,
        )

    return OlympusTestOutput(
        test_id=test_id,
        raw=raw,
        source_path=source_path,
        warnings=warnings,
    )


# ============================================================
#  Client protocol
# ============================================================

@runtime_checkable
class OlympusClient(Protocol):
    """The narrowest surface the validator needs.

    Kept deliberately small: three methods, no lifecycle, no configuration.
    A real client (reading Olympus's output directory, calling its API, or
    talking to it in-process once embedded) satisfies this by implementing
    these three.
    """

    def list_available(self) -> list[str]:
        """Test ids for which Olympus has produced output."""
        ...

    def is_finished(self, test_id: str) -> bool:
        """True when Olympus has finished this test and its output is
        complete. The validator refuses to validate an unfinished test."""
        ...

    def get_test_output(self, test_id: str) -> OlympusTestOutput:
        """Return the normalised output. Raises OlympusError if absent."""
        ...


# ============================================================
#  Mock client
# ============================================================

class MockOlympusClient:
    """Reads Olympus output from a fixture directory: `<root>/<test_id>.json`
    (or `.txt`). Satisfies `OlympusClient`.

    This exists so the whole validation path is buildable and testable before
    Olympus's real format is settled — and it stays useful afterwards as the
    test double for the validator's own unit tests.
    """

    SUFFIXES = (".json", ".txt")

    def __init__(self, root: Path | str):
        self.root = Path(root)

    def _path_for(self, test_id: str) -> Path | None:
        # Guard the id: it reaches the filesystem, and a test id is a plain
        # identifier — never a path. Mirrors APKNavigator's stance on paths
        # supplied from outside.
        if not test_id or "/" in test_id or "\\" in test_id or ".." in test_id:
            raise OlympusError(f"Invalid test id: {test_id!r}")
        for suffix in self.SUFFIXES:
            candidate = self.root / f"{test_id}{suffix}"
            if candidate.is_file():
                return candidate
        return None

    def list_available(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted({
            p.stem for p in self.root.iterdir()
            if p.is_file() and p.suffix in self.SUFFIXES
        })

    def is_finished(self, test_id: str) -> bool:
        return self._path_for(test_id) is not None

    def get_test_output(self, test_id: str) -> OlympusTestOutput:
        path = self._path_for(test_id)
        if path is None:
            raise OlympusError(
                f"No Olympus output for {test_id!r} under {self.root}. "
                f"Available: {', '.join(self.list_available()) or '(none)'}"
            )
        return normalize_olympus_output(
            path.read_text(encoding="utf-8"),
            test_id=test_id,
            source_path=path,
        )
