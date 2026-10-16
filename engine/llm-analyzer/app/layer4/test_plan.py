"""
Test plan manifest loader.

A test plan is a self-contained collection of test cases that the
verdict engine can run against an APK. Plans live under
`app/layer4/test_plans/<plan_name>/` and consist of:

  tests.toml      - manifest mapping test IDs to handlers
  prompts/        - LLM prompt files (.md), referenced by 'llm' entries
  functions/      - Python handler modules, referenced by 'programmatic' entries

The manifest format:

    name = "ADA Refactor v1"       # optional human-readable name
    version = "2026.5"             # optional plan version

    [tests.1-STORAGE-1-1]
    type = "llm"
    prompt = "1-STORAGE-1-1.md"

    [tests.CODE-1-1]
    type = "programmatic"
    handler = "code_1_1.run"       # imports functions/code_1_1.py, calls run()

The TOML section name (e.g. `1-STORAGE-1-1`) is the test_id used
throughout the engine: it appears in logs, becomes the output filename
(`<test_id>.json`), and is what `test_filter` matches against.
"""
from __future__ import annotations

import importlib
import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


# ============================================================
#  Verdict source (see TestEntry.source)
# ============================================================

SOURCE_ENGINE = "engine"    # this engine produces the verdict (default)
SOURCE_OLYMPUS = "olympus"  # Olympus produced it; we validate it for gaps

VALID_SOURCES = (SOURCE_ENGINE, SOURCE_OLYMPUS)


class TestPlanError(Exception):
    """Raised when a test plan manifest is malformed, missing, or
    references things that don't exist (e.g. missing prompt file,
    missing handler module, unknown test type). The caller surfaces
    this to the user and aborts the run — the engine can't sensibly
    continue with a broken plan."""


@dataclass
class TestEntry:
    """One test in a plan.

    Fields populated by type:
      llm:          test_id, type, prompt_path; handler is None
      programmatic: test_id, type, handler; prompt_path is None

    `category` is an optional free-text label (e.g. "STORAGE", "CRYPTO")
    declared in the manifest. It does not affect execution, but the test
    filter matches against it as well as `test_id`, so a user can select a
    whole MASVS category with `--test-filter crypto`. Empty when the
    manifest omits it (older plans).

    `source` says WHERE THE INITIAL VERDICT COMES FROM, which is a different
    axis from `type` (which says HOW WE EXECUTE a test):

      source = "engine"   this engine produces the verdict — the default, and
                          what every plan predating this field does.
      source = "olympus"  Olympus produced the verdict; this engine validates
                          it for gaps instead of running the test cold.

    The two are orthogonal: an Olympus-sourced test that gets validated with
    full evidence access is *executed* by the LLM but *sourced* from Olympus.
    Deliberately not spelled "llm" — `type` already uses that word for the
    other axis, and two keys sharing a value with different meanings would
    misread badly in the manifest.
    """
    test_id: str
    type: str                        # "llm" | "programmatic"
    prompt_path: Path | None = None
    handler: Callable | None = None
    category: str = ""
    source: str = SOURCE_ENGINE


@dataclass
class TestPlan:
    """A loaded test plan. `entries` preserves the order they appear in
    the manifest, which is the order in which tests run."""
    name: str
    plan_dir: Path
    entries: list[TestEntry]

    @property
    def prompts_dir(self) -> Path:
        return self.plan_dir / "prompts"

    @property
    def functions_dir(self) -> Path:
        return self.plan_dir / "functions"


def load_test_plan(plan_dir: Path) -> TestPlan:
    """Load and validate a test plan from its directory.

    Raises TestPlanError on any structural problem; the caller should
    surface that to the user and abort the run. Validation includes:
      - manifest file exists and parses
      - at least one [tests.*] entry exists
      - every entry has a recognized type
      - llm entries point at existing prompt files
      - programmatic entries reference importable handler modules
    """
    plan_dir = Path(plan_dir).resolve()
    manifest_path = plan_dir / "tests.toml"

    if not manifest_path.is_file():
        raise TestPlanError(
            f"Test plan manifest not found: {manifest_path}"
        )

    try:
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise TestPlanError(
            f"Malformed TOML in {manifest_path}: {exc}"
        ) from exc

    tests = data.get("tests") or {}
    if not tests:
        raise TestPlanError(
            f"No [tests.*] entries in {manifest_path}. A plan must "
            f"declare at least one test."
        )

    plan_name = data.get("name") or plan_dir.name
    entries: list[TestEntry] = []

    for test_id, spec in tests.items():
        if not isinstance(spec, dict):
            raise TestPlanError(
                f"Test {test_id!r}: expected a TOML table, got "
                f"{type(spec).__name__}"
            )
        ttype = spec.get("type")
        if ttype == "llm":
            entries.append(_load_llm_entry(test_id, spec, plan_dir))
        elif ttype == "programmatic":
            entries.append(_load_programmatic_entry(test_id, spec, plan_dir))
        else:
            raise TestPlanError(
                f"Test {test_id!r}: unknown type {ttype!r}. Must be "
                f"'llm' or 'programmatic'."
            )

    return TestPlan(name=plan_name, plan_dir=plan_dir, entries=entries)


def filter_entries(
    entries: list[TestEntry], test_filter: str,
) -> list[TestEntry]:
    """Apply a case-insensitive substring filter to test IDs (and the
    entry's `category` label). Empty filter passes everything through.
    Matching either field means `--test-filter crypto` selects a whole
    category while `--test-filter 0202` still selects a single test.
    Matches the semantics of the old `prompts_mask` glob (`*{mask}*.md`)."""
    if not test_filter:
        return entries
    needle = test_filter.lower()
    return [
        e for e in entries
        if needle in e.test_id.lower() or needle in (e.category or "").lower()
    ]


# ============================================================
#  Internal helpers
# ============================================================

def _load_llm_entry(test_id: str, spec: dict, plan_dir: Path) -> TestEntry:
    prompt_filename = spec.get("prompt")
    if not prompt_filename:
        raise TestPlanError(
            f"Test {test_id!r}: 'llm' type requires a 'prompt' field "
            f"naming the markdown file under prompts/."
        )
    prompt_path = plan_dir / "prompts" / prompt_filename
    if not prompt_path.is_file():
        raise TestPlanError(
            f"Test {test_id!r}: prompt file not found at {prompt_path}."
        )
    source = str(spec.get("source") or SOURCE_ENGINE).strip().lower()
    if source not in VALID_SOURCES:
        raise TestPlanError(
            f"Test {test_id!r}: unknown source {source!r}. Must be one of "
            f"{', '.join(map(repr, VALID_SOURCES))}."
        )
    return TestEntry(
        test_id=test_id, type="llm", prompt_path=prompt_path,
        category=str(spec.get("category") or ""),
        source=source,
    )


def _load_programmatic_entry(
    test_id: str, spec: dict, plan_dir: Path,
) -> TestEntry:
    handler_ref = spec.get("handler")
    if not handler_ref:
        raise TestPlanError(
            f"Test {test_id!r}: 'programmatic' type requires a 'handler' "
            f"field (e.g. 'code_1_1.run' to call run() from "
            f"functions/code_1_1.py)."
        )
    if "." not in handler_ref:
        raise TestPlanError(
            f"Test {test_id!r}: handler {handler_ref!r} must be of form "
            f"'module.function'."
        )

    module_short, function_name = handler_ref.rsplit(".", 1)

    # The plan directory's name becomes part of the Python import path.
    # Hyphens in directory names aren't valid in Python identifiers, so
    # the on-disk directory MUST use underscores (e.g. `ada_refactor/`,
    # not `ada-refactor/`) for programmatic handlers to be importable.
    plan_pkg_name = plan_dir.name
    if "-" in plan_pkg_name:
        raise TestPlanError(
            f"Plan directory name {plan_pkg_name!r} contains hyphens, "
            f"which aren't valid in Python package names. Programmatic "
            f"handlers won't be importable. Rename to use underscores "
            f"(e.g. {plan_pkg_name.replace('-', '_')!r})."
        )

    full_module = (
        f"app.layer4.test_plans.{plan_pkg_name}.functions.{module_short}"
    )

    try:
        module = importlib.import_module(full_module)
    except ImportError as exc:
        raise TestPlanError(
            f"Test {test_id!r}: failed to import handler module "
            f"{full_module}: {exc}"
        ) from exc

    handler = getattr(module, function_name, None)
    if handler is None or not callable(handler):
        raise TestPlanError(
            f"Test {test_id!r}: function {function_name!r} not found "
            f"(or not callable) in module {full_module}."
        )

    source = str(spec.get("source") or SOURCE_ENGINE).strip().lower()
    if source not in VALID_SOURCES:
        raise TestPlanError(
            f"Test {test_id!r}: unknown source {source!r}. Must be one of "
            f"{', '.join(map(repr, VALID_SOURCES))}."
        )
    return TestEntry(
        test_id=test_id, type="programmatic", handler=handler,
        category=str(spec.get("category") or ""),
        source=source,
    )