"""
engine_api.py — the one class Olympus talks to.

Olympus is Python and this engine embeds into it as a library, so this module
IS the integration: no CLI, no MCP server, no process boundary.

    from app.engine_api import EngineSettings

    # Configure ONCE for the deployment (no file needed):
    settings = EngineSettings.from_dict({
        "backend": "openai", "model": "qwen3.6:27b",
        "base_url": "http://localhost:11434/v1",
        "test_plan_dir": "app/layer4/test_plans/owasp_mastg",
        "schema":        "app/layer4/prompts/system/2.layer3_schema_v1.2.5_full_spec.md",
        "system_prompt": "app/layer4/prompts/system/1.system_prompt-v1.3.10.md",
    })

    # Then one engine PER APK — evidence_dir/output_dir default off apk_root:
    engine = settings.for_apk("storage/artifacts/my-app")

    # 1. Ask what tests exist
    engine.list_tests("crypto")            # -> [TestInfo, ...]

    # 2. Validate something Olympus already produced
    result = engine.validate("MASTG-TEST-0204", olympus_output=payload)
    result.verdict                          # "pass" | "fail" | ...
    result.gaps_found                       # True if the engine disagreed

    # 3. Or run a test from scratch
    result = engine.run_test("MASTG-TEST-0204")

    # 4. Read the APK directly (the 13 navigator tools)
    engine.call_tool("find_class", {"name": "com.example.Crypto"})

Olympus PUSHES its output in; this engine never calls back into Olympus. That
is why `validate` takes the payload as an argument rather than a client object.

Threading: `EngineAPI` is safe to share. Each call that talks to a model builds
its own backend unless you pass one, because a backend holds conversation state
and sharing one across concurrent tests would interleave two conversations.
"""

from __future__ import annotations

import importlib.util
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.layer4 import runner_config
from app.layer4.apk_navigator import APKNavigator
from app.layer4.test_plan import (
    SOURCE_OLYMPUS, TestEntry, TestPlanError, filter_entries, load_test_plan,
)
from app.layer4.validator import (
    GapValidator, build_validation_prefix, check_review_invariants,
)
from app.layer4.verdict_engine import (
    AttemptRecord, RunConfig, TestStats, _run_one_attempt,
    _verdict_output_path, bootstrap_session, log as _default_log, utc_now,
)
from app.olympus import OlympusTestOutput, normalize_olympus_output


class EngineError(Exception):
    """Base class for every error this facade raises."""


class EngineConfigError(EngineError):
    """Configuration could not be resolved. Replaces the `sys.exit()` calls in
    `runner_config`, which would otherwise kill the host process."""


class TestNotFoundError(EngineError):
    """No test with that id in the loaded plan."""


# ============================================================
#  Value types — plain data, safe to serialise straight out
# ============================================================

@dataclass(frozen=True)
class TestInfo:
    """Catalogue entry for one test."""
    test_id: str
    type: str
    category: str
    source: str
    prompt_file: str | None

    @classmethod
    def from_entry(cls, entry: TestEntry) -> "TestInfo":
        return cls(
            test_id=entry.test_id,
            type=entry.type,
            category=entry.category,
            source=entry.source,
            prompt_file=entry.prompt_path.name if entry.prompt_path else None,
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EngineResult:
    """What a run or a validation produced.

    One type for both paths so a caller never has to branch on which it asked
    for. `olympus` is populated only by `validate`.
    """
    test_id: str
    status: str                     # ok | parse_error | exception | skipped | ...
    verdict: str | None = None
    certainty: int | None = None
    rationale: str | None = None
    evidence_rows: int = 0
    output_path: Path | None = None
    full_verdict: dict | None = None
    olympus: OlympusTestOutput | None = None
    error: str | None = None
    skipped_reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    # Ways the verdict contradicts itself, per the reviewer prompt's own
    # self-verification rules. Non-empty means do not trust this verdict.
    review_violations: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def gaps_found(self) -> bool:
        """True when this engine reached a different verdict than Olympus.

        Only meaningful for `validate`. A differing verdict is the signal that
        the original analysis missed something; matching verdicts mean the
        engine independently confirmed it.
        """
        if not self.ok or self.olympus is None or self.olympus.verdict is None:
            return False
        return _norm(self.verdict) != _norm(self.olympus.verdict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["output_path"] = str(self.output_path) if self.output_path else None
        d["olympus"] = (
            {"verdict": self.olympus.verdict, "raw": self.olympus.raw}
            if self.olympus else None
        )
        d["gaps_found"] = self.gaps_found
        return d


def _norm(verdict: str | None) -> str:
    return (verdict or "").strip().lower()


# ============================================================
#  Config resolution without killing the host process
# ============================================================

def _resolve_settings_or_raise(overrides: dict, config_path: Path | None) -> dict:
    """Run the shared config resolver, converting its `sys.exit()` calls into
    `EngineConfigError`.

    Wrapping rather than reimplementing is deliberate: `resolve_settings` is
    ~200 lines of precedence rules shared with both CLIs, and a second copy
    would drift. `sys.exit` raises SystemExit, so the conversion is exact.
    """
    parser = runner_config.build_argparser()
    args = parser.parse_args([])
    args.config = Path(config_path) if config_path else None

    unknown = set(overrides) - set(vars(args))
    if unknown:
        raise EngineConfigError(
            f"Unknown setting(s): {', '.join(sorted(unknown))}. Valid keys are "
            f"the CLI flag names with dashes replaced by underscores "
            f"(e.g. 'apk_root', 'test_plan_dir', 'model')."
        )

    # argparse would have applied `type=` conversions for us; a dict bypasses
    # that, so do it here. Without this, `resolve_settings` calls .resolve() on
    # a plain string and raises AttributeError — a host configuring from a dict
    # or JSON naturally passes strings, so this is the common case, not an edge.
    # The conversions are read off the parser itself, so new flags stay covered.
    converters = {
        action.dest: action.type
        for action in parser._actions
        if action.type is not None and action.dest != "config"
    }
    for key, value in overrides.items():
        convert = converters.get(key)
        if convert is not None and value is not None and not isinstance(
            value, (convert if isinstance(convert, type) else object,)
        ):
            try:
                value = convert(value)
            except (TypeError, ValueError) as exc:
                raise EngineConfigError(
                    f"Setting {key!r}: cannot convert {value!r} to "
                    f"{getattr(convert, '__name__', convert)} ({exc})"
                ) from exc
        setattr(args, key, value)

    try:
        return runner_config.resolve_settings(args)
    except SystemExit as exc:
        raise EngineConfigError(
            str(exc) or "Invalid engine configuration"
        ) from exc


# ============================================================
#  Modes — (system prompt, schema) pairs
# ============================================================

@dataclass(frozen=True)
class EngineMode:
    """A `(system_prompt, schema)` pair naming one way of using the engine.

    These two settings vary **by mode, not by deployment and not by APK**:

      analysis    the model performs the assessment itself
      validation  the model verifies an existing Olympus result — its system
                  prompt re-scopes the task, and its schema must additionally
                  describe the Olympus output block, which is an extra input
                  that does not exist in the analysis mode

    Both are paths (or literal text for `system_prompt`). Keeping them together
    in one object is what stops them drifting apart: a validation system prompt
    paired with an analysis schema would tell the model to verify a payload the
    schema never describes.
    """
    name: str
    system_prompt: str | Path
    schema: str | Path

    def resolved_schema(self) -> Path:
        return Path(self.schema)


# ============================================================
#  Reusable settings — three tiers, because three things vary
# ============================================================

class EngineSettings:
    """Deployment-level settings, reusable across modes and APKs.

    Settings fall into three tiers, and conflating them is what forces a
    config file per APK:

      | tier           | varies with        | settings                        |
      |----------------|--------------------|---------------------------------|
      | **deployment** | rarely             | backend, model, base_url, api    |
      |                |                    | key, temperature, json_mode,    |
      |                |                    | timeouts, retries, tool limits  |
      | **mode**       | analysis vs        | system_prompt, schema           |
      |                | validation         | (see `EngineMode`)              |
      | **job**        | per APK            | apk_root, evidence_dir,         |
      |                |                    | output_dir, test_plan_dir       |

    `EngineSettings` holds the deployment tier only. Modes are passed in, and
    the job tier is supplied by `for_apk`:

        settings = EngineSettings.from_dict({
            "backend": "openai",
            "model": "qwen3.6:27b",
            "base_url": "http://localhost:11434/v1",
        })

        engine = settings.for_apk(
            "storage/artifacts/my-app",
            test_plan_dir="app/layer4/test_plans/owasp_mastg",
            analysis=ANALYSIS_MODE,
            validation=VALIDATION_MODE,
        )

    `test_plan_dir` is a JOB setting, not a deployment one — different APKs can
    warrant different plans (a certification profile versus the full MASTG set).
    It may still be given at the deployment tier as a default when a host uses
    one plan throughout.

    Resolution is DEFERRED until `for_apk`, because the underlying resolver
    requires all six paths together and so cannot resolve a partial config.
    Errors surface there as `EngineConfigError`.
    """

    def __init__(self, base: dict, *, config_path: Path | None = None, log_fn=None):
        self.base = dict(base)
        self.config_path = config_path
        self.log_fn = log_fn

    @classmethod
    def from_dict(cls, settings: dict, *, log_fn=None) -> "EngineSettings":
        """Deployment settings as a plain dict — no INI file anywhere."""
        return cls(settings, log_fn=log_fn)

    @classmethod
    def from_config_file(
        cls, path: str | Path, *, log_fn=None, **overrides
    ) -> "EngineSettings":
        """Deployment settings from an INI, for hosts that already keep one.
        Keyword overrides win over the file."""
        return cls(overrides, config_path=Path(path), log_fn=log_fn)

    def for_apk(
        self,
        apk_root: str | Path,
        *,
        test_plan_dir: str | Path | None = None,
        evidence_dir: str | Path | None = None,
        output_dir: str | Path | None = None,
        analysis: EngineMode | None = None,
        validation: EngineMode | None = None,
        log_fn=None,
        **overrides,
    ) -> "EngineAPI":
        """Build an `EngineAPI` for one APK.

        `evidence_dir` defaults to `<apk_root>/evidence` and `output_dir` to
        `<apk_root>/verdicts` — the layout this repo's jobs and both sample
        configs use, so the common case needs neither.

        `test_plan_dir` is per-job; omit it to fall back to a deployment-level
        default. `analysis` / `validation` select the mode used by `run_test`
        and `validate` respectively; omit them to use the `system_prompt` and
        `schema` from the deployment settings for both.
        """
        apk_root = Path(apk_root)
        merged = {
            **self.base,
            "apk_root": apk_root,
            "evidence_dir": Path(evidence_dir) if evidence_dir
                            else apk_root / "evidence",
            "output_dir": Path(output_dir) if output_dir
                          else apk_root / "verdicts",
        }
        if test_plan_dir is not None:
            merged["test_plan_dir"] = Path(test_plan_dir)
        # `resolve_settings` requires system_prompt and schema. When no config
        # file is supplying them, seed the resolver from a mode so a host need
        # not repeat them at the deployment tier.
        #
        # Seed from `analysis` ONLY — never from `validation`. Seeding from
        # whichever was given meant that passing `validation=` alone (the
        # natural thing to do when a host only reviews) silently made the
        # VALIDATION prompt the analysis default too, so `run_test` would have
        # run with the reviewer's prompt. That is the same class of silent
        # prompt substitution that made a reviewer run produce a plain
        # test-case verdict with no review block in it.
        #
        # With a config file present, let the file supply them: seeding here
        # would become an explicit CLI-equivalent override and beat the INI.
        if self.config_path is None and analysis is not None:
            if _looks_like_path(analysis.system_prompt):
                merged.setdefault("system_prompt", Path(analysis.system_prompt))
            merged.setdefault("schema", analysis.resolved_schema())
        merged.update(overrides)

        return EngineAPI(
            _resolve_settings_or_raise(merged, self.config_path),
            log_fn=log_fn or self.log_fn,
            analysis_mode=analysis,
            validation_mode=validation,
        )

    def with_(self, **overrides) -> "EngineSettings":
        """A copy with some deployment settings changed — e.g. a different
        model for one batch, without mutating the shared instance."""
        return EngineSettings(
            {**self.base, **overrides},
            config_path=self.config_path,
            log_fn=self.log_fn,
        )


def _looks_like_path(value: str | Path) -> bool:
    """A mode's system_prompt may be a path or the prompt text itself. Text is
    long and multi-line; a path is neither."""
    if isinstance(value, Path):
        return True
    return "\n" not in value and len(value) < 400


# ============================================================
#  The facade
# ============================================================

class EngineAPI:
    """Embeddable entry point. Construct once per APK job and reuse."""

    def __init__(
        self,
        settings: dict,
        *,
        log_fn=None,
        analysis_mode: EngineMode | None = None,
        validation_mode: EngineMode | None = None,
    ):
        self.settings = settings
        self.log = log_fn or _default_log
        # Fall back to the configured system_prompt/schema for both modes when
        # a host has only one of each.
        default = EngineMode(
            name="default",
            system_prompt=settings["system_prompt"],
            schema=settings["schema"],
        )
        self.analysis_mode = analysis_mode or default
        self.validation_mode = validation_mode or analysis_mode or default
        self.config = RunConfig(
            apk_root=settings["apk_root"],
            schema=settings["schema"],
            evidence_dir=settings["evidence_dir"],
            test_plan_dir=settings["test_plan_dir"],
            test_filter=settings["test_filter"],
            output_dir=settings["output_dir"],
            max_tool_iterations=settings["max_tool_iterations"],
            max_test_retries=settings["max_test_retries"],
            retry_delay_seconds=settings["retry_delay_seconds"],
            abort_on_error=settings["abort_on_error"],
            inline_evidence_max_bytes=settings["inline_evidence_max_bytes"],
        )
        self._navigator: APKNavigator | None = None
        self._plan = None
        self._lock = threading.Lock()
        #: Shared by every backend this API builds. `run_parallel` paces all of
        #: its workers through one of these; an embedded host gets the same by
        #: calling `set_rate_limiter` once per run. None means unpaced.
        self._rate_limiter = None

    # ---------- construction ----------

    @classmethod
    def from_config_file(cls, path: str | Path, *, log_fn=None, **overrides):
        """Build from an INI file. Keyword overrides use CLI flag names with
        underscores and take precedence over the file."""
        return cls(_resolve_settings_or_raise(overrides, Path(path)), log_fn=log_fn)

    @classmethod
    def from_dict(cls, settings: dict, *, log_fn=None):
        """Build with no INI file — every value supplied by the host."""
        return cls(_resolve_settings_or_raise(settings, None), log_fn=log_fn)

    # ---------- shared, lazily built ----------

    @property
    def navigator(self) -> APKNavigator:
        """The APK read surface. Built once — indexing is the single most
        expensive operation in the system."""
        with self._lock:
            if self._navigator is None:
                self.log("Indexing APK for engine API...", color="cyan")
                self._navigator = APKNavigator(
                    self.config.apk_root,
                    evidence_dir=self.config.evidence_dir,
                    log_fn=self.log,
                )
            return self._navigator

    @property
    def plan(self):
        with self._lock:
            if self._plan is None:
                try:
                    self._plan = load_test_plan(self.config.test_plan_dir)
                except TestPlanError as exc:
                    raise EngineConfigError(str(exc)) from exc
            return self._plan

    # ---------- test catalogue ----------

    def list_tests(self, test_filter: str = "") -> list[TestInfo]:
        """Tests in the plan, optionally filtered by id or category. Uses the
        engine's own filter, so it selects exactly what the CLI would."""
        return [
            TestInfo.from_entry(e)
            for e in filter_entries(self.plan.entries, test_filter or "")
        ]

    def get_entry(self, test_id: str) -> TestEntry:
        for entry in self.plan.entries:
            if entry.test_id == test_id:
                return entry
        raise TestNotFoundError(f"No test {test_id!r} in plan {self.plan.name!r}.")

    def read_test(self, test_id: str) -> dict:
        """The test's prompt text plus its metadata."""
        entry = self.get_entry(test_id)
        info = TestInfo.from_entry(entry).to_dict()
        info["prompt"] = (
            entry.prompt_path.read_text(encoding="utf-8")
            if entry.prompt_path else None
        )
        info["prompt_path"] = str(entry.prompt_path) if entry.prompt_path else None
        return info

    def olympus_sourced_tests(self) -> list[TestInfo]:
        """Tests the manifest marks as coming from Olympus."""
        return [
            TestInfo.from_entry(e) for e in self.plan.entries
            if e.source == SOURCE_OLYMPUS
        ]

    # ---------- results ----------

    def result_path(self, test_id: str) -> Path:
        """Where this test's verdict is written (category subfolder included)."""
        return _verdict_output_path(
            self.config, test_id, self.get_entry(test_id).category
        )

    def read_results(self, test_id: str) -> dict | None:
        """The stored verdict, or None if the test has not been run."""
        path = self.result_path(test_id)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise EngineError(
                f"Verdict file for {test_id!r} is not valid JSON: {path} ({exc})"
            ) from exc

    def has_results(self, test_id: str) -> bool:
        return self.result_path(test_id).is_file()

    # ---------- the two things that talk to a model ----------

    def run_test(
        self,
        test_id: str,
        *,
        backend=None,
        prompt_prefix: str = "",
        attempt_num: int = 1,
        bootstrap: bool = True,
    ) -> EngineResult:
        """Run one test from scratch and return its result.

        Blocks for as long as the test takes — minutes is normal: up to
        `max_tool_iterations` tool rounds over requests whose own timeout
        defaults to 600s. Call it on a worker thread if the caller is serving a
        request; it is thread-safe.

        `backend=None` builds one from config. Pass your own to control
        concurrency — one backend per in-flight test, never shared.
        """
        entry = self.get_entry(test_id)
        return self._execute(
            entry, backend=backend, prompt_prefix=prompt_prefix,
            attempt_num=attempt_num, mode=self.analysis_mode,
            bootstrap=bootstrap,
        )

    def validate(
        self,
        test_id: str,
        olympus_output: dict | str | bytes | OlympusTestOutput,
        *,
        backend=None,
        system_prompt: str | Path | None = None,
        attempt_num: int = 1,
        bootstrap: bool = True,
    ) -> EngineResult:
        """Check an Olympus result for gaps.

        `olympus_output` is whatever Olympus produced — a dict, a JSON string,
        or raw CLI text. It is normalised, placed in front of the test's own
        prompt, and the model is asked to verify it against the evidence with
        full tool access, paying particular attention to checks that were never
        performed.

        `system_prompt` selects the validation-scoped system prompt (see
        TODO H1). Without it the model is still framed as performing a fresh
        analysis, which weakens — but does not break — the result.
        """
        entry = self.get_entry(test_id)

        output = (
            olympus_output
            if isinstance(olympus_output, OlympusTestOutput)
            else normalize_olympus_output(olympus_output, test_id=test_id)
        )
        for warning in output.warnings:
            self.log(f"  · Olympus output for {test_id}: {warning}", color="dim")

        problems = GapValidator.preflight(self.config)
        if problems:
            raise EngineError("Cannot validate — " + "; ".join(problems))

        mode = self.validation_mode
        if system_prompt is not None:
            mode = EngineMode(
                name=f"{mode.name}+override",
                system_prompt=system_prompt,
                schema=mode.schema,
            )
        if backend is None:
            backend = self.make_backend(system_prompt=mode.system_prompt)

        result = self._execute(
            entry,
            backend=backend,
            prompt_prefix=build_validation_prefix(output),
            attempt_num=attempt_num,
            mode=mode,
            bootstrap=bootstrap,
        )
        result.olympus = output
        result.warnings.extend(output.warnings)
        if result.full_verdict:
            result.review_violations = check_review_invariants(
                result.full_verdict, output.verdict,
                evidence_dir=self.config.evidence_dir,
            )
            for problem in result.review_violations:
                self.log(f"  ⚠ review invariant: {problem}", color="yellow")
        return result

    def _execute(
        self,
        entry: TestEntry,
        *,
        backend,
        prompt_prefix: str,
        attempt_num: int,
        mode: EngineMode,
        bootstrap: bool = True,
    ) -> EngineResult:
        """Shared body of run_test and validate: bootstrap the session, run the
        attempt, map the AttemptRecord onto an EngineResult."""
        if entry.prompt_path is None:
            raise EngineError(
                f"{entry.test_id!r} is a {entry.type} test with no prompt file."
            )
        if backend is None:
            backend = self.make_backend(system_prompt=mode.system_prompt)

        # Register the navigator's 13 tools with the backend. Without this the
        # backend's tool list stays empty, the model is never told the tools
        # exist, and it cannot traverse the app's code at all — it would be
        # limited to whatever evidence arrives inline. run_batch and
        # run_parallel both do this; the facade must too.
        backend.configure_tools(self.navigator)

        # The system prompt defines a stateful protocol that opens by
        # negotiating the schema (Begin -> getSchema -> schema -> getPrompt).
        # Sending a test prompt to a session that skipped it leaves the model
        # without the evidence schema and one step out of step with its own
        # instructions. run_batch has always done this; the facade must too.
        if bootstrap:
            schema_path = mode.resolved_schema()
            if not schema_path.is_file():
                raise EngineConfigError(
                    f"Schema for mode {mode.name!r} not found: {schema_path}"
                )
            if not bootstrap_session(
                backend, schema_path.read_text(encoding="utf-8"), strict=False,
            ):
                raise EngineError(
                    f"Protocol handshake failed for {entry.test_id!r} "
                    f"(mode {mode.name!r}): the model did not request the "
                    f"schema. Check that the system prompt for this mode "
                    f"defines the getSchema handshake."
                )

        stats = TestStats(
            test_file=entry.prompt_path.name,
            test_stem=entry.test_id,
            category=entry.category,
            started_at=utc_now(),
            started_monotonic=time.monotonic(),
        )
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        attempt = _run_one_attempt(
            backend, self.navigator, self.config, entry.prompt_path,
            stats, set(), attempt_num, prompt_prefix=prompt_prefix,
        )
        return self._to_result(entry, attempt)

    def _to_result(self, entry: TestEntry, attempt: AttemptRecord) -> EngineResult:
        stored = self.read_results(entry.test_id) if attempt.status == "ok" else None
        return EngineResult(
            test_id=entry.test_id,
            status=attempt.status,
            verdict=attempt.verdict,
            certainty=attempt.certainty,
            rationale=(stored or {}).get("rationale"),
            evidence_rows=attempt.evidence_table_rows or 0,
            output_path=self.result_path(entry.test_id) if stored else None,
            full_verdict=stored,
            error=attempt.error,
        )

    # ---------- APK read surface ----------

    def tool_names(self) -> tuple[str, ...]:
        return APKNavigator.TOOL_NAMES

    def call_tool(self, name: str, args: dict | None = None):
        """Invoke one navigator tool — the same 13 the LLM is given."""
        if name not in APKNavigator.TOOL_NAMES:
            raise EngineError(
                f"Unknown tool {name!r}. Available: "
                f"{', '.join(APKNavigator.TOOL_NAMES)}"
            )
        return self.navigator.call(name, args or {})

    # ---------- backends ----------

    def set_rate_limiter(self, rate_limiter) -> "EngineAPI":
        """Pace every backend this API builds through one shared limiter.

        Call once per run, before `run_test`/`validate`. The limiter reserves
        its budget up front, which is what stops N concurrent callers from
        collectively overshooting the way a check-then-send limiter does.
        Returns self, so it chains onto `for_apk`.
        """
        self._rate_limiter = rate_limiter
        return self

    def make_backend(self, *, system_prompt: str | Path | None = None):
        """Build a backend from the resolved settings.

        `system_prompt` may be a path or the prompt text itself; omit it to use
        the configured one.
        """
        if system_prompt is None:
            prompt = self.settings["system_prompt"].read_text(encoding="utf-8")
        elif isinstance(system_prompt, Path):
            prompt = system_prompt.read_text(encoding="utf-8")
        else:
            prompt = system_prompt
        return runner_config.make_backend(self.settings, prompt,
                                          rate_limiter=self._rate_limiter)

    # ---------- reporting ----------

    def generate_report(
        self,
        output_path: str | Path,
        *,
        title: str = "Mobile Security Assessment Report",
        apk_name: str | None = None,
    ) -> Path:
        """Render stored verdicts into a self-contained HTML report.

        This is the engine's standalone reporting path. Olympus ships its own
        output mechanism, so this is not on the validation route.
        """
        loaded = _report_module().load_verdicts(self.config.output_dir)
        if not loaded:
            raise EngineError(f"No verdicts found under {self.config.output_dir}.")
        cw = _report_module()
        cases = [
            (i, case_id, data)
            for i, (case_id, data, _) in enumerate(
                sorted(loaded, key=lambda t: cw.sort_key(t[0])), 1
            )
        ]
        html = cw.build_full_html(
            cases,
            title=title,
            apk_name=apk_name or self.config.apk_root.name,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
        return out


_report_cache = None


def _report_module():
    """Load `create_website.py`, which lives at the repo root and is a script
    rather than a package module, so it needs a path-based import."""
    global _report_cache
    if _report_cache is None:
        path = Path(__file__).resolve().parent.parent / "create_website.py"
        if not path.is_file():
            raise EngineError(f"Report generator not found: {path}")
        spec = importlib.util.spec_from_file_location("_create_website", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _report_cache = module
    return _report_cache
