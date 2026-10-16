#!/usr/bin/env python3
"""
olympus_bridge.py — call this engine from Olympus. JSON in, JSON out.

Supersedes `olympus_review.py`, which scraped `Control <id>` out of Olympus's
terminal output and mapped it through a hand-maintained `CONTROL_TO_TEST`
table. Neither is needed. Olympus's `runall` resolves every control invocation
into MASTG rows *before* it reports anything:

    rep  = _assess.assess(target)
    rows = rep["tests"] ...
    for row in rows:
        events.emit("control_done", cid=row["test"], status=_resolve(row)[0])

`row["test"]` is `MASTG-TEST-0202` — the same namespace `tests.toml` uses — and
the row itself is the payload. `normalize_olympus_output` already reads it
unchanged: `_TEST_ID_KEYS` contains "test", `_VERDICT_KEYS` contains "result",
`_RATIONALE_KEYS` contains "reason".

Usage
-----
    # review one Olympus result (row on stdin)
    echo '{"test":"MASTG-TEST-0202","result":"PASS","reason":"..."}' \
      | python3 olympus_bridge.py review --apk-root storage/artifacts/xiaomi-explorer

    # review a whole sweep: JSON array in, NDJSON out, one line per row
    python3 olympus_bridge.py review --batch --apk-root <job> < rows.json

    # run a test with the LLM instead of Olympus's own logic
    python3 olympus_bridge.py run --test MASTG-TEST-0202 --apk-root <job>

    # what this engine would review, given the plan's `source` axis
    python3 olympus_bridge.py list --apk-root <job> --olympus-sourced

Contract
--------
stdout carries results and nothing else. Every log, and anything an SDK prints,
goes to stderr, so the process stays pipeable.

Progress is optional NDJSON on ``--events-fd N`` — deliberately the same
convention Olympus's own CLIs use (`runall --events-fd`), so the GUI side can
reuse `_run_bg_events` rather than growing a second transport.

Exit codes
    0   everything requested produced a verdict
    1   usage or configuration error — nothing ran
    2   ran, but at least one item failed or was skipped

Those three stay distinct on purpose. For a gap detector, "the review failed"
must never be reported as "no gap found" (CLAUDE.md §4.3, decision 3).

Configuration
-------------
Deployment-tier settings come from the environment so Olympus can pass them
without a config file per APK, and so the API key never appears in argv (which
is world-readable in /proc):

    REVIEWER_BACKEND         gemini | openai        (default: gemini)
    REVIEWER_MODEL           model id               (default: gemini-2.5-pro)
    REVIEWER_BASE_URL        for OpenAI-compatible backends (Ollama, vLLM)
    GEMINI_API_KEY / OPENAI_API_KEY / REVIEWER_API_KEY
    REVIEWER_TEST_PLAN       test plan directory
    REVIEWER_SYSTEM_PROMPT   analysis-mode system prompt
    REVIEWER_SCHEMA          analysis-mode schema
    REVIEWER_VALIDATION_SYSTEM_PROMPT   validation-mode system prompt
    REVIEWER_VALIDATION_SCHEMA          validation-mode schema

Any of them can be overridden per call by the matching flag.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


#: Test plans live one directory each under `app/layer4/test_plans/`, and are
#: named by that directory. `owasp_mastg` is the default because it is the plan
#: whose test ids match Olympus's own — a review can only line up against
#: Olympus when both sides mean the same MASTG-TEST-XXXX. Other plans
#: (`ada_refactor`, and whatever arrives later) run the same way, but their ids
#: are their own, so they are an analysis, not a comparison.
TEST_PLAN_ROOT = REPO / "app" / "layer4" / "test_plans"
DEFAULT_TEST_PLAN = "owasp_mastg"
PROMPT_DIR = REPO / "app" / "layer4" / "prompts" / "system"


def list_test_plans(root: Path | None = None) -> list[dict]:
    """Every usable plan under the plans root, by directory name.

    A directory counts as a plan when it holds a `tests.toml`, which is the
    same file `load_test_plan` requires — so anything listed here loads, and a
    half-made directory is not offered.
    """
    root = root or TEST_PLAN_ROOT
    out = []
    for manifest in sorted(root.glob("*/tests.toml")):
        entry = {"name": manifest.parent.name, "path": str(manifest.parent),
                 "title": "", "version": "", "tests": 0}
        try:
            import tomllib
            with manifest.open("rb") as fh:
                data = tomllib.load(fh)
            entry["title"] = str(data.get("name") or "")
            entry["version"] = str(data.get("version") or "")
            entry["tests"] = len(data.get("tests") or {})
        except Exception:                                   # noqa: BLE001
            # A malformed manifest is still worth listing: naming it here is
            # how someone finds out why their plan will not load.
            entry["title"] = "(manifest unreadable)"
        out.append(entry)
    return out


def resolve_test_plan(value: str | Path | None, root: Path | None = None) -> Path:
    """A plan name, or a path, to the plan's directory.

    Names are the ordinary case (`--test-plan ada_refactor`). A path is still
    accepted, because the earlier flag took one and configs in the wild hold
    them. An unknown name fails here, with the list, rather than deep inside
    the loader with a missing-file error.
    """
    root = root or TEST_PLAN_ROOT
    raw = str(value or "").strip() or DEFAULT_TEST_PLAN
    candidate = Path(raw).expanduser()
    if os.sep in raw or "/" in raw or candidate.is_absolute():
        plan = candidate if candidate.is_absolute() else (REPO / candidate)
    else:
        plan = root / raw
    if (plan / "tests.toml").is_file():
        return plan.resolve()
    known = ", ".join(p["name"] for p in list_test_plans(root)) or "(none found)"
    raise SystemExit(
        "unknown test plan %r: no tests.toml at %s\n  available: %s"
        % (raw, plan, known)
    )


def _natkey(name: str):
    """Sort key that orders v1.3.10 after v1.3.8 — plain string sort does not."""
    out, digits = [], ""
    for ch in name:
        if ch.isdigit():
            digits += ch
        else:
            if digits:
                out.append((1, int(digits)))
                digits = ""
            out.append((0, ch))
    if digits:
        out.append((1, int(digits)))
    return out


def discover_modes() -> dict[str, tuple[Path, Path]]:
    """Find the (system prompt, schema) pair for each mode on disk.

    The two modes are told apart by "validation" in the filename, and the
    newest version of each wins. Discovery rather than hardcoding because the
    versions move — this repo has shipped a README pointing at v1.3.9.1 and
    v1_2_4 while the disk held v1.3.10 and v1.2.5.

    Returns only complete pairs. A prompt without its schema is worse than
    neither: a validation prompt paired with the analysis schema tells the
    model to verify a payload the schema never defines.
    """
    if not PROMPT_DIR.is_dir():
        return {}
    prompts = list(PROMPT_DIR.glob("1.system_prompt*.md"))
    schemas = list(PROMPT_DIR.glob("2.layer3_schema*.md"))

    def newest(paths, *, validation: bool):
        matching = [p for p in paths
                    if ("validation" in p.name.lower()) == validation]
        return max(matching, key=lambda p: _natkey(p.name)) if matching else None

    found: dict[str, tuple[Path, Path]] = {}
    for mode, is_validation in (("analysis", False), ("validation", True)):
        prompt = newest(prompts, validation=is_validation)
        schema = newest(schemas, validation=is_validation)
        if prompt and schema:
            found[mode] = (prompt, schema)
    return found


# ---------------------------------------------------------------- plumbing --

def log(msg: str = "", *_args, **_kwargs) -> None:
    """Stderr sink, also handed to the engine as `log_fn`.

    Tolerant of extra arguments on purpose: the engine's own logger is called
    with keywords this bridge has no use for (`color=`, and possibly others),
    and a log callback must never be the thing that fails a run.
    """
    print(msg, file=sys.stderr, flush=True)


class Events:
    """NDJSON progress on a caller-supplied fd, or nothing.

    Same shape Olympus emits, so its `_run_bg_events` reader needs no change:
    one JSON object per line, with an `ev` key. A closed or absent fd is not an
    error — this module is also run from a terminal, where nobody is reading.
    """

    def __init__(self, fd: int | None = None):
        self._f = None
        if fd is not None:
            try:
                self._f = os.fdopen(int(fd), "w", buffering=1)
            except (OSError, ValueError):
                self._f = None

    def emit(self, ev: str, **kw) -> None:
        if not self._f:
            return
        try:
            self._f.write(json.dumps({"ev": ev, **kw}) + "\n")
        except (OSError, ValueError):
            self._f = None

    def close(self) -> None:
        if self._f:
            with contextlib.suppress(OSError):
                self._f.close()
            self._f = None


def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


def resolve_config(arg: str) -> Path | None:
    """Which INI supplies the deployment tier, if any.

    `--config none` disables it. An explicit path must exist. Otherwise the
    repo's own `config.ini` is used when present, because it already points at
    the system prompt and schema that ship here — the two settings the engine
    requires and that have no sensible default.
    """
    if arg.strip().lower() == "none":
        return None
    if arg:
        path = Path(arg).expanduser()
        if not path.is_file():
            raise SystemExit("no such config file: %s" % path)
        return path
    default = REPO / "config.ini"
    return default if default.is_file() else None


def build_settings(args) -> "object":
    """Deployment + mode tiers. Raises EngineConfigError on bad configuration."""
    from app.engine_api import EngineMode, EngineSettings

    # Only values the caller actually supplied — a default here would silently
    # beat the INI it is meant to fall back to.
    explicit: dict = {}

    def put(key: str, *candidates: str) -> None:
        for value in candidates:
            if value:
                explicit[key] = value
                return

    put("backend", args.backend, _env("REVIEWER_BACKEND"))
    put("model", args.model, _env("REVIEWER_MODEL"))
    put("base_url", args.base_url, _env("REVIEWER_BASE_URL"))
    put("api_key", _env("REVIEWER_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY"))
    put("system_prompt", args.system_prompt, _env("REVIEWER_SYSTEM_PROMPT"))
    put("schema", args.schema, _env("REVIEWER_SCHEMA"))

    # `for_apk` resolves all six paths together and requires a deployment-level
    # system_prompt / schema even when both modes carry their own. Seed those
    # from the analysis pair so neither an INI nor a flag is needed for the
    # common case.
    discovered = discover_modes()
    if "analysis" in discovered:
        analysis_prompt, analysis_schema = discovered["analysis"]
        explicit.setdefault("system_prompt", str(analysis_prompt))
        explicit.setdefault("schema", str(analysis_schema))

    config = resolve_config(args.config)
    if config is not None:
        log("config      %s" % config)
        built = EngineSettings.from_config_file(config, log_fn=log)
        if explicit:
            built = built.with_(**explicit)
    else:
        settings = {"backend": "gemini", "model": "gemini-2.5-pro", **explicit}
        missing = [k for k in ("system_prompt", "schema") if k not in settings]
        if missing:
            raise SystemExit(
                "configuration error: no config file and no %s.\n"
                "  Either keep config.ini beside the repo, pass --config <file>,\n"
                "  or set --system-prompt / --schema (REVIEWER_SYSTEM_PROMPT / "
                "REVIEWER_SCHEMA)." % " or ".join(missing)
            )
        built = EngineSettings.from_dict(settings, log_fn=log)

    # Each mode is a (system prompt, schema) PAIR — never one without the
    # other. `run_test()` uses the analysis mode, `validate()` the validation
    # mode, so wiring both here is what makes the routing automatic.
    modes = {}
    for mode, prompt_arg, schema_arg, prompt_env, schema_env in (
        ("analysis", args.system_prompt, args.schema,
         "REVIEWER_SYSTEM_PROMPT", "REVIEWER_SCHEMA"),
        ("validation", args.validation_system_prompt, args.validation_schema,
         "REVIEWER_VALIDATION_SYSTEM_PROMPT", "REVIEWER_VALIDATION_SCHEMA"),
    ):
        prompt = prompt_arg or _env(prompt_env)
        schema = schema_arg or _env(schema_env)
        if bool(prompt) != bool(schema):
            raise SystemExit(
                "configuration error: the %s system prompt and the %s schema must "
                "be set together, or neither.\n  prompt: %s\n  schema: %s"
                % (mode, mode, prompt or "(unset)", schema or "(unset)")
            )
        if not prompt and mode in discovered:
            prompt, schema = discovered[mode]
        if prompt and schema:
            modes[mode] = EngineMode(mode, system_prompt=prompt, schema=schema)
            log("%-11s %s" % (mode, Path(prompt).name))

    return built, modes


def build_engine(args):
    settings, modes = build_settings(args)
    test_plan = resolve_test_plan(
        args.test_plan or _env("REVIEWER_TEST_PLAN", default=DEFAULT_TEST_PLAN))
    log("test plan   %s%s" % (test_plan.name,
                              "" if test_plan.name == DEFAULT_TEST_PLAN else "  (not the default)"))
    engine = settings.for_apk(args.apk_root, test_plan_dir=test_plan, log_fn=log, **modes)
    attach_rate_limiter(engine, args)
    return engine


def attach_rate_limiter(engine, args) -> None:
    """One SharedRateLimiter for every backend this run builds.

    `run_parallel` paces all its workers through a single limiter; without one
    an embedded caller with --workers > 1 lets N threads collectively overshoot
    TPM/RPM, because each only checks its own usage before sending. The limiter
    reserves up front instead, which is the whole point of it.
    """
    if not args.rate_limit:
        log("rate limit  disabled (--no-rate-limit)")
        return
    from app.layer4.shared_rate_limiter import SharedRateLimiter
    tpm = int(args.tpm or engine.settings.get("tpm_limit") or 0)
    rpm = int(args.rpm or 0)
    if tpm <= 0 and rpm <= 0:
        log("rate limit  no TPM or RPM configured — running unpaced")
        return
    engine.set_rate_limiter(SharedRateLimiter(tpm_limit=tpm, rpm_limit=rpm, log_fn=log))
    log("rate limit  TPM<=%s  RPM<=%s  (shared)" % (tpm or "off", rpm or "off"))


# ------------------------------------------------------------------ tokens --

class UsageMeter:
    """Counts every turn's tokens for ONE call.

    The engine reports the LAST turn's usage on its result, but the bill is the
    SUM over turns: a verdict that took six tool round-trips is six billed
    requests. So the count is taken where every turn passes — the backend's own
    `record_usage`, which the send path calls once per response — instead of
    being read off the result afterwards.

    Summing Gemini's `prompt_token_count` is not double counting. Each request
    resends the whole conversation and is billed for it, so a long tool loop
    costs far more than its final number suggests. That is the number worth
    showing, and the reason this exists.

    Attaching is an instance attribute, which shadows the bound method for that
    one backend. It is deliberately not a subclass: the backend is built by
    `runner_config.make_backend`, and a wrapper type there would have to be
    kept in step with every backend the engine learns to build.
    """

    KEYS = ("turns", "in", "out", "cached", "total")

    def __init__(self):
        self.turns = 0
        self.tin = 0
        self.tout = 0
        self.cached = 0

    def attach(self, backend):
        inner = getattr(backend, "record_usage", None)
        if not callable(inner):
            return backend                  # a backend that reports no usage
        meter = self

        def counting(usage):
            try:
                meter.turns += 1
                meter.tin += int(getattr(usage, "prompt_tokens", 0) or 0)
                meter.tout += int(getattr(usage, "completion_tokens", 0) or 0)
                meter.cached += int(getattr(usage, "cached_tokens", 0) or 0)
            except Exception:                # noqa: BLE001 - counting never fails a call
                pass
            return inner(usage)              # the rate limiter still gets its record

        backend.record_usage = counting
        return backend

    def as_dict(self) -> dict:
        return {"turns": self.turns, "in": self.tin, "out": self.tout,
                "cached": self.cached, "total": self.tin + self.tout}


def merge_tokens(into: dict, more: dict | None) -> dict:
    """Fold one token dict into a running total. Unknown shapes are ignored."""
    if isinstance(more, dict):
        for key in UsageMeter.KEYS:
            try:
                into[key] = int(into.get(key) or 0) + int(more.get(key) or 0)
            except (TypeError, ValueError):
                pass
    return into


def mode_backend(engine, mode: str):
    """A backend carrying the system prompt this mode is supposed to use.

    `EngineAPI._execute` selects the mode's prompt only when it builds the
    backend itself (`if backend is None`). A caller that passes its own backend
    — which every concurrent caller must, since a backend holds conversation
    state — silently substitutes whatever `make_backend()` defaults to, and that
    default is the ANALYSIS prompt. A review then runs the analyst's
    instructions against the validation schema: the exact pairing `EngineMode`'s
    docstring warns about, with nothing in the output to say so.
    """
    emode = engine.validation_mode if mode == "review" else engine.analysis_mode
    return engine.make_backend(system_prompt=emode.system_prompt)


# ----------------------------------------------------------------- results --

def envelope(mode: str, test_id: str, result, tokens: dict | None = None) -> dict:
    """One flat shape for Olympus to consume.

    `to_dict()` is `asdict()`, which carries fields but not properties, so `ok`
    and `gaps_found` are lifted out explicitly — they are the two a caller
    actually branches on.
    """
    olympus_verdict = None
    if getattr(result, "olympus", None) is not None:
        olympus_verdict = result.olympus.verdict

    return {
        "mode": mode,
        "test_id": result.test_id or test_id,
        "status": result.status,
        "ok": result.ok,
        "gaps_found": result.gaps_found,
        "verdict": result.verdict,
        "olympus_verdict": olympus_verdict,
        "certainty": result.certainty,
        "rationale": result.rationale,
        "review_violations": list(result.review_violations),
        "warnings": list(result.warnings),
        "error": result.error,
        "skipped_reason": result.skipped_reason,
        "output_path": str(result.output_path) if result.output_path else None,
        # What this call actually cost, summed over every turn. Always present,
        # so a consumer never has to distinguish "no tokens" from "not counted"
        # — `turns: 0` says the meter saw nothing.
        "tokens": tokens if tokens is not None else {
            "turns": 0, "in": 0, "out": 0, "cached": 0, "total": 0},
        "result": result.to_dict(),
    }


def error_envelope(mode: str, test_id: str, exc: Exception) -> dict:
    # An exception inside the engine is the one thing this bridge cannot
    # diagnose from its own side, so the traceback goes to stderr immediately
    # and travels in the envelope. A swallowed traceback turns a five-minute
    # fix into a guessing game.
    tb = traceback.format_exc()
    log(tb.rstrip())
    return {
        "traceback": tb,
        "mode": mode,
        "test_id": test_id,
        "status": "exception",
        "ok": False,
        "gaps_found": False,
        "verdict": None,
        "olympus_verdict": None,
        "certainty": None,
        "rationale": None,
        "review_violations": [],
        "warnings": [],
        "error": "%s: %s" % (type(exc).__name__, exc),
        "skipped_reason": None,
        "output_path": None,
        "result": None,
    }


def read_stdin_json():
    text = sys.stdin.read()
    if not text.strip():
        raise SystemExit("nothing on stdin: expected the Olympus row(s) as JSON")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Not JSON: raw CLI text is a supported (weaker) input — normalize_olympus_output
        # forwards it to the model as prose. There is no parseable Olympus verdict in
        # that case, so `gaps_found` correctly stays False rather than inventing one.
        return text


def row_test_id(row) -> str:
    if isinstance(row, dict):
        for key in ("test", "test_id", "testId", "id", "case_id"):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


# ---------------------------------------------------------------- commands --

def cmd_review(args) -> int:
    engine = build_engine(args)
    events = Events(args.events_fd)
    payload = read_stdin_json()

    if args.batch:
        rows = payload if isinstance(payload, list) else [payload]
    else:
        rows = [payload]

    items = []
    for row in rows:
        test_id = args.test or row_test_id(row)
        if not test_id:
            log("skipping a row with no test id and no --test given")
            continue
        items.append((test_id, row))

    if not items:
        raise SystemExit("no reviewable rows: none carried a test id")

    events.emit("review_plan", total=len(items))
    failures = 0
    out_lines = []

    def one(index_item):
        index, (test_id, row) = index_item
        events.emit("review_start", cid=test_id, index=index + 1, total=len(items))
        meter = UsageMeter()
        try:
            # One backend per in-flight test — a backend holds conversation
            # state and must never be shared (INTEGRATION.md, threading) — and
            # built through `mode_backend`, because a backend passed in is the
            # one thing that stops the engine selecting the reviewer's prompt.
            backend = meter.attach(mode_backend(engine, "review"))
            with contextlib.redirect_stdout(sys.stderr):
                result = engine.validate(test_id, row, backend=backend)
            env = envelope("review", test_id, result, meter.as_dict())
        except Exception as exc:                            # noqa: BLE001
            env = error_envelope("review", test_id, exc)
            env["tokens"] = meter.as_dict()                 # a failure still cost
        events.emit(
            "review_done", cid=env["test_id"], status=env["status"],
            gaps_found=env["gaps_found"], verdict=env["verdict"],
            tokens_total=env["tokens"]["total"], turns=env["tokens"]["turns"],
        )
        return env

    if args.workers > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            envs = list(pool.map(one, enumerate(items)))
    else:
        envs = [one(pair) for pair in enumerate(items)]

    spent: dict = {}
    for env in envs:
        if not env["ok"]:
            failures += 1
        merge_tokens(spent, env.get("tokens"))
        out_lines.append(env)

    if args.batch:
        for env in out_lines:
            print(json.dumps(env, ensure_ascii=False), flush=True)
    else:
        print(json.dumps(out_lines[0], indent=2, ensure_ascii=False))

    events.emit("review_all_done", total=len(items), failed=failures,
                tokens_total=spent.get("total", 0), turns=spent.get("turns", 0))
    log("tokens      %s in + %s out = %s over %d turn(s) in %d review(s)"
        % (f"{spent.get('in', 0):,}", f"{spent.get('out', 0):,}",
           f"{spent.get('total', 0):,}", spent.get("turns", 0), len(items)))
    events.close()
    return 2 if failures else 0


def cmd_run(args) -> int:
    if not args.test:
        raise SystemExit("run requires --test MASTG-TEST-XXXX")
    engine = build_engine(args)
    events = Events(args.events_fd)

    events.emit("run_start", cid=args.test, total=1)
    meter = UsageMeter()
    try:
        backend = meter.attach(mode_backend(engine, "run"))
        with contextlib.redirect_stdout(sys.stderr):
            result = engine.run_test(args.test, backend=backend)
        env = envelope("run", args.test, result, meter.as_dict())
    except Exception as exc:                                # noqa: BLE001
        env = error_envelope("run", args.test, exc)
        env["tokens"] = meter.as_dict()                     # a failure still cost
    events.emit("run_done", cid=env["test_id"], status=env["status"],
                verdict=env["verdict"], tokens_total=env["tokens"]["total"],
                turns=env["tokens"]["turns"])
    log("tokens      %s in + %s out = %s over %d turn(s)"
        % (f"{env['tokens']['in']:,}", f"{env['tokens']['out']:,}",
           f"{env['tokens']['total']:,}", env["tokens"]["turns"]))
    events.close()

    print(json.dumps(env, indent=2, ensure_ascii=False))
    return 0 if env["ok"] else 2


def cmd_list(args) -> int:
    engine = build_engine(args)
    with contextlib.redirect_stdout(sys.stderr):
        tests = (engine.olympus_sourced_tests() if args.olympus_sourced
                 else engine.list_tests(args.filter or ""))
    print(json.dumps([t.to_dict() for t in tests], indent=2, ensure_ascii=False))
    return 0


def cmd_list_plans(args) -> int:
    plans = list_test_plans()
    if getattr(args, "json", False):
        print(json.dumps({"default": DEFAULT_TEST_PLAN, "root": str(TEST_PLAN_ROOT),
                          "plans": plans}, indent=2, ensure_ascii=False))
        return 0 if plans else 1
    if not plans:
        log("no test plans found under %s" % TEST_PLAN_ROOT)
        return 1
    print("%-20s %-7s %-10s %s" % ("PLAN", "TESTS", "VERSION", "NAME"))
    for plan in plans:
        print("%-20s %-7d %-10s %s%s"
              % (plan["name"], plan["tests"], plan["version"] or "-",
                 plan["title"] or "-",
                 "   (default)" if plan["name"] == DEFAULT_TEST_PLAN else ""))
    return 0


# -------------------------------------------------------------------- main --

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="olympus_bridge.py",
        description="Call the LLM analysis engine from Olympus. JSON in, JSON out.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--apk-root", required=True,
                        help="evidence job root, e.g. storage/artifacts/<name>")
        sp.add_argument("--test-plan", default="",
                        help="plan NAME under app/layer4/test_plans (default: "
                             "%s), or a path to a plan directory. "
                             "`list-plans` shows what is installed."
                             % DEFAULT_TEST_PLAN)
        sp.add_argument("--config", default="",
                        help="INI supplying the deployment tier. Default: the "
                             "repo's config.ini if present. 'none' to disable.")
        sp.add_argument("--backend", default="", help="gemini | openai")
        sp.add_argument("--model", default="")
        sp.add_argument("--base-url", default="")
        sp.add_argument("--system-prompt", default="", help="analysis-mode system prompt")
        sp.add_argument("--schema", default="", help="analysis-mode schema")
        sp.add_argument("--validation-system-prompt", default="")
        sp.add_argument("--validation-schema", default="")
        sp.add_argument("--events-fd", type=int, default=None,
                        help="write NDJSON progress to this fd (Olympus convention)")
        sp.add_argument("--tpm", type=int, default=0,
                        help="tokens/minute ceiling. Default: the resolved tpm_limit.")
        sp.add_argument("--rpm", type=int, default=150,
                        help="requests/minute ceiling (run_parallel's default is 150)")
        sp.add_argument("--no-rate-limit", dest="rate_limit", action="store_false",
                        help="send unpaced — only safe for a single sequential call")
        return sp

    r = common(sub.add_parser("review", help="check an Olympus result for gaps"))
    r.add_argument("--test", default="", help="override the row's test id")
    r.add_argument("--batch", action="store_true",
                   help="stdin is a JSON array of rows; stdout becomes NDJSON")
    r.add_argument("--workers", type=int, default=1,
                   help="concurrent reviews (one backend each). Default 1.")
    r.set_defaults(func=cmd_review)

    x = common(sub.add_parser("run", help="run a test with the LLM, not Olympus"))
    x.add_argument("--test", default="", required=True)
    x.set_defaults(func=cmd_run)

    l = common(sub.add_parser("list", help="list tests this engine knows"))
    l.add_argument("--filter", default="", help="test id or category substring")
    l.add_argument("--olympus-sourced", action="store_true",
                   help="only tests whose plan entry says source = olympus")
    l.set_defaults(func=cmd_list)

    # No `common(...)`: listing plans reads directories. It must work before an
    # APK, a key or a backend exists, because "which plans do I have" is asked
    # precisely when something has not been set up yet.
    pl = sub.add_parser("list-plans", help="list installed test plans")
    pl.add_argument("--json", action="store_true", help="machine-readable")
    pl.set_defaults(func=cmd_list_plans)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except Exception as exc:                                # noqa: BLE001
        # Configuration and plan errors mean nothing ran — exit 1, distinct
        # from "ran and failed" (exit 2).
        log("error: %s: %s" % (type(exc).__name__, exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
