#!/usr/bin/env python3
"""
olympus_run.py — one entry point for both modes. Flags only, Gemini only.

    # Olympus answers the tests, the LLM reviews its answers
    ./olympus_run.py --mode reviewer --target file_manager --test 0232

    # the LLM answers the tests itself, Olympus is not asked
    ./olympus_run.py --mode analyzer --target file_manager --test 0221-0232

    # start from an APK: acquire, prepare, build evidence, then run
    ./olympus_run.py --mode reviewer --apk ~/apks/xiaomi-explorer.apk --category crypto

What each mode is
-----------------
reviewer   Olympus runs the selected controls (`olympus_owasp.runall --test`),
           its resolved MASTG rows are collected, and each row is handed to
           `engine.validate(test_id, row)` — the LLM checks Olympus's answer
           against the evidence with full tool access, looking for checks that
           were never performed. Uses the VALIDATION prompt + schema.

analyzer   `engine.run_test(test_id)` only. Olympus answers nothing; the LLM
           produces the verdict from the evidence on its own. Uses the ANALYSIS
           prompt + schema.

The two are alternatives, not a sequence: reviewing the engine's own output
would be the engine grading itself.

Prompts and schema are discovered per mode from
`app/layer4/prompts/system/`, newest version of each pair — never hardcoded,
because those versions move.

Target resolution
-----------------
`--target` names an Olympus target (a name under `targets/`, or a path).
`--apk` acquires and prepares one through Olympus first.

Either way, the engine's evidence tree is built if it is missing or stale —
Olympus's `rsc_base/` is reused as the apktool half, jadx runs once, and the
androguard-backed builders run once, all keyed on the APK's sha256.

Output
------
NDJSON, one object per test, to `--out` (default: the job's `reviews.ndjson`).
A summary table goes to stderr; the results path goes to stdout.

Exit codes: 0 all produced a verdict · 1 nothing ran · 2 ran with failures.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import subprocess
import sys
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

from olympus_bridge import (discover_modes, envelope, error_envelope, log,  # noqa: E402
                            list_test_plans, merge_tokens, mode_backend,
                            resolve_test_plan, UsageMeter)

DEFAULT_OLYMPUS = Path.home() / ".local/share/olympus-owasp/usr/share/olympus-owasp"
DEFAULT_ARTIFACTS = Path.home() / "olympus-evidence"
#: Plan NAME, resolved against app/layer4/test_plans by `resolve_test_plan`.
#: A path still works, for configs written before names were accepted.
DEFAULT_TEST_PLAN = "owasp_mastg"
MODEL = "gemini-2.5-pro"

TEST_ID = re.compile(r"^(?:MASTG-TEST-)?(\d{4})$")
TEST_RANGE = re.compile(r"^(?:MASTG-TEST-)?(\d{4})\s*-\s*(?:MASTG-TEST-)?(\d{4})$")


def die(msg: str) -> "NoReturn":                            # noqa: F821
    raise SystemExit("error: " + msg)


# ------------------------------------------------------------------ Olympus --

def olympus_python(home: Path) -> Path:
    py = home / ".venv" / "bin" / "python3"
    if not py.is_file():
        die("no Olympus interpreter at %s — is --olympus-home right?" % py)
    return py


def olympus_call(home: Path, code: str, *, quiet: bool = True) -> str:
    """Run a snippet inside Olympus's own venv and return its stdout.

    Olympus is a separate environment on purpose: it pins androguard==4.1.3
    because that pin sits in its evidence path, and this repo does not.
    """
    proc = subprocess.run(
        [str(olympus_python(home)), "-c", code], cwd=str(home),
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-6:]
        die("Olympus call failed:\n  " + "\n  ".join(tail))
    if not quiet and proc.stderr.strip():
        log(proc.stderr.rstrip())
    return proc.stdout


def acquire_target(home: Path, apk: Path, name: str = "") -> Path:
    """Acquire and prepare an APK through Olympus, returning its target dir.

    `acquire_from_paths` calls `prepare()` and then *discards its result*, so a
    failed decode returns a target directory that looks fine and contains no
    sources. The decode is therefore checked here rather than trusted.
    """
    log("acquiring   %s" % apk)
    out = olympus_call(home, (
        "import json\n"
        "from olympus_owasp.recon import acquire as A\n"
        "t = A.acquire_from_paths([%r], name=%r or None, log=lambda *a: None)\n"
        "print(json.dumps({'target': t}))\n"
    ) % (str(apk), name))
    target = (json.loads(out.strip().splitlines()[-1]) or {}).get("target")
    if not target:
        die("Olympus refused to acquire %s (invalid target name, or no base APK)" % apk)
    return Path(target)


def check_prepared(target: Path) -> None:
    rsc = target / "rsc_base"
    if not (rsc / "AndroidManifest.xml").is_file():
        die("%s was not prepared (no AndroidManifest.xml under rsc_base/)" % target)
    if not any(p.is_dir() for p in rsc.glob("smali*")):
        die("%s has no smali*/ — the decode produced resources but no sources.\n"
            "Re-prepare it with a current apktool; every code-backed evidence file "
            "would otherwise be silently empty." % target)


def resolve_target(home: Path, args) -> Path:
    if args.target:
        candidate = Path(args.target).expanduser()
        if not candidate.is_dir():
            candidate = home / "targets" / args.target
        if not candidate.is_dir():
            die("no such Olympus target: %s" % args.target)
        return candidate.resolve()

    apk = Path(args.apk).expanduser().resolve()
    if not apk.is_file():
        die("no such APK: %s" % apk)
    existing = home / "targets" / (args.name or apk.stem)
    if existing.is_dir():
        log("target      reusing %s" % existing)
        return existing
    return acquire_target(home, apk, args.name)


def olympus_rows(home: Path, target: Path) -> list[dict]:
    """Olympus's resolved MASTG rows: {test, result, engine, reason, ...}."""
    out = olympus_call(home, (
        "import json\n"
        "from olympus_owasp import assess as A\n"
        "rep = A.assess(%r)\n"
        "rows = rep['tests'] if isinstance(rep, dict) and 'tests' in rep else rep\n"
        "rows = rows if isinstance(rows, list) else list(rows.values())\n"
        "print('<<<ROWS>>>' + json.dumps(rows, default=str))\n"
    ) % str(target))
    for line in out.splitlines():
        if line.startswith("<<<ROWS>>>"):
            return json.loads(line[len("<<<ROWS>>>"):])
    die("could not read Olympus's resolved rows — assess() printed nothing usable")


def olympus_runall(home: Path, target: Path, short_ids: list[str], timeout: int) -> None:
    """Make Olympus actually answer the selected controls.

    Its human log is forwarded to stderr. Without it the run looks like a hang:
    Olympus only emits `control_done` after the whole sweep, so there is no
    per-control progress to show until the end.
    """
    cmd = [str(olympus_python(home)), "-m", "olympus_owasp.runall", str(target)]
    for sid in short_ids:
        cmd += ["--test", sid]
    cmd += ["--timeout", str(timeout)]
    log("olympus     %s" % " ".join(cmd[2:]))
    proc = subprocess.Popen(cmd, cwd=str(home), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in proc.stdout:
        log("  | " + line.rstrip())
    proc.wait()
    if proc.returncode != 0:
        log("olympus     runall exited %d — continuing with whatever it resolved"
            % proc.returncode)


# ----------------------------------------------------------------- evidence --

def ensure_evidence(target: Path, artifacts_root: Path, extra: list[str],
                    skip: bool, dry: bool) -> Path:
    job_root = artifacts_root / target.name
    if skip:
        if not (job_root / "evidence").is_dir():
            die("--skip-evidence given but %s/evidence does not exist" % job_root)
        return job_root
    cmd = [sys.executable, str(REPO / "olympus_evidence.py"),
           "--olympus-target", str(target), "--artifacts-root", str(artifacts_root)]
    for flag in extra:
        # `--jadx-arg=--no-res`, never two tokens: argparse treats a value
        # beginning with "-" as the next option and reports the flag as
        # missing its argument.
        cmd.append("--jadx-arg=%s" % flag)
    if dry:
        cmd.append("--dry-run")
    proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True)
    if proc.stderr.strip():
        log(proc.stderr.rstrip())
    if proc.returncode != 0:
        die("evidence build failed (see above)")
    printed = proc.stdout.strip().splitlines()
    return Path(printed[-1]) if printed else job_root


def check_package_name(job_root: Path) -> None:
    """A missing package name silently reclassifies first-party code.

    `app_metadata` writes `package_name: "unknown"` and the sha256 of zero
    bytes when it could not read the APK, rather than failing — and ownership
    classification reads that name.
    """
    path = job_root / "evidence" / "app_metadata.json"
    if not path.is_file():
        log("WARNING     no app_metadata.json — ownership classification will be "
            "unreliable and first-party code may read as third-party")
        return
    try:
        app = (json.loads(path.read_text(encoding="utf-8")) or {}).get("app") or {}
    except (OSError, ValueError):
        return
    package = (app.get("package_name") or "").strip()
    if not package or package == "unknown" or not app.get("apk_size_bytes"):
        log("WARNING     app_metadata has no usable package name (%r, %s bytes).\n"
            "            Rebuild it with an explicit --apk, or first-party classes "
            "will be classified as third-party."
            % (package or None, app.get("apk_size_bytes")))
    else:
        log("package     %s" % package)


# -------------------------------------------------------------- test choice --

def expand_selectors(selectors: list[str]) -> tuple[set[str], list[tuple[int, int]]]:
    """Accepts MASTG-TEST-0232, 0232, and 0221-0232 ranges."""
    exact: set[str] = set()
    ranges: list[tuple[int, int]] = []
    for raw in selectors:
        for part in str(raw).split(","):
            part = part.strip()
            if not part:
                continue
            span = TEST_RANGE.match(part)
            if span:
                lo, hi = int(span.group(1)), int(span.group(2))
                ranges.append((min(lo, hi), max(lo, hi)))
                continue
            one = TEST_ID.match(part)
            if not one:
                die("not a test id or range: %r (expected 0232, MASTG-TEST-0232, "
                    "or 0221-0232)" % part)
            exact.add(one.group(1))
    return exact, ranges


def select_tests(engine, args) -> list[str]:
    with contextlib.redirect_stdout(sys.stderr):
        infos = engine.list_tests(args.category or "")
    known = [i.test_id for i in infos]
    if not known:
        die("the test plan matched nothing" +
            (" for category %r" % args.category if args.category else ""))
    if args.all or (not args.test and args.category):
        return known

    exact, ranges = expand_selectors(args.test)
    chosen = []
    for test_id in known:
        tail = test_id[-4:]
        if not tail.isdigit():
            continue
        n = int(tail)
        if tail in exact or any(lo <= n <= hi for lo, hi in ranges):
            chosen.append(test_id)
    missing = exact - {t[-4:] for t in chosen}
    if missing:
        die("not in the test plan: %s" % ", ".join("MASTG-TEST-" + m for m in sorted(missing)))
    if not chosen:
        die("no tests selected — pass --test, --category or --all")
    return chosen


# -------------------------------------------------------------------- engine --

def build_engine(job_root: Path, args):
    """Gemini, with each mode's own prompt/schema pair. No INI is read.

    Deliberately not `config.ini`: it defaults to the OpenAI backend and
    carries an API key in the file. The key comes from the environment.
    """
    from app.engine_api import EngineMode, EngineSettings

    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        die("GEMINI_API_KEY is not set")

    found = discover_modes()
    if "analysis" not in found:
        die("no analysis prompt/schema pair under app/layer4/prompts/system/")
    if args.mode == "reviewer" and "validation" not in found:
        die("reviewer mode needs a validation prompt/schema pair; only the "
            "analysis pair was found under app/layer4/prompts/system/")

    analysis_prompt, analysis_schema = found["analysis"]
    settings = EngineSettings.from_dict({
        "backend": "gemini",
        "model": args.model,
        "api_key": key,
        "system_prompt": str(analysis_prompt),
        "schema": str(analysis_schema),
    }, log_fn=log)

    modes = {}
    for name, (prompt, schema) in found.items():
        modes[name] = EngineMode(name, system_prompt=prompt, schema=schema)
        log("%-11s %s" % (name, Path(prompt).name))

    plan = resolve_test_plan(args.test_plan or DEFAULT_TEST_PLAN)
    log("test plan   %s%s" % (plan.name, "" if plan.name == DEFAULT_TEST_PLAN
                              else "   (not the default)"))
    engine = settings.for_apk(job_root, test_plan_dir=plan, log_fn=log, **modes)
    # One limiter for the whole run, shared by every worker's backend.
    if args.rate_limit:
        from app.layer4.shared_rate_limiter import SharedRateLimiter
        tpm = int(args.tpm or engine.settings.get("tpm_limit") or 0)
        rpm = int(args.rpm or 0)
        if tpm > 0 or rpm > 0:
            engine.set_rate_limiter(
                SharedRateLimiter(tpm_limit=tpm, rpm_limit=rpm, log_fn=log))
            log("rate limit  TPM<=%s  RPM<=%s  (shared across %d worker(s))"
                % (tpm or "off", rpm or "off", args.workers))
    return engine


def run_one(engine, mode: str, test_id: str, row, _use_own_backend: bool = True) -> dict:
    # `_use_own_backend` no longer decides anything: every call now builds its
    # own backend, because that is the only way to both meter it and give it
    # the right system prompt. It stays in the signature so the caller reads
    # the same; sequential runs pay one extra object per test for it.
    kind = "review" if mode == "reviewer" else "run"
    meter = UsageMeter()
    try:
        # A backend holds conversation state — one per in-flight test, never
        # shared. Built through `mode_backend`, because passing a backend is
        # exactly what stops the engine picking this mode's own system prompt:
        # a bare make_backend() hands the reviewer the ANALYST's instructions.
        # Metered here because this is where every turn passes.
        backend = meter.attach(mode_backend(engine, kind))
        with contextlib.redirect_stdout(sys.stderr):
            if mode == "reviewer":
                result = engine.validate(test_id, row, backend=backend)
            else:
                result = engine.run_test(test_id, backend=backend)
        return envelope(kind, test_id, result, meter.as_dict())
    except Exception as exc:                                # noqa: BLE001
        env = error_envelope(kind, test_id, exc)
        env["tokens"] = meter.as_dict()                     # a failure still cost
        return env


# ---------------------------------------------------------------------- main --

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="olympus_run.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Run MASTG tests with Olympus and review them, or run them "
                    "with the LLM engine alone. Gemini only.",
    )
    p.add_argument("--mode", choices=("analyzer", "reviewer"), required=True)

    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--target", help="Olympus target: a name under targets/, or a path")
    target.add_argument("--apk", help="APK to acquire and prepare through Olympus first")
    p.add_argument("--name", default="", help="target name to use when acquiring an APK")

    p.add_argument("--test", action="append", default=[],
                   help="0232, MASTG-TEST-0232, or a range 0221-0232. Repeatable.")
    p.add_argument("--category", default="", help="plan category, e.g. crypto")
    p.add_argument("--all", action="store_true", help="every test the plan matches")

    p.add_argument("--model", default=MODEL)
    p.add_argument("--olympus-home", default=str(DEFAULT_OLYMPUS))
    p.add_argument("--artifacts-root", default=str(DEFAULT_ARTIFACTS))
    p.add_argument("--test-plan", default="",
                   help="plan NAME under app/layer4/test_plans (default: %s), or "
                        "a path to a plan directory. --list-plans shows what is "
                        "installed. Only the default plan's ids line up with "
                        "Olympus's, so --mode reviewer needs it." % DEFAULT_TEST_PLAN)
    p.add_argument("--list-plans", action="store_true",
                   help="print the installed test plans and exit")
    p.add_argument("--out", default="", help="results NDJSON (default: <job>/reviews.ndjson)")
    p.add_argument("--workers", type=int, default=1, help="concurrent tests. Default 1.")
    p.add_argument("--tpm", type=int, default=0,
                   help="tokens/minute ceiling. Default: the resolved tpm_limit.")
    p.add_argument("--rpm", type=int, default=150,
                   help="requests/minute ceiling (run_parallel's default is 150)")
    p.add_argument("--no-rate-limit", dest="rate_limit", action="store_false",
                   help="send unpaced — only safe for --workers 1")
    p.add_argument("--timeout", type=int, default=1800, help="Olympus per-run timeout")
    p.add_argument("--skip-evidence", action="store_true",
                   help="assume the evidence tree is current")
    p.add_argument("--dry-run", action="store_true",
                   help="resolve everything and print the plan; call no model")
    return p


def main(argv=None) -> int:
    # Before parsing, because --mode and a target are required arguments and
    # listing plans needs neither: asking what is installed is what someone
    # does BEFORE they can name a target.
    if "--list-plans" in (sys.argv[1:] if argv is None else list(argv)):
        plans = list_test_plans()
        if not plans:
            die("no test plans found under %s/app/layer4/test_plans" % REPO)
        for plan in plans:
            log("%-20s %-4d test(s)  %s%s"
                % (plan["name"], plan["tests"], plan["title"] or "-",
                   "   (default)" if plan["name"] == DEFAULT_TEST_PLAN else ""))
        return 0
    args = build_parser().parse_args(argv)
    home = Path(args.olympus_home).expanduser().resolve()
    if not home.is_dir():
        die("no Olympus at %s" % home)

    target = resolve_target(home, args)
    check_prepared(target)
    log("target      %s" % target)

    # jadx skips resources: every resource-backed evidence builder reads
    # apktool output, which Olympus's decode already provides for free.
    job_root = ensure_evidence(target, Path(args.artifacts_root).expanduser().resolve(),
                               ["--no-res"], args.skip_evidence, args.dry_run)
    log("job         %s" % job_root)
    if not args.dry_run:
        check_package_name(job_root)

    engine = build_engine(job_root, args)
    tests = select_tests(engine, args)
    log("mode        %s" % args.mode)
    log("tests       %d selected: %s" % (len(tests), ", ".join(t[-4:] for t in tests)))

    rows: dict[str, dict] = {}
    if args.mode == "reviewer":
        short = [t[-4:] for t in tests]
        if not args.dry_run:
            olympus_runall(home, target, short, args.timeout)
        for row in (olympus_rows(home, target) if not args.dry_run else []):
            test_id = str(row.get("test") or "")
            if test_id:
                rows[test_id] = row
        unanswered = [t for t in tests if t not in rows]
        if unanswered and not args.dry_run:
            log("skipping    %d test(s) Olympus did not answer: %s"
                % (len(unanswered), ", ".join(t[-4:] for t in unanswered)))
        tests = [t for t in tests if t in rows] if not args.dry_run else tests
        if not tests and not args.dry_run:
            die("Olympus answered none of the selected tests — nothing to review")

    out_path = Path(args.out).expanduser() if args.out else job_root / (
        "reviews.ndjson" if args.mode == "reviewer" else "analyses.ndjson")

    if args.dry_run:
        log("dry run     would %s %d test(s) and write %s"
            % ("review" if args.mode == "reviewer" else "analyse", len(tests), out_path))
        print(out_path)
        return 0

    def work(test_id: str) -> dict:
        log(">>> %s %s" % (args.mode, test_id))
        env = run_one(engine, args.mode, test_id, rows.get(test_id), args.workers > 1)
        log("<<< %s %s%s" % (test_id, env["status"],
                             "  GAP" if env.get("gaps_found") else ""))
        return env

    if args.workers > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(work, tests))
    else:
        results = [work(t) for t in tests]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for env in results:
            fh.write(json.dumps(env, ensure_ascii=False) + "\n")

    failed = [e for e in results if not e["ok"]]
    gaps = [e for e in results if e.get("gaps_found")]
    spent: dict = {}
    for env in results:
        merge_tokens(spent, env.get("tokens"))

    log("")
    log("%-18s %-10s %-10s %-10s %s" % ("TEST", "STATUS", "VERDICT", "OLYMPUS", "TOKENS"))
    for env in results:
        tok = env.get("tokens") or {}
        log("%-18s %-10s %-10s %-10s %9s%s"
            % (env["test_id"], env["status"], env["verdict"] or "-",
               env["olympus_verdict"] or "-", f"{tok.get('total', 0):,}",
               "   GAP" if env.get("gaps_found") else ""))
    log("")
    log("%d test(s) · %d failed · %d disagreement(s) with Olympus"
        % (len(results), len(failed), len(gaps)))
    # Printed even when every test failed: a failed run still spent the tokens,
    # and that is precisely when nobody thinks to look.
    log("%s tokens · %s in + %s out · %d model turn(s) · %s"
        % (f"{spent.get('total', 0):,}", f"{spent.get('in', 0):,}",
           f"{spent.get('out', 0):,}", spent.get("turns", 0), args.model))

    print(out_path)
    return 2 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:                                # noqa: BLE001
        log("error: %s: %s" % (type(exc).__name__, exc))
        sys.exit(1)
