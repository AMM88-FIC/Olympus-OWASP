"""
run_parallel.py — Parallel entry-point / orchestrator for the verdict engine.

Where ``run_verdict_engine.py`` runs every test case sequentially through a
single stateful backend, this runner fans the test plan out across worker
threads so many test cases progress at once.

Pipeline:

  Phase 0 — Index the APK ONCE in memory (APKNavigator: class index + evidence
            index). Evidence files are pre-warmed so worker threads only ever
            read the shared index, never mutate it.
  Phase 1 — Create a server-side EXPLICIT CACHE holding the ENTIRE constant
            prefix: system prompt + tool declarations + the deterministic
            handshake transcript (Begin → getSchema → schema delivery →
            getPrompt). Crucially this caches the SCHEMA too — Gemini does not
            implicitly cache a request's dynamic contents on top of an explicit
            cache, so anything left in live history (like the schema) would be
            full-billed every turn. With the whole prefix cached, each worker's
            live history starts EMPTY and the model is already `initialized`.
            The handshake is run once (inline) only on a cache MISS, to capture
            the genuine transcript; a persisted-handle reuse skips it entirely.
  Phase 2 — (Only when the cache is disabled/unavailable.) Run the handshake
            once and use its transcript as a shared INLINE baseline — the
            original behaviour, with the schema re-sent per turn.
  Phase 3 — Schedule the tests across a thread pool, in one of two modes
            (config [parallel].mode):
              flat   — every test queued at once; runs as a worker slot frees.
              groups — tests bucketed by ID prefix; one test per group per
                       round, so groups advance together in lockstep rounds.
            A single SharedRateLimiter (TPM + RPM) paces ALL workers so the
            account-level Gemini quota is never exceeded.
  Phase 4 — Aggregate per-test stats and write the run summary.

Config reuse: base settings (paths, model, retries, …) are resolved by
``app.layer4.runner_config.resolve_settings``, shared with the sequential
runner, so there is one source of truth for the shared keys. This file adds a
``[parallel]`` section plus a few ``[gemini]`` keys (rpm_limit,
use_explicit_cache, cache_ttl_seconds).

Usage:
    python run_parallel.py --config config-gemini.ini
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import sys
import threading
import time
from pathlib import Path

from app.layer4.apk_navigator import APKNavigator
from app.layer4 import verdict_engine
from app.layer4.verdict_engine import (
    RunConfig, TestStats, banner,
    _finalize_test_stats, _run_one_attempt, _run_programmatic_test,
    _print_and_save_summary, _resolve_first_response_to_protocol,
    _log_turn,
)
from app.layer4.test_plan import load_test_plan, TestPlanError
from app.layer4.shared_rate_limiter import SharedRateLimiter
from app.layer4.verifier import Verifier, DEFAULT_VERIFIER_SYSTEM_PROMPT


# ============================================================
#  Test selection (regex)
# ============================================================

def _filter_entries_regex(entries, pattern):
    """Filter test entries by a case-insensitive regular expression matched
    (re.search) against each test_id OR the entry's `category` label. Empty/
    blank pattern selects everything.

    Unlike the sequential runner's substring filter, this accepts full regex,
    so 'storage|network' selects either category. Matching `category` means
    'crypto' selects the whole MASVS-CRYPTO group while 'MASTG-TEST-0202' still
    selects a single test. Raises re.error on a bad pattern (callers surface it
    before spending any tokens)."""
    if not pattern or not pattern.strip():
        return list(entries)
    rx = re.compile(pattern, re.IGNORECASE)
    return [e for e in entries
            if rx.search(e.test_id) or rx.search(e.category or "")]


# ============================================================
#  Shared config plumbing
# ============================================================
#
# The INI/CLI merge rules, the argument surface, and backend construction are
# shared with the sequential runner so both agree on precedence and defaults.
# They live in app/layer4/runner_config.py.
#
# This was previously an importlib shim that loaded a root-level script named
# `run_verdict_engine-parallel-tools-optimized.py` by file path — necessary
# only because hyphens make a filename unimportable as a module. The `runner`
# alias is kept so the ~5 call sites below read unchanged.

from app.layer4 import runner_config as runner


# ============================================================
#  Thread-safe logging
# ============================================================
#
# verdict_engine emits log lines from inside the per-test code paths. With
# many workers running concurrently those lines interleave. We wrap the
# module's logger with a lock (so lines don't tear) and a thread-local test
# prefix (so you can tell which test a line belongs to). Reassigning
# verdict_engine.log works because the module's functions resolve `log` from
# the module global at call time.

_log_lock = threading.Lock()
_log_tls = threading.local()
_orig_log = verdict_engine.log


def log(msg: str = "", color: str = "") -> None:
    prefix = getattr(_log_tls, "prefix", "")
    with _log_lock:
        _orig_log(f"{prefix}{msg}" if prefix else msg, color=color)


verdict_engine.log = log


# ============================================================
#  Extra (parallel-only) config keys
# ============================================================

def _read_parallel_settings(cp) -> dict:
    g = runner.cfg_get
    return {
        "mode": (g(cp, "parallel", "mode", default="flat") or "flat").lower(),
        "max_workers": g(cp, "parallel", "max_workers", default=4, cast=int),
        "group_by": (g(cp, "parallel", "group_by", default="alpha")
                     or "alpha").lower(),
        "rpm_limit": g(cp, "gemini", "rpm_limit", default=150, cast=int),
        "use_explicit_cache": g(cp, "gemini", "use_explicit_cache",
                                 default=False, cast=bool),
        "cache_ttl_seconds": g(cp, "gemini", "cache_ttl_seconds",
                               default=3600, cast=int),
        # [verifier] — second-opinion review of each verdict
        "verifier_enabled": g(cp, "verifier", "enabled",
                              default=False, cast=bool),
        "verifier_max_rounds": g(cp, "verifier", "max_rounds",
                                 default=1, cast=int),
        "verifier_model": g(cp, "verifier", "model", default=""),
        "verifier_system_prompt": g(cp, "verifier", "system_prompt", default=""),
        "verifier_include_test_prompt": g(cp, "verifier", "include_test_prompt",
                                          default=True, cast=bool),
        # openai/Ollama verifier only: off | object (json_object). 'schema' is
        # intentionally not offered here to stay backend-neutral.
        "verifier_json_mode": g(cp, "verifier", "json_mode", default="object"),
        # When true, log each verifier request, its token usage, and the reply.
        "verifier_verbose": g(cp, "verifier", "verbose", default=False,
                              cast=bool),
    }


# ============================================================
#  Explicit-cache handle persistence
# ============================================================
#
# Creating a Gemini explicit cache mints a NEW server-side object every time,
# so a fresh cache per run means redundant uploads + overlapping storage cost.
# We persist the handle to a small file next to the config and reuse it on the
# next run while it is still valid — both locally (not expired, fingerprint
# matches) and server-side (still resolvable).

CACHE_HANDLE_FILENAME = ".gemini_cache.json"
# Reuse only if at least this many seconds of TTL remain, so a cache doesn't
# expire mid-run.
CACHE_EXPIRY_MARGIN_SECONDS = 120.0


def _cache_fingerprint(model: str, system_prompt: str, schema_text: str,
                       tool_names) -> str:
    """Identity of the cached content. If any of these change, the persisted
    handle must NOT be reused (the cache holds the old content).

    Covers model, system prompt text, schema text (the schema is embedded in
    the cached handshake), and the SET of tool names — not individual tool
    descriptions/params. If you edit tool *declarations* without adding/
    removing a tool, delete the handle file to force a rebuild.
    """
    h = hashlib.sha256()
    h.update(model.encode("utf-8"))
    h.update(b"\0")
    h.update(system_prompt.encode("utf-8"))
    h.update(b"\0")
    h.update(schema_text.encode("utf-8"))
    h.update(b"\0")
    h.update(",".join(sorted(tool_names or [])).encode("utf-8"))
    return h.hexdigest()


def _load_persisted_cache(path: Path, *, model: str, fingerprint: str,
                          api_key: str) -> str | None:
    """Return a reusable cache name from the handle file, or None if it is
    missing, stale, fingerprint-mismatched, or no longer exists server-side."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if data.get("model") != model:
        return None
    if data.get("fingerprint") != fingerprint:
        return None
    if time.time() >= float(data.get("expire_at_epoch", 0)) \
            - CACHE_EXPIRY_MARGIN_SECONDS:
        return None
    name = data.get("cache_name")
    if not name:
        return None
    from app.layer4.backends.gemini_backend import explicit_cache_exists
    if not explicit_cache_exists(api_key=api_key, cache_name=name):
        return None
    return name


def _persist_cache(path: Path, *, cache_name: str, model: str,
                   fingerprint: str, ttl_seconds: int) -> None:
    payload = {
        "cache_name": cache_name,
        "model": model,
        "fingerprint": fingerprint,
        "created_at_epoch": time.time(),
        "expire_at_epoch": time.time() + ttl_seconds,
    }
    try:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log(f"  Cache handle persisted to {path}", color="dim")
    except Exception as exc:  # noqa: BLE001
        log(f"  ⚠ Could not persist cache handle to {path}: {exc}",
            color="yellow")


# ============================================================
#  Grouping
# ============================================================

def _group_key(test_id: str, group_by: str) -> str:
    """Derive a test's group bucket from its ID.

    alpha (default): first dash-segment that contains letters
                     ('1-STORAGE-1-1' → 'STORAGE', 'CODE-1-1' → 'CODE').
    first:           the first dash-segment verbatim.
    """
    segments = test_id.split("-")
    if group_by == "first":
        return segments[0]
    for seg in segments:
        if re.search(r"[A-Za-z]", seg):
            return seg.upper()
    return segments[0]


# ============================================================
#  Worker backend factory
# ============================================================

def _make_worker_backend(settings, system_prompt, *, cached_content,
                         rate_limiter):
    """Create a fresh backend with its OWN conversation history. For gemini we
    inject the shared explicit cache + shared rate limiter; other backends
    fall back to the sequential runner's factory (each worker still isolated)."""
    if settings["backend_type"] == "gemini":
        from app.layer4.backends.gemini_backend import GeminiBackend
        return GeminiBackend(
            api_key=settings["api_key"],
            model=settings["model"],
            system_prompt=system_prompt,
            tpm_limit=settings["tpm_limit"],
            max_request_retries=settings["max_request_retries"],
            request_retry_base_seconds=settings["request_retry_base_seconds"],
            request_retry_max_seconds=settings["request_retry_max_seconds"],
            cached_content=cached_content,
            rate_limiter=rate_limiter,
            log_fn=log,
        )
    return runner.make_backend(settings, system_prompt)


# ============================================================
#  Verifier
# ============================================================

def _build_verifier(settings, par, config_dir, rate_limiter):
    """Construct the optional verdict Verifier from [verifier] config, or None
    if disabled. Supports both gemini and openai/Ollama backends. The factory
    makes a fresh verifier-role backend per review (its own clean system
    prompt, no tools) so it is thread-safe across workers."""
    if not par["verifier_enabled"]:
        return None

    vp_path = par["verifier_system_prompt"]
    if vp_path:
        p = Path(vp_path)
        if not p.is_absolute():
            p = (config_dir / p).resolve()
        verifier_system_prompt = p.read_text()
    else:
        verifier_system_prompt = DEFAULT_VERIFIER_SYSTEM_PROMPT
    verifier_model = par["verifier_model"] or settings["model"]
    bt = settings["backend_type"]

    if bt == "gemini":
        from app.layer4.backends.gemini_backend import GeminiBackend

        def factory():
            return GeminiBackend(
                api_key=settings["api_key"],
                model=verifier_model,
                system_prompt=verifier_system_prompt,
                tpm_limit=settings["tpm_limit"],
                max_request_retries=settings["max_request_retries"],
                request_retry_base_seconds=settings["request_retry_base_seconds"],
                request_retry_max_seconds=settings["request_retry_max_seconds"],
                cached_content=None,       # verifier has its own system prompt
                rate_limiter=rate_limiter,  # verifier calls count against quota
                log_fn=log,
            )
        detail = f"model {verifier_model}"
    elif bt == "openai":
        from app.layer4.backends.openai_backend import OpenAIBackend
        # json_object is broadly supported (Ollama/vLLM/etc.); strict
        # json_schema is avoided here to stay backend-neutral. The verifier's
        # reply parser is lenient regardless.
        v_json_mode = par["verifier_json_mode"]

        def factory():
            return OpenAIBackend(
                base_url=settings["base_url"],
                api_key=settings["api_key"],
                model=verifier_model,
                system_prompt=verifier_system_prompt,
                temperature=settings["temperature"],
                json_mode=v_json_mode,
                request_timeout=settings["request_timeout"],
                max_request_retries=settings["max_request_retries"],
                request_retry_base_seconds=settings["request_retry_base_seconds"],
                request_retry_max_seconds=settings["request_retry_max_seconds"],
                num_ctx=settings["num_ctx"],
                max_tokens=settings["num_ctx"],
                decorate_system_prompt=False,  # clean prompt — not an analyst
                log_fn=log,
            )
        detail = f"model {verifier_model}, json_mode {par['verifier_json_mode']}"
    else:
        log(f"  ⚠ Verifier not supported for backend {bt!r}; disabling.",
            color="yellow")
        return None

    log(f"  Verifier: ENABLED — {detail}, "
        f"max_rounds {par['verifier_max_rounds']}, "
        f"include_test_prompt {par['verifier_include_test_prompt']}"
        f"{', verbose' if par['verifier_verbose'] else ''}",
        color="cyan")
    return Verifier(
        backend_factory=factory,
        max_rounds=par["verifier_max_rounds"],
        include_test_prompt=par["verifier_include_test_prompt"],
        verbose=par["verifier_verbose"],
        log_fn=log,
    )


# ============================================================
#  Per-test execution (one worker)
# ============================================================

def _run_llm_test(entry, settings, system_prompt, config, navigator, *,
                  baseline_history, baseline_evidence, cached_content,
                  rate_limiter, verifier) -> TestStats:
    """Run a single LLM test on its own backend seeded from the shared
    baseline. Mirrors run_batch's per-test retry loop, minus the inter-test
    reset (each worker owns an independent conversation, so there is nothing
    to reset between tests)."""
    backend = _make_worker_backend(
        settings, system_prompt,
        cached_content=cached_content, rate_limiter=rate_limiter,
    )
    backend.configure_tools(navigator)
    backend.restore_history(baseline_history)

    test_stats = TestStats(
        test_file=entry.prompt_path.name,
        test_stem=entry.test_id,
        category=entry.category,
        started_at=verdict_engine.datetime.now(
            verdict_engine.timezone.utc).isoformat(),
        started_monotonic=time.monotonic(),
    )

    sent_evidence_files = set(baseline_evidence)
    history_snapshot = backend.snapshot_history()
    evidence_snapshot = set(sent_evidence_files)
    tool_count_at_start = test_stats.tool_call_count
    tool_calls_at_start = list(test_stats.tool_calls)

    max_attempts = config.max_test_retries + 1
    for attempt_num in range(1, max_attempts + 1):
        if attempt_num > 1:
            log(f"  ↻ Retrying (attempt {attempt_num}/{max_attempts}) after "
                f"{config.retry_delay_seconds:.0f}s...", color="yellow")
            time.sleep(config.retry_delay_seconds)
            backend.restore_history(history_snapshot)
            sent_evidence_files = set(evidence_snapshot)
            test_stats.tool_call_count = tool_count_at_start
            test_stats.tool_calls = list(tool_calls_at_start)

        attempt = _run_one_attempt(
            backend, navigator, config, entry.prompt_path, test_stats,
            sent_evidence_files, attempt_num, verifier=verifier,
        )
        test_stats.attempts.append(attempt)

        if attempt.status == "ok":
            test_stats.status = "ok"
            test_stats.succeeded_on_attempt = attempt_num
            break

        log(f"  ✗ Attempt {attempt_num}/{max_attempts} failed: "
            f"{attempt.status} ({attempt.error})", color="red")
        if attempt_num >= max_attempts:
            test_stats.status = attempt.status
            test_stats.error = attempt.error
            test_stats.raw_response = attempt.raw_response
            test_stats.verdict_turn_tokens = attempt.verdict_turn_tokens

    _finalize_test_stats(test_stats)
    return test_stats


def _run_entry(entry, settings, system_prompt, config, navigator, *,
               baseline_history, baseline_evidence, cached_content,
               rate_limiter, verifier) -> TestStats:
    """Dispatch one test entry (programmatic or LLM) and always return a
    TestStats — failures are captured, never lost from the summary."""
    _log_tls.prefix = f"[{entry.test_id}] "
    try:
        banner(f"Test {entry.test_id} ({entry.type})", color="magenta")
        if entry.type == "programmatic":
            collected: list[TestStats] = []
            _run_programmatic_test(entry, config, collected)
            return collected[0]
        return _run_llm_test(
            entry, settings, system_prompt, config, navigator,
            baseline_history=baseline_history,
            baseline_evidence=baseline_evidence,
            cached_content=cached_content, rate_limiter=rate_limiter,
            verifier=verifier,
        )
    except Exception as exc:  # noqa: BLE001 — keep one failure from sinking all
        log(f"  ✗ Worker crashed: {type(exc).__name__}: {exc}", color="red")
        ts = TestStats(
            test_file=getattr(getattr(entry, "prompt_path", None), "name",
                              f"<{entry.test_id}>"),
            test_stem=entry.test_id,
            category=entry.category,
            started_at=verdict_engine.datetime.now(
                verdict_engine.timezone.utc).isoformat(),
            started_monotonic=time.monotonic(),
        )
        ts.status = "exception"
        ts.error = f"{type(exc).__name__}: {exc}"
        _finalize_test_stats(ts)
        return ts
    finally:
        _log_tls.prefix = ""


def _run_programmatic_entry(entry, config) -> TestStats:
    """Run a single programmatic test. These need no backend, cache, rate
    limiter or verifier, so they execute before any LLM phase — a
    programmatic-only selection therefore spends zero tokens."""
    _log_tls.prefix = f"[{entry.test_id}] "
    try:
        banner(f"Test {entry.test_id} (programmatic)", color="magenta")
        collected: list[TestStats] = []
        _run_programmatic_test(entry, config, collected)
        return collected[0]
    except Exception as exc:  # noqa: BLE001 — never sink the whole batch
        log(f"  ✗ Worker crashed: {type(exc).__name__}: {exc}", color="red")
        ts = TestStats(
            test_file=f"<{entry.test_id}>",
            test_stem=entry.test_id,
            category=entry.category,
            started_at=verdict_engine.datetime.now(
                verdict_engine.timezone.utc).isoformat(),
            started_monotonic=time.monotonic(),
        )
        ts.status = "exception"
        ts.error = f"{type(exc).__name__}: {exc}"
        _finalize_test_stats(ts)
        return ts
    finally:
        _log_tls.prefix = ""


# ============================================================
#  Schedulers
# ============================================================

def _schedule_flat(entries, run_one, max_workers) -> list[TestStats]:
    """Every test queued at once; runs as worker slots free up."""
    results: list[TestStats] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="vtest",
    ) as pool:
        futures = {pool.submit(run_one, e): e for e in entries}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    return results


def _schedule_groups(entries, run_one, max_workers, group_by) -> list[TestStats]:
    """Bucket tests by group; run one test per group per round so the groups
    advance together in lockstep rounds."""
    buckets: dict[str, list] = {}
    order: list[str] = []
    for e in entries:
        k = _group_key(e.test_id, group_by)
        if k not in buckets:
            buckets[k] = []
            order.append(k)
        buckets[k].append(e)

    log(f"  Groups ({len(order)}): "
        + ", ".join(f"{k}×{len(buckets[k])}" for k in order), color="cyan")

    results: list[TestStats] = []
    round_num = 0
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="vtest",
    ) as pool:
        while any(buckets[k] for k in order):
            round_num += 1
            round_entries = [buckets[k].pop(0) for k in order if buckets[k]]
            log(f"\n  ── Round {round_num}: {len(round_entries)} test(s) "
                f"in flight ──", color="bold")
            futures = [pool.submit(run_one, e) for e in round_entries]
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())  # barrier: round advances together
    return results


# ============================================================
#  Bootstrap handshake (run once, inline — no cache)
# ============================================================

def _run_handshake(settings, system_prompt, schema_text, navigator, *,
                   rate_limiter):
    """Run the deterministic bootstrap handshake on a fresh INLINE backend
    (system prompt + tools sent directly, no explicit cache) and return the
    resulting conversation history — the transcript
    ``[Begin, getSchema, schema, getPrompt]``.

    This transcript is either embedded into the explicit cache (so the schema
    is cached) or used directly as the shared inline baseline. Returns None if
    the model does not reach getSchema (a hard bootstrap failure).
    """
    backend = _make_worker_backend(
        settings, system_prompt, cached_content=None, rate_limiter=rate_limiter,
    )
    backend.configure_tools(navigator)

    result = backend.send_user_message("Begin.", label="kickoff")
    _log_turn(result, label="MODEL")
    msg = _resolve_first_response_to_protocol(backend, result)
    if not msg or msg.get("operation") != "getSchema":
        log(f"❌ Expected getSchema. Got: {msg!r}", color="red")
        return None

    intro = (
        "Here is the evidence schema. Level 2 (decompiled Java, manifest, "
        "resources) and level 3 (smali bytecode) are NOT delivered upfront. "
        "When your protocol's escalation rules require you to consult them, "
        "use the available tools (read_file, find_class, find_subclasses, "
        "list_imports, list_dir, grep, search_code) to fetch the specific "
        "bytes you need."
    )
    result = backend.send_user_message(
        f"{intro}\n\n=== schema.md ===\n{schema_text}", label="schema",
    )
    _log_turn(result, label="MODEL")
    msg = _resolve_first_response_to_protocol(backend, result)
    if not msg or msg.get("operation") != "getPrompt":
        log(f"⚠ Expected getPrompt. Got: {msg!r} (continuing)", color="yellow")

    log(f"  Handshake complete ({backend.history_length()} turns).",
        color="cyan")
    return backend.snapshot_history()


# ============================================================
#  Main
# ============================================================

def main() -> int:
    args = runner.build_argparser().parse_args()
    settings = runner.resolve_settings(args)
    cp = runner.load_config_file(args.config) if args.config else None
    par = _read_parallel_settings(cp)
    config_dir = args.config.parent.resolve() if args.config else Path.cwd()

    system_prompt = settings["system_prompt"].read_text()

    # Effective test filter (treated as a case-insensitive regex):
    #   --test-filter  >  [paths].prompts_mask (legacy)  >  [paths].test_filter
    # resolve_settings already folds the first two into settings['test_filter'];
    # here we also honour a plain [paths].test_filter key.
    if not settings["test_filter"]:
        cfg_tf = runner.cfg_get(cp, "paths", "test_filter")
        if cfg_tf:
            settings["test_filter"] = cfg_tf
    test_filter = settings["test_filter"]

    # ---------------- Phase 0: test selection + APK indexing ----------
    banner("Phase 0  ·  Test selection & APK indexing")

    # 0a — Resolve & DISPLAY the selection first, before any token spend
    # (cache creation / handshake). Bail early on an empty match or bad regex.
    try:
        plan = load_test_plan(settings["test_plan_dir"])
    except TestPlanError as exc:
        log(f"Failed to load test plan: {exc}", color="red")
        return 1
    try:
        entries = _filter_entries_regex(plan.entries, test_filter)
    except re.error as exc:
        log(f"Invalid --test-filter regex {test_filter!r}: {exc}", color="red")
        return 1
    total = len(plan.entries)
    if not entries:
        log(f"No tests in plan {plan.name!r} matched filter {test_filter!r} "
            f"({total} test(s) available).", color="red")
        return 1
    log(f"  Plan {plan.name!r}: {len(entries)}/{total} test(s) matched "
        f"filter {test_filter or '(none — all tests)'!r}:", color="cyan")
    n_llm = sum(1 for e in entries if e.type == "llm")
    n_prog = len(entries) - n_llm
    for i, e in enumerate(entries, 1):
        log(f"    {i:>3}. {e.test_id}  ({e.type})", color="cyan")
    log(f"  → {len(entries)} selected: {n_llm} llm, {n_prog} programmatic",
        color="cyan")

    # 0b — Index the APK once (no tokens).
    log(f"  Backend: {settings['backend_type']} / {settings['model']}",
        color="cyan")
    log(f"  APK root: {settings['apk_root']}", color="cyan")
    log(f"  Mode: {par['mode']}  ·  max_workers: {par['max_workers']}",
        color="cyan")

    navigator = APKNavigator(
        settings["apk_root"],
        evidence_dir=settings["evidence_dir"],
        rag=None,
        log_fn=log,
    )
    istats = navigator.index.stats()
    log(f"  Index: {istats['classes']} classes "
        f"({istats['java_classes']} java, {istats['smali_classes']} smali)",
        color="green")

    # Pre-warm the evidence index so worker threads only ever READ the shared
    # dicts (lazy per-file loading is not thread-safe).
    evidence_files = navigator.evidence_index.list_files()
    for fname in evidence_files:
        try:
            navigator.evidence_index._load(fname)
        except Exception as exc:  # noqa: BLE001
            log(f"  ⚠ pre-warm failed for {fname}: {exc}", color="yellow")
    log(f"  Evidence: pre-warmed {len(evidence_files)} file(s)", color="green")

    config = RunConfig(
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
    config.output_dir.mkdir(parents=True, exist_ok=True)

    is_gemini = settings["backend_type"] == "gemini"

    # Split the selection. Programmatic tests need no backend/cache/handshake,
    # so they run FIRST; the token-spending LLM phases happen only if there are
    # LLM tests — a programmatic-only run therefore spends zero tokens.
    prog_entries = [e for e in entries if e.type == "programmatic"]
    llm_entries = [e for e in entries if e.type == "llm"]

    summary: list[TestStats] = []
    started = time.monotonic()
    rate_limiter = None

    # Lightweight backend for summary metadata only. Constructing it makes NO
    # API call, so it is token-free even when every LLM phase is skipped.
    meta_backend = _make_worker_backend(
        settings, system_prompt, cached_content=None, rate_limiter=None,
    )

    # ---------------- Phase 1: programmatic tests (no tokens) ----------
    if prog_entries:
        banner(f"Phase 1  ·  {len(prog_entries)} programmatic test(s) "
               f"(no LLM — no tokens)")
        summary.extend(_schedule_flat(
            prog_entries,
            lambda e: _run_programmatic_entry(e, config),
            par["max_workers"],
        ))

    # ---------------- LLM phases (only if LLM tests are selected) -------
    if llm_entries:
        if is_gemini:
            rate_limiter = SharedRateLimiter(
                tpm_limit=settings["tpm_limit"],
                rpm_limit=par["rpm_limit"],
                log_fn=log,
            )
            log(f"  Rate limiter: TPM≤{settings['tpm_limit']:,}, "
                f"RPM≤{par['rpm_limit']} (shared across workers)", color="cyan")

        verifier = _build_verifier(settings, par, config_dir, rate_limiter)

        schema_text = config.schema.read_text()
        baseline_evidence: set[str] = set()
        cached_content = None
        baseline_history = None

        # ------------ Phase 2: explicit cache (persisted handle) -------
        if is_gemini and par["use_explicit_cache"]:
            banner("Phase 2  ·  Explicit cache (system prompt + schema + tools)")
            from app.layer4.backends.gemini_backend import create_explicit_cache
            cache_path = config_dir / CACHE_HANDLE_FILENAME
            tool_names = getattr(navigator, "TOOL_NAMES", None)
            fingerprint = _cache_fingerprint(
                settings["model"], system_prompt, schema_text, tool_names,
            )
            cached_content = _load_persisted_cache(
                cache_path, model=settings["model"], fingerprint=fingerprint,
                api_key=settings["api_key"],
            )
            if cached_content:
                # Whole prefix (system + schema + handshake) is cached, so
                # workers start from an EMPTY live history; no handshake needed.
                log(f"  Reusing persisted cache {cached_content} (from "
                    f"{cache_path}). Schema is cached — skipping handshake.",
                    color="green")
                baseline_history = []
            else:
                # Cache miss: run the handshake ONCE to capture the genuine
                # transcript, then embed it (schema included) into a new cache.
                banner("Phase 3  ·  Bootstrap handshake (to build the cache)")
                transcript = _run_handshake(
                    settings, system_prompt, schema_text, navigator,
                    rate_limiter=rate_limiter,
                )
                if transcript is None:
                    return 1
                try:
                    cached_content = create_explicit_cache(
                        api_key=settings["api_key"],
                        model=settings["model"],
                        system_prompt=system_prompt,
                        navigator=navigator,
                        handshake_contents=transcript,
                        ttl_seconds=par["cache_ttl_seconds"],
                        log_fn=log,
                    )
                    _persist_cache(
                        cache_path, cache_name=cached_content,
                        model=settings["model"], fingerprint=fingerprint,
                        ttl_seconds=par["cache_ttl_seconds"],
                    )
                    baseline_history = []  # transcript now lives in the cache
                except Exception as exc:  # noqa: BLE001
                    log(f"  ⚠ Explicit cache unavailable "
                        f"({type(exc).__name__}: {exc}). Falling back to "
                        f"inline schema in baseline.", color="yellow")
                    cached_content = None
                    baseline_history = transcript  # inline: re-sent per turn

        # ------- Phase 3 (inline path): handshake → inline baseline ----
        if baseline_history is None:
            banner("Phase 3  ·  Bootstrap handshake (shared inline baseline)")
            baseline_history = _run_handshake(
                settings, system_prompt, schema_text, navigator,
                rate_limiter=rate_limiter,
            )
            if baseline_history is None:
                return 1

        if cached_content:
            log("  Workers seed from EMPTY history; full prefix (incl. schema) "
                "served from cache.", color="cyan")
        else:
            log(f"  Workers seed from inline baseline "
                f"({len(baseline_history)} turns); schema re-sent per turn.",
                color="cyan")

        # ------------ Phase 4: schedule the LLM tests ----------
        banner(f"Phase 4  ·  Running {len(llm_entries)} LLM test(s) — "
               f"mode={par['mode']}")

        def run_one(entry):
            return _run_entry(
                entry, settings, system_prompt, config, navigator,
                baseline_history=baseline_history,
                baseline_evidence=baseline_evidence,
                cached_content=cached_content, rate_limiter=rate_limiter,
                verifier=verifier,
            )

        if par["mode"] == "groups":
            summary.extend(_schedule_groups(
                llm_entries, run_one, par["max_workers"], par["group_by"],
            ))
        else:
            summary.extend(_schedule_flat(
                llm_entries, run_one, par["max_workers"],
            ))
    elif prog_entries:
        log("\n  No LLM tests selected — skipped cache/handshake; "
            "zero tokens spent.", color="green")

    wall = time.monotonic() - started

    # Keep summary in test-plan order for readability.
    order = {e.test_id: i for i, e in enumerate(entries)}
    summary.sort(key=lambda s: order.get(s.test_stem, 1_000_000))

    # ---------------- Summary ----------------
    _print_and_save_summary(meta_backend, navigator, config, summary)
    log(f"\n  Wall-clock: {verdict_engine.format_duration(wall)} "
        f"({wall:.1f}s) for {len(summary)} test(s) "
        f"({len(prog_entries)} programmatic, {len(llm_entries)} llm) at "
        f"{par['max_workers']} workers", color="green")
    if rate_limiter is not None:
        snap = rate_limiter.snapshot()
        log(f"  Final rate window: RPM {snap['rpm_in_window']}/"
            f"{snap['rpm_budget']}, TPM {snap['tpm_in_window']:,}/"
            f"{snap['tpm_budget']:,}", color="dim")

    # Verifier aggregate — makes it unmistakable whether the verifier ran.
    if par["verifier_enabled"]:
        reviews = [rv for s in summary for rv in (s.verifier_reviews or [])]
        if reviews:
            tests_reviewed = sum(1 for s in summary if s.verifier_reviews)
            accepted = sum(1 for rv in reviews if rv.get("acceptable"))
            revisions = sum(1 for rv in reviews
                            if rv.get("phase") == "post-revision")
            vtok = sum((rv.get("usage") or {}).get("total_tokens") or 0
                       for rv in reviews)
            log(f"  Verifier: {len(reviews)} review(s) across "
                f"{tests_reviewed} test(s) — {accepted} accepted, "
                f"{len(reviews) - accepted} rejected, {revisions} revision(s), "
                f"{vtok:,} tokens", color="cyan")
        else:
            log("  Verifier: ENABLED but produced 0 reviews. If LLM tests ran, "
                "check that you launched run_parallel.py (the sequential "
                "runner does not call the verifier).", color="yellow")

    ok = sum(1 for r in summary if r.status == "ok")
    return 0 if ok == len(summary) else 2


if __name__ == "__main__":
    sys.exit(main())
