"""
verdict_engine.py — Backend-agnostic verdict engine.

This module owns the protocol loop, the per-test loop, evidence delivery,
tool-call resolution, retry logic, and summary printing. It speaks only to
the abstract Backend interface — never directly to any LLM SDK.

Public entry point: run_batch(backend, navigator, ...).

Conversation flow per session:

    Initialization:
        Code: "Begin." (kickoff)
        LLM:  getSchema
        Code: schema text
        LLM:  getPrompt

    Per-test loop:
        Code: per-test prompt
        LLM:  getEvidence  -OR-  tool calls  -OR-  verdict directly
        Code: requested L1 evidence inline (slim strings.json on the fly)
        LLM:  reasoning turns with tool calls
              → resolved locally via APKNavigator
              → results fed back as tool responses
              → loop until LLM emits a final response with no tool_calls
        Code: stores verdict, sends `reset prompt`
        LLM:  ack
"""

from __future__ import annotations

import ujson
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.layer4.backends.base import Backend, ToolCall, ToolResponse, TurnResult

from .test_plan import (
    TestEntry, TestPlan, TestPlanError, filter_entries, load_test_plan,
)


# ============================================================
#  Logging (shared with the runner script)
# ============================================================

C = {
    "cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m",
    "red": "\033[31m", "dim": "\033[2m", "bold": "\033[1m",
    "magenta": "\033[35m", "blue": "\033[34m", "reset": "\033[0m",
}

# A response is accepted as a verdict only if it has all three of these
# fields. A dict with just "verdict" set could be an in-progress thought
# rather than the final answer.
_VERDICT_REQUIRED_FIELDS = ("verdict", "certainty_percent", "evidence_table")

# How many times to re-prompt the model when it returns something other
# than a verdict at the verdict stage. Three handles "model needs one
# more evidence batch then commits" but bails on persistent confusion.
MAX_RECOVERY_ATTEMPTS = 3


def log(msg: str = "", color: str = "") -> None:
    prefix = C.get(color, "")
    suffix = C["reset"] if prefix else ""
    print(f"{prefix}{msg}{suffix}", file=sys.stderr)


def banner(title: str, color: str = "bold") -> None:
    log("")
    log("=" * 70, color="dim")
    log(title, color=color)
    log("=" * 70, color="dim")


# ============================================================
#  Protocol message parser
# ============================================================

def parse_protocol_message(text: str) -> dict | None:
    """Parse a JSON protocol message. Tolerates ```json fences, harmony channel
    markers, and concatenated duplicate JSON objects. Returns the FIRST valid
    JSON object found."""
    if not text:
        return None
    cleaned = text.strip()
    cleaned = re.sub(r"<\|channel\|>\w+<\|message\|>", "", cleaned)
    cleaned = re.sub(r"<\|(?:start|end|return|call|message|channel)\|>\w*", "",
                     cleaned)
    cleaned = cleaned.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if "\n" in cleaned:
            cleaned = cleaned.split("\n", 1)[1]
        if "```" in cleaned:
            cleaned = cleaned.rsplit("```", 1)[0]
    cleaned = cleaned.strip()
    if not cleaned:
        return None

    decoder = json.JSONDecoder()
    first_brace = cleaned.find("{")
    if first_brace < 0:
        return None
    try:
        parsed, end = decoder.raw_decode(cleaned, first_brace)
        trailing = cleaned[end:].strip()
        if trailing:
            preview = trailing[:80].replace("\n", " ")
            log(f"  · parse_protocol_message: ignored {len(trailing):,} chars "
                f"of trailing content: {preview!r}"
                f"{'...' if len(trailing) > 80 else ''}",
                color="dim")
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _classify_response(text: str | None) -> tuple[str, dict | None]:
    """Classify what the model emitted at the verdict stage.

    Returns (category, parsed) where category is one of:
      "verdict"      — parsed has all required verdict fields
      "getEvidence"  — parsed is a getEvidence protocol message
      "getPrompt"    — parsed is a getPrompt protocol message
      "empty"        — text is None, "", or whitespace-only
      "unknown_json" — parsed as JSON but not a recognized shape
      "nonjson"      — text exists but isn't JSON
    """
    if not text or not text.strip():
        return ("empty", None)
    parsed = parse_protocol_message(text)
    if parsed is None:
        return ("nonjson", None)
    op = parsed.get("operation")
    if op == "getEvidence":
        return ("getEvidence", parsed)
    if op == "getPrompt":
        return ("getPrompt", parsed)
    if all(k in parsed for k in _VERDICT_REQUIRED_FIELDS):
        return ("verdict", parsed)
    return ("unknown_json", parsed)


def _nudge_and_resolve(
    backend, navigator, test_stats, config, *, prompt: str, label: str,
):
    """Send a recovery prompt to the model, log the response, and run the
    standard tool-resolution loop. Returns (final_text, final_usage)."""
    result = backend.send_user_message(prompt, label=label)
    _log_turn(result, label="MODEL")
    return _resolve_tools(
        backend, navigator, result, test_stats,
        max_iterations=config.max_tool_iterations,
    )

# ============================================================
#  Protocol-as-tool-call collision detection
# ============================================================

PROTOCOL_OP_NAMES = {"getSchema", "getEvidence", "getPrompt", "reset"}


def detect_protocol_call_collision(tool_calls: list[ToolCall]) -> dict | None:
    """If a single tool_call has a name matching a protocol op, lift it back
    into a protocol-message dict. Used when the model packages a protocol
    response as a function call."""
    if not tool_calls or len(tool_calls) != 1:
        return None
    call = tool_calls[0]
    if call.name not in PROTOCOL_OP_NAMES:
        return None
    parsed = call.args
    if isinstance(parsed, dict) and parsed.get("operation") == call.name:
        return parsed
    if isinstance(parsed, dict) and "args" in parsed:
        return {"status": "prompted", "operation": call.name,
                "args": parsed["args"]}
    if isinstance(parsed, list):
        return {"operation": call.name, "args": parsed}
    return {"operation": call.name, "args": "None"}


# ============================================================
#  Test-stat dataclasses
# ============================================================

@dataclass
class AttemptRecord:
    """Outcome of a single attempt at running a test."""
    attempt: int
    status: str  # ok | parse_error | protocol_error | tool_loop_overflow | exception
    duration_seconds: float
    verdict: str | None = None
    certainty: int | None = None
    evidence_table_rows: int | None = None
    tool_call_count: int = 0
    error: str | None = None
    raw_response: str | None = None
    verdict_turn_tokens: dict = field(default_factory=dict)


@dataclass
class TestStats:
    test_file: str
    test_stem: str
    started_at: str
    started_monotonic: float = 0.0
    category: str = ""
    finished_at: str | None = None
    duration_seconds: float | None = None
    status: str = "running"
    verdict: str | None = None
    certainty: int | None = None
    evidence_table_rows: int | None = None
    evidence_delivered: list = field(default_factory=list)
    evidence_via_tools: list = field(default_factory=list)
    evidence_already_inline: list = field(default_factory=list)
    evidence_already_via_tools: list = field(default_factory=list)
    evidence_missing: list = field(default_factory=list)
    tool_calls: list = field(default_factory=list)
    tool_call_count: int = 0
    verdict_turn_tokens: dict = field(default_factory=dict)
    error: str | None = None
    raw_response: str | None = None
    attempts: list = field(default_factory=list)
    succeeded_on_attempt: int | None = None
    verifier_reviews: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v not in (None, [], {})}
        d.pop("started_monotonic", None)
        if "attempts" in d:
            d["attempts"] = [
                {k: v for k, v in a.__dict__.items() if v not in (None, [], {})}
                for a in d["attempts"]
            ]
        return d


def utc_now() -> str:
    """Current UTC time as an ISO-8601 string. One definition, used by the
    engine, the facade and the validator alike."""
    return datetime.now(timezone.utc).isoformat()


SCHEMA_INTRO = (
    "Here is the evidence schema. Level 2 (decompiled Java, manifest, "
    "resources) and level 3 (smali bytecode) are NOT delivered upfront. "
    "When your protocol's escalation rules require you to consult them, "
    "use the available tools (read_file, find_class, find_subclasses, "
    "list_imports, list_dir, grep, search_code) to fetch the specific "
    "bytes you need."
)


def bootstrap_session(
    backend: Backend, schema_text: str, *, strict: bool = False,
) -> bool:
    """Run the protocol handshake on a fresh backend session:

        Begin.  →  getSchema  →  schema text  →  getPrompt

    A session MUST go through this before any test prompt is sent. The system
    prompt defines a stateful protocol that begins by negotiating the schema;
    a backend that jumps straight to a test prompt has a model that never saw
    the evidence schema and is one step out of step with its own instructions.

    Returns True when both stages answered as expected. `strict=False` keeps
    the long-standing tolerance for a missing `getPrompt` (it is logged, not
    fatal); a missing `getSchema` always returns False because the schema was
    then never delivered.

    Shared by `run_batch` and by `EngineAPI`, so the handshake exists once.
    """
    result = backend.send_user_message("Begin.", label="kickoff")
    _log_turn(result, label="MODEL")
    msg = _resolve_first_response_to_protocol(backend, result)
    if not msg or msg.get("operation") != "getSchema":
        log(f"❌ Expected getSchema. Got: {msg!r}", color="red")
        return False

    result = backend.send_user_message(
        f"{SCHEMA_INTRO}\n\n=== schema.md ===\n{schema_text}", label="schema",
    )
    _log_turn(result, label="MODEL")
    msg = _resolve_first_response_to_protocol(backend, result)
    if not msg or msg.get("operation") != "getPrompt":
        log(f"❌ Expected getPrompt. Got: {msg!r}", color="red")
        return not strict
    return True


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m {s % 60:02d}s"


# Names the model might list in getEvidence that no longer apply with function
# calling. Drop them silently.
ALREADY_PROVIDED_VIA_TOOLS = {
    "apktool.xml", "jadx.xml", "apktool.tar", "jadx.tar",
}


# ============================================================
#  Run config
# ============================================================

@dataclass
class RunConfig:
    """Aggregates all the per-batch settings the engine needs.
    Backend-specific settings (model, base_url, etc.) are on the backend."""
    apk_root: Path
    schema: Path
    evidence_dir: Path
    test_plan_dir: Path
    test_filter: str
    output_dir: Path
    max_tool_iterations: int = 50
    max_test_retries: int = 2
    retry_delay_seconds: float = 10.0
    abort_on_error: bool = False
    # Files at or below this size in bytes are delivered inline as full
    # content in response to getEvidence. Files above this size are NOT
    # delivered inline — instead, the engine acknowledges that the file
    # is available via the navigator's evidence tools (get_evidence_record,
    # match_evidence_records, count_evidence_records). The model already
    # received the L1 schema describing each file's structure at bootstrap;
    # combined with these tools and list_evidence_files, that's sufficient
    # to investigate without paying inline-delivery token costs.
    inline_evidence_max_bytes: int = 10_240


# ============================================================
#  Tool resolution loop
# ============================================================

def _resolve_tools(
    backend: Backend,
    navigator,
    initial_result: TurnResult,
    test_stats: TestStats,
    *,
    max_iterations: int,
) -> tuple[str, dict]:
    """Iterate: model emits tool calls → we execute them → return results to
    model → repeat until model emits a final text response with no calls.
    Returns (final_text, final_usage_dict)."""
    text = initial_result.text
    calls = initial_result.tool_calls
    usage = initial_result.usage

    for iteration in range(max_iterations):
        if not calls:
            return text, _usage_to_dict(usage)

        # Check for mid-reasoning protocol-as-tool-call collision
        collision = detect_protocol_call_collision(calls)
        if collision is not None:
            log(f"  · Protocol-as-tool-call during reasoning: "
                f"'{calls[0].name}' lifted into protocol form.", color="dim")
            backend.ack_protocol_tool_calls(calls)
            return ujson.dumps(collision), _usage_to_dict(usage)

        # Execute the tools and build response messages
        tool_responses: list[ToolResponse] = []
        for call in calls:
            test_stats.tool_call_count += 1
            test_stats.tool_calls.append({"name": call.name, "args": call.args})
            try:
                result = navigator.call(call.name, call.args)
                payload: dict | str = {"result": result}
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
                log(f"    ⚠ tool error in {call.name}: {err}", color="yellow")
                payload = {"error": err}
            tool_responses.append(ToolResponse(
                tool_call_id=call.id, name=call.name, content=payload,
            ))

        result = backend.send_tool_responses(
            tool_responses,
            label=f"tool responses (iter {iteration + 1}, "
                  f"{len(tool_responses)} result(s))",
        )
        _log_turn(result, label="MODEL")
        text, calls, usage = result.text, result.tool_calls, result.usage

    raise RuntimeError(
        f"Exceeded {max_iterations} tool iterations without a final response."
    )


def _usage_to_dict(usage) -> dict:
    return {
        k: v for k, v in {
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
        }.items() if v is not None
    }

_VERDICT_REQUIRED_FIELDS = ("verdict", "certainty_percent", "evidence_table")

def _classify_response(text: str | None) -> tuple[str, dict | None]:
    """Classify what the model emitted at a stage where we expected a
    verdict. Returns (category, parsed) where category is one of:
    "verdict"      — parsed has all required verdict fields
    "getEvidence"  — parsed is a getEvidence protocol message
    "getPrompt"    — parsed is a getPrompt protocol message
    "empty"        — text is None, "", or whitespace-only
    "unknown_json" — parsed JSON but not a recognized shape
    "nonjson"      — text exists but isn't JSON

    `parsed` is the parsed dict for the JSON cases, None otherwise.
    """

    if not text or not text.strip():
        return ("empty", None)

    parsed = parse_protocol_message(text)
    if parsed is None:
        return ("nonjson", None)

    op = parsed.get("operation")
    if op == "getEvidence":
        return ("getEvidence", parsed)
    if op == "getPrompt":
        return ("getPrompt", parsed)

    if all(k in parsed for k in _VERDICT_REQUIRED_FIELDS):
        return ("verdict", parsed)

    return ("unknown_json", parsed)

def _log_turn(result: TurnResult, *, label: str) -> None:
    if result.tool_calls:
        log(f"<<< {label}  [{len(result.tool_calls)} tool call(s)]",
            color="green")
        for tc in result.tool_calls:
            args_preview =ujson.dumps(tc.args)[:200]
            log(f"  → {tc.name}({args_preview})", color="cyan")
    if result.text:
        log(f"<<< {label}  [text]", color="green")
        log(result.text)
    if not result.tool_calls and not result.text:
        log(f"<<< {label}  [empty response]", color="red")
    if result.usage and result.usage.prompt_tokens:
        cached_str = (
            f" cached={result.usage.cached_tokens}"
            if result.usage.cached_tokens is not None else ""
        )
        log(f"    [tokens: prompt={result.usage.prompt_tokens} "
            f"completion={result.usage.completion_tokens} "
            f"total={result.usage.total_tokens}]"
            f"{cached_str}", color="dim")


# ============================================================
#  Reset between tests
# ============================================================

def _try_reset_prompt(backend: Backend) -> bool:
    """Send `{"operation": "reset", "args": "prompt"}` and verify ack.
    Returns True if reset succeeded."""
    result = backend.send_user_message(
       ujson.dumps({"operation": "reset", "args": "prompt"}),
        label="reset prompt",
    )
    _log_turn(result, label="MODEL")
    if result.tool_calls:
        collision = detect_protocol_call_collision(result.tool_calls)
        if collision is not None:
            log(f"  · Protocol-as-tool-call on reset: lifting "
                f"'{result.tool_calls[0].name}'.", color="dim")
            backend.ack_protocol_tool_calls(result.tool_calls)
        else:
            log("  ⚠ Reset triggered tool calls; acking and treating "
                "ack-text as authoritative.", color="yellow")
            backend.ack_protocol_tool_calls(result.tool_calls)
    msg = parse_protocol_message(result.text)
    ok = bool(msg and msg.get("response_code") == "ok")
    if not ok:
        log(f"  ⚠ Reset failed. Model said: {result.text}", color="yellow")
    return ok


# ============================================================
#  Per-test execution (one attempt)
# ============================================================

def _verify_and_revise(
    backend: Backend,
    navigator,
    config: RunConfig,
    verifier,
    verdict: dict,
    final_usage: dict,
    test_stats: TestStats,
    test_prompt: str,
) -> tuple[dict, dict]:
    """Review `verdict` with the verifier; on rejection, ask the analyst
    session to revise (up to verifier.max_rounds revisions), re-reviewing each
    revision. Returns the (possibly revised) verdict and the latest usage dict.
    Always returns a usable verdict — the verifier is a quality gate, not a
    hard failure path.

    `max_rounds` is the number of REVISION attempts. An initial review is
    always performed; each revision is followed by a fresh review. So
    max_rounds=1 means: review → (if rejected) revise once → re-review → save.
    """
    def _record(review, *, rnd, phase):
        test_stats.verifier_reviews.append({
            "round": rnd,
            "phase": phase,
            "acceptable": review.acceptable,
            "comments": review.comments,
            "parse_error": review.parse_error,
            "usage": review.usage,
        })

    # --- Initial review ---
    log(f"  → Verifier reviewing verdict "
        f"(verdict={verdict.get('verdict')!r}, max_rounds="
        f"{verifier.max_rounds})…", color="cyan")
    review = verifier.review(verdict, test_prompt=test_prompt)
    _record(review, rnd=0, phase="initial")
    if review.acceptable:
        log("  ✓ Verifier accepted the verdict.", color="green")
        return verdict, final_usage
    log(f"  ⚑ Verifier rejected the verdict: {review.comments[:200]}"
        f"{'…' if len(review.comments) > 200 else ''}", color="yellow")

    # --- Revision cycles ---
    for rev in range(1, verifier.max_rounds + 1):
        log(f"  ↻ Asking the analyst to revise "
            f"(revision {rev}/{verifier.max_rounds})…", color="cyan")
        nudge_result = backend.send_user_message(
            verifier.build_nudge(review),
            label=f"verifier revision {rev}",
        )
        _log_turn(nudge_result, label="MODEL")
        revised_text, final_usage = _resolve_tools(
            backend, navigator, nudge_result, test_stats,
            max_iterations=config.max_tool_iterations,
        )
        category, parsed = _classify_response(revised_text)
        if category != "verdict":
            log(f"  · Revision {rev} did not yield a clean verdict "
                f"(category={category}); keeping the prior verdict.",
                color="yellow")
            return verdict, final_usage
        verdict = parsed

        # Re-review the revised verdict.
        review = verifier.review(verdict, test_prompt=test_prompt)
        _record(review, rnd=rev, phase="post-revision")
        if review.acceptable:
            log(f"  ✓ Verifier accepted the revised verdict "
                f"(after revision {rev}).", color="green")
            return verdict, final_usage
        log(f"  ⚑ Verifier still rejected after revision "
            f"{rev}/{verifier.max_rounds}: {review.comments[:200]}"
            f"{'…' if len(review.comments) > 200 else ''}", color="yellow")

    log(f"  · Verifier unsatisfied after {verifier.max_rounds} revision(s); "
        f"saving the last verdict.", color="dim")
    return verdict, final_usage


def _run_one_attempt(
    backend: Backend,
    navigator,
    config: RunConfig,
    prompt_path: Path,
    test_stats: TestStats,
    sent_evidence_files: set[str],
    attempt_num: int,
    verifier=None,
    prompt_prefix: str = "",
    prompt_suffix: str = "",
) -> AttemptRecord:
    """Run a single attempt of one test. Mutates test_stats with per-attempt
    evidence-tracking fields. Returns the AttemptRecord describing the outcome.

    Caller is responsible for snapshot/restore of backend history and
    sent_evidence_files between attempts.

    `prompt_prefix` / `prompt_suffix` wrap the test prompt read from
    `prompt_path`, without touching the file. This is the seam validation mode
    uses to put an existing Olympus verdict in front of the model alongside the
    test's own prompt; everything downstream (evidence delivery, tools, verdict
    parsing, retry, recovery) is unchanged. Both default to "" so the normal
    analysis path behaves exactly as before.

    If `verifier` is provided, the parsed verdict is reviewed before saving;
    on rejection the verifier's comments are nudged back into this session for
    revision (up to verifier.max_rounds). None disables verification.
    """
    attempt_start = time.monotonic()

    # Reset per-attempt fields
    test_stats.evidence_delivered = []
    test_stats.evidence_via_tools = []
    test_stats.evidence_already_inline = []
    test_stats.evidence_already_via_tools = []
    test_stats.evidence_missing = []

    def _record(status: str, **kwargs) -> AttemptRecord:
        return AttemptRecord(
            attempt=attempt_num,
            status=status,
            duration_seconds=round(time.monotonic() - attempt_start, 2),
            tool_call_count=test_stats.tool_call_count,
            **kwargs,
        )

    try:
        test_prompt = prompt_path.read_text()
        if prompt_prefix or prompt_suffix:
            test_prompt = f"{prompt_prefix}{test_prompt}{prompt_suffix}"
        result = backend.send_user_message(
            test_prompt,
            label=f"prompt: {prompt_path.name} (attempt {attempt_num})",
        )
        _log_turn(result, label="MODEL")

        # First-response branching
        collision = detect_protocol_call_collision(result.tool_calls)
        if collision is not None:
            log(f"  · Protocol-as-tool-call detected: lifting "
                f"'{result.tool_calls[0].name}' into protocol form.",
                color="dim")
            backend.ack_protocol_tool_calls(result.tool_calls)
            msg = collision
            calls: list[ToolCall] = []
        else:
            msg = parse_protocol_message(result.text) if result.text else None
            calls = result.tool_calls

        is_get_evidence = bool(msg and msg.get("operation") == "getEvidence")
        is_verdict_directly = bool(msg and "verdict" in msg)

        if is_verdict_directly:
            log("  · Model went straight to verdict (no evidence, no tools).",
                color="dim")
            final_text = result.text
            final_usage = _usage_to_dict(result.usage)

        elif is_get_evidence:
            requested = list(msg.get("args") or [])
            evidence_body = _build_evidence_payload(
                requested, config, navigator, sent_evidence_files, test_stats,
                backend,
            )

            n_inline = len(test_stats.evidence_delivered)
            n_via_tools = len(test_stats.evidence_via_tools)
            label_parts = []
            if n_inline:
                label_parts.append(f"{n_inline} inline")
            if n_via_tools:
                label_parts.append(f"{n_via_tools} via tools")
            label = "evidence (" + ", ".join(label_parts or ["nothing new"]) + ")"

            ev_result = backend.send_user_message(evidence_body, label=label)
            _log_turn(ev_result, label="MODEL")
            sent_evidence_files.update(test_stats.evidence_delivered)
            sent_evidence_files.update(test_stats.evidence_via_tools)

            final_text, final_usage = _resolve_tools(
                backend, navigator, ev_result, test_stats,
                max_iterations=config.max_tool_iterations,
            )

        elif calls:
            log("  · No getEvidence message — model is using tools directly. "
                "Resolving tool calls...", color="dim")
            final_text, final_usage = _resolve_tools(
                backend, navigator, result, test_stats,
                max_iterations=config.max_tool_iterations,
            )

        else:
            log(f"❌ Unexpected response shape. text={result.text!r} "
                f"calls={len(calls)}", color="red")
            return _record(
                "protocol_error",
                error=("First response after per-test prompt was neither "
                       "getEvidence, a verdict, nor tool calls"),
                raw_response=result.text,
            )

        # Parse the verdict
        # Recovery loop: the model gets up to MAX_RECOVERY_ATTEMPTS rounds
        # to produce a verdict-shaped response. Each iteration handles the
        # response by category and either lands on a verdict or sends
        # another prompt. Beyond the cap, give up as parse_error.

        verdict = None
        recovery_attempt = 0

        while recovery_attempt <= MAX_RECOVERY_ATTEMPTS:
            category, parsed = _classify_response(final_text)

            if category == "verdict":
                verdict = parsed
                break

            if recovery_attempt == MAX_RECOVERY_ATTEMPTS:
                log(
                    f"❌ Model did not produce a verdict after "
                    f"{MAX_RECOVERY_ATTEMPTS} recovery attempts. "
                    f"Last response category: {category}.",
                    color="red",
                )
                
                return _record(
                    "parse_error",
                    error=(
                        f"No verdict after {MAX_RECOVERY_ATTEMPTS} "
                        f"recovery attempts (last category: {category})"
                    ),
                    raw_response=final_text,
                    verdict_turn_tokens=final_usage,
                )

            recovery_attempt += 1

            if category == "getEvidence":
                # Model wants more evidence. Honor it: deliver the
                # requested files and continue. This is the same flow
                # as the initial getEvidence branch above, just routed
                # from the post-tools stage.
                log(
                    f"  · Model emitted getEvidence at verdict stage "
                    f"(recovery {recovery_attempt}/{MAX_RECOVERY_ATTEMPTS}). "
                    f"Delivering requested evidence and continuing.",
                    color="dim",
                )
                requested = list(parsed.get("args") or [])
                evidence_body = _build_evidence_payload(
                    requested, config, navigator,
                    sent_evidence_files, test_stats, backend,
                )
                ev_result = backend.send_user_message(
                    evidence_body,
                    label=f"evidence (recovery {recovery_attempt})",
                )
                _log_turn(ev_result, label="MODEL")
                sent_evidence_files.update(test_stats.evidence_delivered)
                sent_evidence_files.update(test_stats.evidence_via_tools)
                final_text, final_usage = _resolve_tools(
                    backend, navigator, ev_result, test_stats,
                    max_iterations=config.max_tool_iterations,
                )
                continue

            if category == "getPrompt":
                # Rare. Model is asking for a prompt; we don't have a
                # well-defined response for this at the verdict stage,
                # so nudge it back to producing a verdict.
                
                log(
                    f"  · Model emitted getPrompt at verdict stage "
                    f"(recovery {recovery_attempt}/{MAX_RECOVERY_ATTEMPTS}). "
                    f"Nudging to commit to a verdict.",
                    color="dim",
                )
                nudge_result = backend.send_user_message(
                    "Please commit to a final verdict now using the "
                    "evidence already gathered. Return the verdict JSON "
                    "with all required fields (verdict, certainty_percent, "
                    "evidence_table, rationale, etc.).",
                    label=f"verdict nudge (recovery {recovery_attempt})",
                )
                _log_turn(nudge_result, label="MODEL")
                final_text, final_usage = _resolve_tools(
                    backend, navigator, nudge_result, test_stats,
                    max_iterations=config.max_tool_iterations,
                )
                continue

            if category == "empty":
                
                log(
                    f"  · Model returned empty response "
                    f"(recovery {recovery_attempt}/{MAX_RECOVERY_ATTEMPTS}). "
                    f"Asking to continue.",
                    color="dim",
                )
                cont_result = backend.send_user_message(
                    "Please continue with your analysis and provide the "
                    "final verdict in the required JSON format.",
                    label=f"continue nudge (recovery {recovery_attempt})",
                )
                _log_turn(cont_result, label="MODEL")
                final_text, final_usage = _resolve_tools(
                    backend, navigator, cont_result, test_stats,
                    max_iterations=config.max_tool_iterations,
                )
                continue

            if category in ("unknown_json", "nonjson"):
                
                log(
                    f"  · Model emitted unrecognized response "
                    f"(category={category}, "
                    f"recovery {recovery_attempt}/{MAX_RECOVERY_ATTEMPTS}). "
                    f"Asking for the verdict in the required format.",
                    color="dim",
                )
                nudge_result = backend.send_user_message(
                    "Your previous response was not recognized as a "
                    "verdict. Please return the verdict JSON with all "
                    "required fields: verdict, certainty_percent, "
                    "evidence_table, rationale, mapped_maswe, "
                    "recommended_mastg_tests, needs_dynamic_testing, "
                    "false_positive_risks.",
                    label=f"format nudge (recovery {recovery_attempt})",
                )
                _log_turn(nudge_result, label="MODEL")
                final_text, final_usage = _resolve_tools(
                    backend, navigator, nudge_result, test_stats,
                    max_iterations=config.max_tool_iterations,
                )
                continue

        # The loop is guaranteed to exit via `break` (verdict) or via
        # the MAX_RECOVERY_ATTEMPTS return inside the loop. This assert
        # is defensive — if we ever drop out of the loop without
        # setting verdict, surface that as a bug rather than silently
        # writing None to disk.
        assert verdict is not None, (
            "verdict_engine bug: recovery loop exited without verdict"
        )

        # Optional verifier loop: review the verdict and, on rejection, nudge
        # the session to revise before saving.
        if verifier is not None:
            verdict, final_usage = _verify_and_revise(
                backend, navigator, config, verifier, verdict, final_usage,
                test_stats, test_prompt,
            )

            # Success — save and record
        out_path = _verdict_output_path(
            config, test_stats.test_stem, test_stats.category)
        out_path.write_text(ujson.dumps(verdict, indent=2))
        log(f"  ✓ Saved verdict to {out_path}", color="green")
        test_stats.verdict = verdict.get("verdict")
        test_stats.certainty = verdict.get("certainty_percent")
        test_stats.evidence_table_rows = len(verdict.get("evidence_table") or [])
        test_stats.verdict_turn_tokens = final_usage
        log(
            f"    verdict={test_stats.verdict}  "
            f"certainty={test_stats.certainty}  "
            f"rows={test_stats.evidence_table_rows}  "
            f"tool_calls={test_stats.tool_call_count}",
            color="green",
        )
        return _record(
            "ok",
            verdict=test_stats.verdict,
            certainty=test_stats.certainty,
            evidence_table_rows=test_stats.evidence_table_rows,
            verdict_turn_tokens=final_usage,
        )

    except RuntimeError as e:
        msg_str = f"{type(e).__name__}: {e}"
        log(f"❌ Test attempt crashed: {msg_str}", color="red")
        status = ("tool_loop_overflow" if "tool iterations" in str(e)
                  else "exception")
        return _record(status, error=msg_str)
    except Exception as e:
        msg_str = f"{type(e).__name__}: {e}"
        log(f"❌ Test attempt crashed: {msg_str}", color="red")
        return _record("exception", error=msg_str)


def _verdict_output_path(
    config: RunConfig, test_id: str, category: str = "",
) -> Path:
    """Return the on-disk path for a test's verdict JSON.

    When the test declares a ``category`` (e.g. "CRYPTO"), the verdict is
    grouped into an ``<output_dir>/<CATEGORY>/`` subfolder so a run's progress
    is legible by MASVS category instead of a flat list of numeric test IDs.
    Tests without a category fall back to the output root — backward
    compatible with plans that predate the category field. The category is
    reduced to a single safe path segment so it can never escape output_dir.
    """
    base = config.output_dir
    cat = (category or "").strip().strip("/\\")
    if cat:
        cat = cat.replace("..", "_").replace("/", "_").replace("\\", "_")
        base = base / cat
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{test_id}.json"


def _run_programmatic_test(
    entry: TestEntry,
    config: RunConfig,
    summary: list[TestStats],
) -> None:
    """Execute a programmatic test handler and write its verdict to disk.

    Programmatic handlers receive (job_id, evidence_dir) and return a
    verdict dict matching the LLM-test output shape. No retries — if a
    handler raises, the failure is recorded as a structured error verdict
    rather than rerun.
    """
    import json
    from datetime import datetime, timezone

    test_stats = TestStats(
        test_file=f"<programmatic:{entry.test_id}>",
        test_stem=entry.test_id,
        category=entry.category,
        started_at=datetime.now(timezone.utc).isoformat(),
        started_monotonic=time.monotonic(),
    )

    log(f"  Running programmatic handler for {entry.test_id}...",
        color="cyan")

    try:
        verdict = entry.handler(
            job_id=config.apk_root.name,
            evidence_dir=config.evidence_dir,
        )
        if not isinstance(verdict, dict):
            raise TypeError(
                f"handler returned {type(verdict).__name__}, expected dict"
            )
        test_stats.status = "ok"
        log(f"  ✓ {entry.test_id}: {verdict.get('verdict', '?')}",
            color="green")
    except Exception as exc:
        log(f"  ✗ {entry.test_id} failed: {type(exc).__name__}: {exc}",
            color="red")
        verdict = {
            "test_id": entry.test_id,
            "verdict": "error",
            "certainty_percent": 0,
            "evidence_table": [],
            "rationale": (
                f"Programmatic handler raised {type(exc).__name__}: {exc}"
            ),
            "mapped_maswe": [],
            "recommended_mastg_tests": [],
            "needs_dynamic_testing": False,
            "false_positive_risks": [],
        }
        test_stats.status = "error"
        test_stats.error = f"{type(exc).__name__}: {exc}"

    # Surface the verdict in the run summary, same columns as LLM tests.
    test_stats.verdict = verdict.get("verdict")
    test_stats.certainty = verdict.get("certainty_percent")
    test_stats.evidence_table_rows = len(verdict.get("evidence_table") or [])

    test_stats.finished_at = datetime.now(timezone.utc).isoformat()
    test_stats.duration_seconds = (
        time.monotonic() - test_stats.started_monotonic
    )

    out_path = _verdict_output_path(config, entry.test_id, entry.category)
    out_path.write_text(
        ujson.dumps(verdict, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log(f"  → wrote {out_path}", color="dim")

    summary.append(test_stats)

def _build_evidence_payload(
    requested: list[str],
    config: RunConfig,
    navigator,
    sent_evidence_files: set[str],
    test_stats: TestStats,
    backend,
) -> str:
    """Assemble the evidence body from a list of requested L1 file names.
    Tracks per-file outcome on test_stats.

    Routing per file:
      - Already provided via tools (e.g. obfuscation): skip with note.
      - Already delivered inline this session: skip with note.
      - Not found in --evidence-dir: emit ✗ note.
      - File on disk ≤ inline_evidence_max_bytes: deliver as full content
        inline (cheaper than a tool round-trip for tiny files).
      - File on disk > inline_evidence_max_bytes: deliver an acknowledgement
        pointing at the evidence tools. The model already knows what fields
        each evidence file holds (from the L1 schema delivered at bootstrap)
        and uses get_evidence_record / match_evidence_records /
        count_evidence_records to retrieve the parts it needs."""
    payload_chunks: list[str] = []

    for name in requested:
        if name in ALREADY_PROVIDED_VIA_TOOLS:
            test_stats.evidence_already_via_tools.append(name)
            payload_chunks.append(
                f"=== {name}: already provided "
                f"(reachable via tools, not as an evidence file) ==="
            )
            continue
        if name in sent_evidence_files:
            test_stats.evidence_already_inline.append(name)
            payload_chunks.append(
                f"=== {name}: already provided "
                f"(delivered earlier in this session — refer to it in prior context) ==="
            )
            continue
        ev_path = config.evidence_dir / name
        if not ev_path.exists():
            test_stats.evidence_missing.append(name)
            payload_chunks.append(
                f"=== {name}: not found "
                f"(file does not exist in the evidence directory) ==="
            )
            continue

        size = ev_path.stat().st_size
        if size <= config.inline_evidence_max_bytes:
            # Tiny file — deliver in full, as before. No tool round-trip
            # needed for files this small.
            content = ev_path.read_text()
            payload_chunks.append(f"=== {name} ===\n{content}")
            test_stats.evidence_delivered.append(name)
        else:
            # Large file — acknowledge availability and direct the model
            # to the evidence tools. We compute the vocabulary preview
            # here (one walk of the records) so the model can pick filter
            # values that actually appear in the file, instead of guessing.
            # Without this preview, the model frequently issues 0-match
            # queries because its guess for an enum-like field's vocabulary
            # ("sharedpreferences") doesn't match the actual stored form
            # ("shared_preferences"), then falls back to grep against
            # source — which is exactly the failure mode we want to avoid.
            try:
                total_records = navigator.evidence_index.count_records(name)
                vocab = navigator.evidence_index.field_vocabularies(name)
            except Exception as e:
                total_records = {"total": "?"}
                vocab = {}
                log(
                    f"    (vocabulary preview unavailable for {name}: "
                    f"{type(e).__name__}: {e})",
                    color="dim",
                )

            vocab_lines = []
            for path, counts in vocab.items():
                # Render each field's top values inline. Keep the format
                # compact — this is delivered every test that requests
                # this file, so verbosity adds up.
                more = counts.pop("_more", 0) if "_more" in counts else 0
                pairs = ", ".join(f"{k}({v})" for k, v in counts.items())
                if more:
                    pairs += f", ... ({more} more values)"
                vocab_lines.append(f"  {path}: {pairs}")

            vocab_block = (
                "\nField value vocabularies (top values, for picking "
                "regex filters):\n" + "\n".join(vocab_lines)
                if vocab_lines else ""
            )

            payload_chunks.append(
                f"=== {name} (available via evidence tools) ===\n"
                f"This file is {size:,} bytes on disk with "
                f"{total_records['total']} records. It is NOT delivered "
                f"inline. Use the navigator's evidence tools to access its "
                f"records:\n"
                f"  - count_evidence_records(file={name!r}) for totals or "
                f"field-grouped histograms.\n"
                f"  - match_evidence_records(file={name!r}, "
                f"filters={{...}}) for records whose fields match regex "
                f"patterns (re.search semantics; anchor with ^...$ for "
                f"exact match; dotted paths supported for nested fields).\n"
                f"  - get_evidence_record(file={name!r}, ids=[...]) for one "
                f"or more specific records by id (batch multiple ids in "
                f"one call).\n"
                f"The L1 schema you received at bootstrap describes the "
                f"fields each record contains. Cite findings by record id "
                f"in your verdict."
                f"{vocab_block}"
            )
            test_stats.evidence_via_tools.append(name)

    for d in test_stats.evidence_delivered:
        log(f"  ✓ {d} (delivered inline, ≤{config.inline_evidence_max_bytes:,} bytes)",
            color="green")
    for v in test_stats.evidence_via_tools:
        log(f"  → {v} (available via evidence tools)", color="cyan")
    for s in test_stats.evidence_already_inline:
        log(f"  · {s} (already provided — sent earlier in session)",
            color="dim")
    for s in test_stats.evidence_already_via_tools:
        log(f"  · {s} (already provided — reachable via tools)", color="dim")
    for m in test_stats.evidence_missing:
        log(f"  ✗ {m} (NOT FOUND in --evidence-dir)", color="red")

    body = "Evidence:\n" + "\n\n".join(payload_chunks)
    if test_stats.evidence_missing:
        body += (
            f"\n\n[Note: {len(test_stats.evidence_missing)} requested "
            f"evidence file(s) could not be delivered. Proceed with "
            f"the available evidence and reflect the gap in your verdict.]"
        )
    return body


def _finalize_test_stats(stats: TestStats) -> None:
    stats.finished_at = datetime.now(timezone.utc).isoformat()
    stats.duration_seconds = round(
        time.monotonic() - stats.started_monotonic, 2,
    )
    log(
        f"    elapsed: {format_duration(stats.duration_seconds)} "
        f"({stats.duration_seconds:.1f}s)",
        color="dim",
    )


# ============================================================
#  Public entry point
# ============================================================

def run_batch(
    backend: Backend,
    navigator,
    config: RunConfig,
) -> int:
    """Run a complete verdict-engine batch. Returns process exit code:
        0 = all tests succeeded
        1 = fatal error (bootstrap failed)
        2 = at least one test failed
    """
    
    try:
        plan = load_test_plan(config.test_plan_dir)
    except TestPlanError as exc:
        log(f"Failed to load test plan: {exc}", color="red")
        return 1

    entries = filter_entries(plan.entries, config.test_filter)
    if not entries:
        msg = (
            f"No tests in plan {plan.name!r} matched filter "
            f"{config.test_filter!r}."
            if config.test_filter else
            f"Test plan {plan.name!r} contains no entries."
        )
        log(msg, color="red")
        return 1

    log(f"Loaded plan {plan.name!r} with {len(entries)} test(s):",
        color="cyan")
    for e in entries:
        log(f"  · {e.test_id} ({e.type})", color="cyan")

    config.output_dir.mkdir(parents=True, exist_ok=True)

    backend.configure_tools(navigator)

    schema_text = config.schema.read_text()
    sent_evidence_files: set[str] = set()
    summary: list[TestStats] = []

    try:
        # ---------------- Phases 1-2: bootstrap + schema ----------------
        # Extracted to bootstrap_session() so EngineAPI runs the identical
        # handshake instead of a second copy. Tolerance for a missing
        # getPrompt is preserved (strict=False) — see that function.
        banner("Phase 1-2  ·  Bootstrap (expect getSchema, deliver schema)")
        if not bootstrap_session(backend, schema_text, strict=False):
            return 1

        # Capture the post-handshake state as the per-test baseline.
        # Every test will restore this baseline before running, so each
        # test starts with the same minimal history (system_prompt +
        # schema + handshake) regardless of how many tests preceded it.
        # This keeps the per-call prefix size bounded to ~17K + the
        # current test's own conversation, instead of growing linearly
        # across the run.
        baseline_history = backend.snapshot_history()
        baseline_evidence = set(sent_evidence_files)
        log(
            f"Captured baseline ({backend.history_length()} history "
            f"entries, {len(baseline_evidence)} evidence files). All "
            f"tests will reset to this baseline before running.",
            color="cyan",
        )

        # ---------------- Per-test loop ----------------
        for i, entry in enumerate(entries, 1):
            banner(f"Test {i}/{len(entries)}  ·  {entry.test_id} ({entry.type})",
                    color="magenta")

            # Programmatic tests run synchronously without backend
            # interaction — handle them and skip the rest of the loop body.
            if entry.type == "programmatic":
                _run_programmatic_test(entry, config, summary)
                continue

            # LLM tests proceed as before. test_file and test_stem now
            # come from the test_id (the TOML section name) rather than
            # the prompt filename, so outputs are named after the test ID.
            test_stats = TestStats(
            test_file=entry.prompt_path.name,
            test_stem=entry.test_id,
            category=entry.category,
            started_at=datetime.now(timezone.utc).isoformat(),
            started_monotonic=time.monotonic(),
        )

            # Restore the post-handshake baseline. Each test runs in a
            # fresh conversational context: prior tests' tool calls,
            # evidence, and verdicts are not carried over. The model
            # will re-discover basics it might have learned in earlier
            # tests (slightly more tool calls per test), but this is
            # outweighed by avoiding the linear growth of per-call
            # prefix size.
            backend.restore_history(baseline_history)
            sent_evidence_files.clear()
            sent_evidence_files.update(baseline_evidence)

            # The retry snapshot is now taken AFTER the baseline restore,
            # so within-test retries restart from this test's beginning,
            # not from prior tests' state. The snapshot just captures a
            # smaller history now.
            history_snapshot = backend.snapshot_history()
            evidence_snapshot = set(sent_evidence_files)
            tool_count_at_start = test_stats.tool_call_count
            tool_calls_at_start = list(test_stats.tool_calls)

            max_attempts = config.max_test_retries + 1
            for attempt_num in range(1, max_attempts + 1):
                if attempt_num > 1:
                    log(
                        f"  ↻ Retrying test (attempt {attempt_num}/"
                        f"{max_attempts}) after "
                        f"{config.retry_delay_seconds:.0f}s pause...",
                        color="yellow",
                    )
                    time.sleep(config.retry_delay_seconds)
                    backend.restore_history(history_snapshot)
                    sent_evidence_files.clear()
                    sent_evidence_files.update(evidence_snapshot)
                    test_stats.tool_call_count = tool_count_at_start
                    test_stats.tool_calls = list(tool_calls_at_start)

                attempt = _run_one_attempt(
                    backend, navigator, config, entry.prompt_path, test_stats,
                    sent_evidence_files, attempt_num,
                )
                test_stats.attempts.append(attempt)

                if attempt.status == "ok":
                    test_stats.status = "ok"
                    test_stats.succeeded_on_attempt = attempt_num
                    if attempt_num > 1:
                        log(
                            f"  ✓ Test succeeded on attempt {attempt_num} "
                            f"after {attempt_num - 1} failed attempt(s).",
                            color="green",
                        )
                    break

                log(
                    f"  ✗ Attempt {attempt_num}/{max_attempts} failed: "
                    f"{attempt.status} ({attempt.error})",
                    color="red",
                )
                if attempt_num >= max_attempts:
                    test_stats.status = attempt.status
                    test_stats.error = attempt.error
                    test_stats.raw_response = attempt.raw_response
                    test_stats.verdict_turn_tokens = attempt.verdict_turn_tokens
                    log(
                        f"  ✗ Test failed after {max_attempts} attempt(s). "
                        f"Recording failure and continuing.",
                        color="red",
                    )
                    if config.abort_on_error:
                        _finalize_test_stats(test_stats)
                        summary.append(test_stats)
                        raise RuntimeError(
                            f"Test {entry.test_id} failed all "
                            f"{max_attempts} attempts; abort-on-error set."
                        )

            _finalize_test_stats(test_stats)
            summary.append(test_stats)

            if i < len(entries):
                log("\n  ... resetting prompt state for next test ...",
                    color="dim")
                if not _try_reset_prompt(backend):
                    log("Reset failed; aborting batch.", color="red")
                    break

        # ---------------- Summary ----------------
        _print_and_save_summary(backend, navigator, config, summary)
        ok_count = sum(1 for r in summary if r.status == "ok")
        return 0 if ok_count == len(summary) else 2

    except Exception as e:
        log(f"\nFatal error: {type(e).__name__}: {e}", color="red")
        _save_summary_with_error(
            backend, config, summary, error=f"{type(e).__name__}: {e}",
        )
        return 1


def _resolve_first_response_to_protocol(
    backend: Backend, result: TurnResult,
) -> dict | None:
    """For the bootstrap and schema phases, accept either a protocol JSON
    text response or a protocol-as-tool-call collision."""
    collision = detect_protocol_call_collision(result.tool_calls)
    if collision is not None:
        log(f"  · Protocol-as-tool-call detected: lifting "
            f"'{result.tool_calls[0].name}'.", color="dim")
        backend.ack_protocol_tool_calls(result.tool_calls)
        return collision
    return parse_protocol_message(result.text)


def _print_and_save_summary(
    backend: Backend,
    navigator,
    config: RunConfig,
    summary: list[TestStats],
) -> None:
    banner("Run summary", color="bold")
    ok_count = sum(1 for r in summary if r.status == "ok")
    durations = [r.duration_seconds for r in summary
                 if r.duration_seconds is not None]
    total_seconds = sum(durations) if durations else 0
    avg_seconds = (total_seconds / len(durations)) if durations else 0

    log(f"  Tests run:      {len(summary)}")
    log(f"  Successful:     {ok_count}",
        color="green" if ok_count == len(summary) else "yellow")
    log(f"  Errors:         {len(summary) - ok_count}",
        color="red" if ok_count < len(summary) else "")
    if durations:
        log(f"  Total elapsed:  {format_duration(total_seconds)} "
            f"({total_seconds:.1f}s across {len(durations)} test(s))")
        log(f"  Avg per test:   {format_duration(avg_seconds)} "
            f"({avg_seconds:.1f}s)")
    retried = [r for r in summary if r.attempts and len(r.attempts) > 1]
    if retried:
        recovered = [r for r in retried if r.status == "ok"]
        log(
            f"  Retried tests:  {len(retried)} ({len(recovered)} recovered, "
            f"{len(retried) - len(recovered)} stayed failed)",
            color="yellow",
        )
    log("")
    log(f"  {'TEST':<28} {'STATUS':<13} {'VERDICT':<18} {'CERT':>5}  "
        f"{'ROWS':>5}  {'TOOLS':>5}  {'ATT':>3}  {'PROMPT-TOK':>10}  "
        f"{'ELAPSED':>10}")
    log(f"  {'-'*28} {'-'*13} {'-'*18} {'-'*5}  {'-'*5}  {'-'*5}  "
        f"{'-'*3}  {'-'*10}  {'-'*10}")
    for r in summary:
        tokens = (r.verdict_turn_tokens or {}).get("prompt_tokens", "")
        n_attempts = len(r.attempts) if r.attempts else 1
        log(
            f"  {r.test_stem[:28]:<28} "
            f"{r.status:<13} "
            f"{str(r.verdict or '')[:18]:<18} "
            f"{str(r.certainty or ''):>5}  "
            f"{str(r.evidence_table_rows or ''):>5}  "
            f"{r.tool_call_count:>5}  "
            f"{n_attempts:>3}  "
            f"{str(tokens):>10}  "
            f"{format_duration(r.duration_seconds):>10}"
        )

    try:
        plan = load_test_plan(config.test_plan_dir)
    except TestPlanError as exc:
        log(f"Failed to load test plan: {exc}", color="red")
        return 1
    
    summary_path = config.output_dir / "_summary.json"
    summary_path.write_text(ujson.dumps({
        "run_at": datetime.now(timezone.utc).isoformat(),
        "backend": backend.name,
        "model": backend.model,
        "apk_root": str(config.apk_root),
        "evidence_dir": str(config.evidence_dir),
        "test_plan_dir": str(config.test_plan_dir),
        "test_plan_name": plan.name,
        "test_filter": config.test_filter,
        "index_stats": navigator.index.stats(),
        "totals": {
            "tests_run": len(summary),
            "successful": ok_count,
            "errors": len(summary) - ok_count,
            "total_seconds": round(total_seconds, 2),
            "avg_seconds": round(avg_seconds, 2),
            "retried": len(retried),
        },
        "tests": [r.to_dict() for r in summary],
    }, indent=2))
    log(f"\n  Summary written to {summary_path}", color="green")


def _save_summary_with_error(
    backend: Backend,
    config: RunConfig,
    summary: list[TestStats],
    *,
    error: str,
) -> None:
    summary_path = config.output_dir / "_summary.json"
    summary_path.write_text(ujson.dumps({
        "run_at": datetime.now(timezone.utc).isoformat(),
        "backend": backend.name,
        "model": backend.model,
        "fatal_error": error,
        "tests": [r.to_dict() for r in summary],
    }, indent=2))
    log(f"  Partial summary written to {summary_path}", color="yellow")