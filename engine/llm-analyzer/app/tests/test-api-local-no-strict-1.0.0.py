"""
test_openwebui_apk.py — Batch verdict-engine runner against an OpenAI-compatible
chat completions endpoint (OpenWebUI, Ollama, vLLM, llama-cpp-server, etc.).

Mirrors the architecture of test_gemini_apk.py but talks the OpenAI Chat
Completions protocol instead of Gemini's. Same APKNavigator, same per-test
loop, same evidence handling, same retry-on-transient-error logic. Only the
wire format is different.

Conversation flow per session — identical to the Gemini runner:

    Initialization:
        Code: "Begin." (kickoff, system prompt set on first message)
        LLM:  getSchema
        Code: schema text
        LLM:  getPrompt

    Per-test loop:
        Code: per-test prompt
        LLM:  getEvidence  -OR-  tool calls  -OR-  verdict directly
        Code: requested L1 evidence inline (slim strings.json on the fly)
        LLM:  reasoning turns with tool calls
              → resolved locally via APKNavigator
              → results fed back as 'tool' role messages
              → loop until LLM emits an assistant message with content + no tool_calls
        Code: stores verdict, sends `reset prompt`
        LLM:  ack

Requires gpt-oss-120b or a similar tool-call-capable model. The OpenAI Python
SDK is used as the wire client because it speaks Chat Completions natively.

Usage:
    python test_openwebui_apk.py \\
        --base-url http://your-host:port/api \\
        --api-key sk-... \\
        --model gpt-oss:120b \\
        --apk-root /extracted/diva \\
        --system-prompt 1.system_prompt-v1.3.4.md \\
        --schema 2.layer3_schema_v1_2_4_full_spec.md \\
        --evidence-dir /extracted/diva/evidence \\
        --prompts-dir app/layer4/prompts/ada-mobile-profile-certification/ \\
        --output-dir verdicts/diva-local/

Notes on OpenWebUI specifically:
- The base URL should end at '/api' (not '/v1'). The endpoint is then
  '<base>/chat/completions'. The OpenAI SDK appends '/chat/completions' to
  whatever base_url you provide, so passing '<host>/api' is correct.
- Auth is Bearer token. Both 'sk-' API keys and JWTs work; the SDK handles
  the header automatically when you pass `api_key=...`.
- gpt-oss models accept reasoning effort via the system prompt: include
  'Reasoning: medium' (or low/high) somewhere. We inject it automatically
  when --reasoning-effort is set.
"""

from __future__ import annotations

import argparse
import ujson
import os
import re
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from openai import OpenAI

from apk_navigator import APKNavigator


# ============================================================
#  Logging
# ============================================================

C = {
    "cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m",
    "red": "\033[31m", "dim": "\033[2m", "bold": "\033[1m",
    "magenta": "\033[35m", "blue": "\033[34m", "reset": "\033[0m",
}


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
#  Tool declarations (OpenAI Chat Completions format)
# ============================================================

def build_openai_tool_declarations() -> list[dict]:
    """Return tool list in OpenAI's `tools=[{type:"function", function:{...}}]` shape.

    The schemas mirror the Gemini declarations one-for-one; only the wrapping
    is different. APKNavigator's TOOL_NAMES is the source of truth.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": (
                    "List immediate children of a directory in the extracted APK tree. "
                    "Use to orient yourself before reading files. Directory entries end with '/'."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "prefix": {"type": "string", "description": (
                            "Relative path from APK root, e.g. 'jadx/sources/com/example/'. "
                            "Empty string for root."
                        )},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": (
                    "Read a file from the extracted APK tree, optionally limited to a line range. "
                    "When level 1 evidence cites Source.line_start and Source.line_end, ALWAYS "
                    "pass them — never read full files when you have a range. Reading the whole "
                    "file when a 30-line range is sufficient is wasteful and forbidden."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": (
                            "Relative path from APK root, e.g. "
                            "'jadx/sources/com/example/MainActivity.java' or "
                            "'apktool/AndroidManifest.xml' or "
                            "'apktool/smali/com/example/MainActivity.smali'."
                        )},
                        "line_start": {"type": "integer", "description": "1-indexed start line (inclusive)."},
                        "line_end":   {"type": "integer", "description": "1-indexed end line (inclusive)."},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "find_class",
                "description": (
                    "Resolve a Java/Kotlin class name (FQN or simple) to its file path(s). "
                    "Returns ClassRef entries with `fqn`, `path`, `is_smali`. If is_smali is "
                    "true, JADX failed to decompile the class and only smali is available — "
                    "treat that as L3 and follow the escalation rules accordingly."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": (
                            "Fully-qualified name like 'com.foo.Bar' or simple name like 'Bar'."
                        )},
                    },
                    "required": ["name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "find_subclasses",
                "description": (
                    "Find classes that extend or implement the given fully-qualified type. "
                    "Use to discover the concrete implementation of an abstract base or interface "
                    "cited in evidence (e.g. when an L1 record points at BaseAuthActivity but the "
                    "actual logic lives in a subclass)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "fqn": {"type": "string", "description": "Fully-qualified type name."},
                        "transitive": {"type": "boolean", "description": (
                            "If true, include indirect subclasses. Default false (direct only)."
                        )},
                    },
                    "required": ["fqn"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_imports",
                "description": (
                    "Return imports declared at the top of a Java source file. Use to "
                    "disambiguate which type a name refers to (e.g. javax.crypto.Cipher vs a "
                    "third-party shim with the same simple name)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Relative path to a .java file."},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": (
                    "Regex search across files under a path prefix. Use sparingly — prefer "
                    "find_class + read_file when you already know the location. Returns up to "
                    "200 matches with snippets capped at 300 chars."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Python regex."},
                        "path_prefix": {"type": "string", "description": (
                            "Limit search to this subtree, e.g. 'jadx/sources/com/example/'."
                        )},
                        "file_glob": {"type": "string", "description": (
                            "Filename glob, e.g. '*.java' or '*.smali'. Default '*'."
                        )},
                    },
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_string_record",
                "description": (
                    "Return the full record for a given strings.json id. The strings.json "
                    "file is delivered inline in slim form (id, category, value, path only) "
                    "to keep token cost manageable. Use this tool to expand a specific "
                    "record when you need its snippet_context, noise_signals, or any other "
                    "field beyond the four delivered inline."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "string_id": {"type": "string", "description": (
                            "The id from the slim strings.json record, e.g. 'str-2206'."
                        )},
                    },
                    "required": ["string_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_string_records_by_category",
                "description": (
                    "Return up to N full strings.json records under a given category, "
                    "e.g. 'API_KEY', 'CREDENTIAL', 'SECRET_KEY', 'URL'. Use when you "
                    "want to enumerate all records of a class up front rather than "
                    "picking ids one by one from the slim manifest."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Category name."},
                        "limit": {"type": "integer", "description": "Max records to return."},
                    },
                    "required": ["category"],
                },
            },
        },
    ]


# ============================================================
#  Protocol helpers
# ============================================================

def parse_protocol_message(text: str) -> dict | None:
    """Parse a JSON protocol message. Tolerates ```json fences and gpt-oss
    harmony-channel artifacts that occasionally leak through (`<|channel|>final<|message|>`)."""
    if not text:
        return None
    cleaned = text.strip()

    # Strip harmony channel markers if they leaked through
    cleaned = re.sub(r"<\|channel\|>\w+<\|message\|>", "", cleaned)
    cleaned = re.sub(r"<\|(?:start|end|return|call|message|channel)\|>\w*", "", cleaned)
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

    # Try direct parse, then fall back to extracting first JSON object
    try:
        return ujson.loads(cleaned)
    except ujson.JSONDecodeError:
        pass

    # Find the first balanced JSON object
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return ujson.loads(match.group(0))
        except ujson.JSONDecodeError:
            return None
    return None


# ============================================================
#  Retry-on-transient-error wrapper
# ============================================================

RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


def _extract_status_code(err: BaseException) -> int | None:
    for attr in ("status_code", "code"):
        v = getattr(err, attr, None)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    response = getattr(err, "response", None)
    if response is not None:
        v = getattr(response, "status_code", None)
        if isinstance(v, int):
            return v
    msg = str(err)
    head = msg.split(" ", 1)[0]
    if head.isdigit():
        return int(head)
    m = re.search(r"['\"]code['\"]\s*:\s*(\d{3})", msg)
    if m:
        return int(m.group(1))
    m = re.search(r"\b([45]\d{2})\b", msg)
    if m:
        return int(m.group(1))
    return None


def with_transient_retry(fn, *, max_attempts=6, base_backoff=5.0, max_backoff=120.0,
                         on_wait=None):
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except Exception as e:
            status = _extract_status_code(e)
            if status is None or status not in RETRYABLE_STATUS_CODES:
                raise
            last_error = e
            if attempt >= max_attempts:
                break
            wait = min(base_backoff * (2 ** (attempt - 1)), max_backoff)
            if on_wait:
                on_wait(status, wait, f"backoff (attempt {attempt}/{max_attempts})",
                        attempt, max_attempts)
            time.sleep(wait)
    assert last_error is not None
    raise last_error


# ============================================================
#  Per-test stats
# ============================================================

@dataclass
class TestStats:
    test_file: str
    test_stem: str
    started_at: str
    finished_at: str | None = None
    status: str = "running"
    verdict: str | None = None
    certainty: int | None = None
    evidence_table_rows: int | None = None
    evidence_delivered: list = field(default_factory=list)
    evidence_already_inline: list = field(default_factory=list)
    evidence_already_via_tools: list = field(default_factory=list)
    evidence_missing: list = field(default_factory=list)
    tool_calls: list = field(default_factory=list)
    tool_call_count: int = 0
    verdict_turn_tokens: dict = field(default_factory=dict)
    error: str | None = None
    raw_response: str | None = None

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], {})}


# Names the model might list in getEvidence that no longer apply with function
# calling. Drop them silently.
ALREADY_PROVIDED_VIA_TOOLS = {
    "apktool.xml", "jadx.xml", "apktool.tar", "jadx.tar",
}

# Protocol operation names that the model may incorrectly emit as function
# calls instead of as JSON-text messages. When that happens we extract the
# args back out and treat the call as if the model had emitted the protocol
# message directly.
PROTOCOL_OP_NAMES = {"getSchema", "getEvidence", "getPrompt", "reset"}


def detect_protocol_call_collision(tool_calls: list) -> dict | None:
    """If a tool_call's name matches a protocol operation, lift it back into
    a protocol message dict and return that. Otherwise return None.

    Handles two shapes the model might produce:
      1. Function name == operation, args == raw protocol args
         e.g. name="getEvidence", arguments={"args": ["foo.json"]}
      2. Function name == operation, args == the entire protocol envelope
         e.g. name="getEvidence", arguments={"status": "prompted",
              "operation": "getEvidence", "args": [...]}

    The model that produced the failing example used shape 2.
    """
    if not tool_calls:
        return None
    # Only handle the simple, common case: a single tool_call whose name is
    # a protocol op. If the model emits multiple tool calls and ONE of them
    # is a protocol-op collision, we leave it alone — that's a more complex
    # confusion we'd want to see in logs first.
    if len(tool_calls) != 1:
        return None
    call = tool_calls[0]
    name = call.function.name
    if name not in PROTOCOL_OP_NAMES:
        return None
    try:
        parsed =ujson.loads(call.function.arguments or "{}")
    except ujson.JSONDecodeError:
        return None

    # Shape 2: full envelope already inside arguments
    if isinstance(parsed, dict) and parsed.get("operation") == name:
        return parsed
    # Shape 1: just the args field
    if isinstance(parsed, dict) and "args" in parsed:
        return {
            "status": "prompted",  # best-effort default
            "operation": name,
            "args": parsed["args"],
        }
    # Shape 1 variant: arguments are the args list directly
    if isinstance(parsed, list):
        return {"operation": name, "args": parsed}
    # No args? Treat as a no-arg protocol op (e.g. getSchema)
    return {"operation": name, "args": "None"}


# ============================================================
#  Main
# ============================================================

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--base-url", required=True, help=(
        "OpenAI-compatible API base URL. For OpenWebUI: 'http://host:port/api'. "
        "For Ollama: 'http://host:11434/v1'. For vLLM: 'http://host:8000/v1'."
    ))
    ap.add_argument("--api-key", default=None, help=(
        "Bearer token. For OpenWebUI: the user's API key (sk-...) or a JWT. "
        "For local-only Ollama with no auth, pass any non-empty string. "
        "Defaults to OPENAI_API_KEY env var."
    ))
    ap.add_argument("--model", required=True, help=(
        "Model name as known to the backend, e.g. 'gpt-oss:120b' for Ollama, "
        "'openai/gpt-oss-120b' for vLLM."
    ))
    ap.add_argument("--apk-root",      required=True, type=Path)
    ap.add_argument("--system-prompt", required=True, type=Path)
    ap.add_argument("--schema",        required=True, type=Path)
    ap.add_argument("--evidence-dir",  required=True, type=Path)
    ap.add_argument("--prompts-dir",   required=True, type=Path)
    ap.add_argument("--output-dir",    required=True, type=Path)
    ap.add_argument("--reasoning-effort", choices=["low", "medium", "high"],
                    default="medium", help=(
        "gpt-oss reasoning level. Injected into the system prompt as "
        "'Reasoning: <level>'. Default 'medium'. Use 'high' for hard "
        "verifications, 'low' for quick smoke tests."
    ))
    ap.add_argument("--temperature", type=float, default=0.2, help=(
        "Sampling temperature. 0.2 keeps verdicts deterministic enough for "
        "reproducibility while allowing some flexibility in tool-use planning."
    ))
    ap.add_argument("--max-tool-iterations", type=int, default=50)
    ap.add_argument("--max-retries", type=int, default=6)
    ap.add_argument("--retry-base-seconds", type=float, default=5.0)
    ap.add_argument("--retry-max-seconds", type=float, default=120.0)
    ap.add_argument("--request-timeout", type=float, default=600.0, help=(
        "Per-request timeout in seconds. Local models can be slow on long "
        "histories — 600s gives plenty of room."
    ))
    ap.add_argument("--abort-on-error", action="store_true")
    args = ap.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY") or "sk-no-auth"

    prompts = sorted(args.prompts_dir.glob("*.md"))
    if not prompts:
        sys.exit(f"No .md files in {args.prompts_dir}")

    log(f"Found {len(prompts)} test prompt(s):", color="cyan")
    for p in prompts:
        log(f"  · {p.name}", color="cyan")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # System prompt + schema, with reasoning effort prepended and a
    # protocol/tool clarification appended.
    system_prompt_raw = args.system_prompt.read_text()
    schema_text = args.schema.read_text()
    protocol_clarification = (
        "\n\n## CRITICAL: Protocol messages are NOT function calls\n"
        "\n"
        "You have access to two distinct response mechanisms. Do not confuse them.\n"
        "\n"
        "1. **Protocol messages** (`getSchema`, `getPrompt`, `getEvidence`, "
        "`reset`, the verdict). These are emitted as JSON in your text response. "
        "They are NEVER function calls. There is no `getEvidence` tool, no "
        "`getSchema` tool, no `reset` tool. If you try to call one as a function, "
        "the system will reject it.\n"
        "\n"
        "2. **Function tools** (`read_file`, `find_class`, `find_subclasses`, "
        "`list_imports`, `list_dir`, `grep`, `get_string_record`, "
        "`list_string_records_by_category`). These are emitted via the function-"
        "calling mechanism. They are NEVER protocol messages. They serve only "
        "to retrieve L2/L3 evidence during reasoning.\n"
        "\n"
        "Right turn shapes:\n"
        "  - Asking for L1 evidence → text JSON `{\"operation\": \"getEvidence\", "
        "\"args\": [\"foo.json\"]}`\n"
        "  - Reading an L2 file → function call `read_file({\"path\": \"...\", "
        "\"line_start\": 70, \"line_end\": 110})`\n"
        "  - Emitting the verdict → text JSON with verdict, evidence_table, etc.\n"
        "\n"
        "Wrong turn shapes (the system will warn or fail on these):\n"
        "  - `getEvidence` as a function call — there is no such function\n"
        "  - The verdict as a function call — verdicts are JSON text\n"
        "  - `read_file` as a JSON text message — read_file is a function\n"
    )
    system_prompt = (
        f"Reasoning: {args.reasoning_effort}\n\n"
        f"{system_prompt_raw}"
        f"{protocol_clarification}"
    )

    # Index APK
    banner("Phase 0  ·  Indexing APK")
    log(f"  APK root: {args.apk_root}", color="cyan")
    navigator = APKNavigator(args.apk_root, evidence_dir=args.evidence_dir)
    stats = navigator.index.stats()
    log(
        f"  Index: {stats['classes']} classes "
        f"({stats['java_classes']} java, {stats['smali_classes']} smali only), "
        f"{stats['indexed_files_with_imports']} files with imports",
        color="green",
    )
    if navigator._strings_by_id:
        log(
            f"  strings.json: indexed {len(navigator._strings_by_id)} records "
            f"across {len(navigator._strings_by_category)} categories",
            color="green",
        )

    # OpenAI client (works for any OpenAI-compatible endpoint)
    client = OpenAI(
        base_url=args.base_url,
        api_key=api_key,
        timeout=args.request_timeout,
    )
    log(
        f"  Backend: {args.base_url}\n"
        f"  Model: {args.model}\n"
        f"  Reasoning: {args.reasoning_effort}, Temperature: {args.temperature}",
        color="cyan",
    )

    tools = build_openai_tool_declarations()

    # Conversation state — OpenAI shape: list of dicts with role/content/tool_calls/etc.
    messages: list[dict] = [{"role": "system", "content": system_prompt}]
    sent_evidence_files: set[str] = set()
    summary: list[TestStats] = []

    # ----- send() -----
    def send(new_messages: list[dict], label: str) -> tuple[str, list, dict]:
        """Send one or more new messages; return (text, tool_calls, usage)."""
        log(f"\n>>> USER  ({label})", color="yellow")
        for m in new_messages:
            role = m.get("role", "?")
            if m.get("content"):
                preview = str(m["content"])[:160].replace("\n", " ")
                log(
                    f"    [{role}] {preview}{'...' if len(str(m['content'])) > 160 else ''}",
                    color="dim",
                )
            elif m.get("tool_call_id"):
                resp_preview = str(m.get("content") or "")[:120].replace("\n", " ")
                log(f"    [tool] {m.get('name','?')}({resp_preview}...)", color="dim")

        messages.extend(new_messages)

        def _on_wait(status, wait, reason, attempt, max_attempts):
            log(
                f"  ⏳ HTTP {status} — pausing {wait:.1f}s ({reason}); "
                f"will retry [{attempt}/{max_attempts}]",
                color="yellow",
            )

        def _do_call():
            return client.chat.completions.create(
                model=args.model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=args.temperature,
            )

        resp = with_transient_retry(
            _do_call,
            max_attempts=args.max_retries,
            base_backoff=args.retry_base_seconds,
            max_backoff=args.retry_max_seconds,
            on_wait=_on_wait,
        )

        choice = resp.choices[0]
        msg = choice.message

        # Append the assistant turn to history exactly as the API returned it.
        # OpenAI requires the assistant message be in history before tool
        # responses are appended — and it must include any tool_calls the
        # model emitted, with their original ids.
        assistant_history_msg: dict = {"role": "assistant"}
        if msg.content is not None:
            assistant_history_msg["content"] = msg.content
        if msg.tool_calls:
            assistant_history_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]
        messages.append(assistant_history_msg)

        text = msg.content or ""
        tool_calls = list(msg.tool_calls or [])
        usage = {}
        if resp.usage:
            usage = {
                "prompt_tokens": resp.usage.prompt_tokens,
                "completion_tokens": resp.usage.completion_tokens,
                "total_tokens": resp.usage.total_tokens,
            }

        if tool_calls:
            log(f"<<< MODEL  [{len(tool_calls)} tool call(s)]", color="green")
            for tc in tool_calls:
                args_preview = (tc.function.arguments or "")[:200]
                log(f"  → {tc.function.name}({args_preview})", color="cyan")
        if text:
            log("<<< MODEL  [text]", color="green")
            log(text)
        if not tool_calls and not text:
            log("<<< MODEL  [empty response]", color="red")

        if usage:
            log(
                f"    [tokens: prompt={usage.get('prompt_tokens')} "
                f"completion={usage.get('completion_tokens')} "
                f"total={usage.get('total_tokens')}]",
                color="dim",
            )
        return text, tool_calls, usage

    def resolve_tools(initial_text: str, initial_calls: list, initial_usage: dict,
                      stats: TestStats) -> tuple[str, dict]:
        text, calls, usage = initial_text, initial_calls, initial_usage
        for iteration in range(args.max_tool_iterations):
            if not calls:
                return text, usage

            # If the model emitted a protocol message disguised as a tool call,
            # ack it and surface the message text so the caller can handle it.
            # This mostly shows up as 'reset' or 'getEvidence' mid-reasoning.
            collision_msg = detect_protocol_call_collision(calls)
            if collision_msg is not None:
                log(
                    f"  · Protocol-as-tool-call during reasoning: "
                    f"'{calls[0].function.name}' lifted into protocol form.",
                    color="dim",
                )
                ack_protocol_tool_calls(calls)
                # Stuff the lifted message into the text return so the caller
                # treats it as if the model had emitted it as text.
                return ujson.dumps(collision_msg), usage

            # Build tool response messages — OpenAI shape: role=tool, plus
            # tool_call_id matching the assistant's original tool_calls[].id.
            tool_response_messages = []
            for call in calls:
                stats.tool_call_count += 1
                try:
                    parsed_args =ujson.loads(call.function.arguments or "{}")
                except ujson.JSONDecodeError:
                    parsed_args = {}
                stats.tool_calls.append({
                    "name": call.function.name,
                    "args": parsed_args,
                })
                try:
                    result = navigator.call(call.function.name, parsed_args)
                    payload =ujson.dumps({"result": result})
                except Exception as e:
                    err = f"{type(e).__name__}: {e}"
                    log(f"    ⚠ tool error in {call.function.name}: {err}",
                        color="yellow")
                    payload =ujson.dumps({"error": err})
                tool_response_messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.function.name,
                    "content": payload,
                })

            text, calls, usage = send(
                tool_response_messages,
                f"tool responses (iter {iteration + 1}, {len(tool_response_messages)} result(s))",
            )

        raise RuntimeError(
            f"Exceeded {args.max_tool_iterations} tool iterations without a final response."
        )

    def ack_protocol_tool_calls(tool_calls: list, note: str = "") -> None:
        """Send minimal tool responses for a protocol-disguised tool_call.

        When the model emits a protocol message as a function call, the
        assistant turn already has tool_calls in history. The OpenAI API
        requires those to be followed by matching tool responses before
        the next user/assistant turn. Without these acks the next request
        will fail with 'tool_call_id not found'.

        We can't pass the result through send() (that would consume the
        next turn). Instead we append the ack messages directly to the
        history with a simple confirmation payload. The API accepts this
        as long as the ids and shape are right; we never actually request
        a model response to these.
        """
        for call in tool_calls:
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "name": call.function.name,
                "content":ujson.dumps({
                    "result": "acknowledged",
                    "note": note or (
                        "Your function call was a protocol message, not a tool. "
                        "It has been processed by the protocol layer. Continue."
                    ),
                }),
            })

    def try_reset_prompt() -> bool:
        text, calls, _ = send(
            [{"role": "user",
              "content":ujson.dumps({"operation": "reset", "args": "prompt"})}],
            "reset prompt",
        )
        # Reset acks shouldn't trigger tool calls, but if the model emits one,
        # ack it so history stays well-formed for the next turn.
        if calls:
            collision_msg = detect_protocol_call_collision(calls)
            if collision_msg is not None:
                log(
                    f"  · Protocol-as-tool-call on reset ack: lifting "
                    f"'{calls[0].function.name}'.", color="dim",
                )
                ack_protocol_tool_calls(calls)
            else:
                log("  ⚠ Reset triggered tool calls; acking and treating "
                    "ack-text as authoritative.", color="yellow")
                ack_protocol_tool_calls(
                    calls, note="Ignoring tool calls on reset ack.",
                )
        msg = parse_protocol_message(text)
        ok = bool(msg and msg.get("response_code") == "ok")
        if not ok:
            log(f"  ⚠ Reset failed. Model said: {text}", color="yellow")
        return ok

    try:
        # ---------------- Phase 1: bootstrap ----------------
        banner("Phase 1  ·  Bootstrap (expect getSchema)")
        text, calls, _ = send(
            [{"role": "user", "content": "Begin."}],
            "kickoff",
        )
        collision_msg = detect_protocol_call_collision(calls)
        if collision_msg is not None:
            log(
                f"  · Protocol-as-tool-call detected at bootstrap: lifting "
                f"'{calls[0].function.name}'.", color="dim",
            )
            ack_protocol_tool_calls(calls)
            msg = collision_msg
        else:
            msg = parse_protocol_message(text)
        if not msg or msg.get("operation") != "getSchema":
            log(f"❌ Expected getSchema. Got: {msg!r}", color="red")
            return 1

        # ---------------- Phase 2: schema ----------------
        banner("Phase 2  ·  Deliver schema")
        intro = (
            "Here is the evidence schema. Level 2 (decompiled Java, manifest, "
            "resources) and level 3 (smali bytecode) are NOT delivered upfront. "
            "When your protocol's escalation rules require you to consult them, "
            "use the available tools (read_file, find_class, find_subclasses, "
            "list_imports, list_dir, grep) to fetch the specific bytes you need."
        )
        text, calls, _ = send(
            [{"role": "user", "content": f"{intro}\n\n=== schema.md ===\n{schema_text}"}],
            "schema",
        )
        collision_msg = detect_protocol_call_collision(calls)
        if collision_msg is not None:
            log(
                f"  · Protocol-as-tool-call detected at schema: lifting "
                f"'{calls[0].function.name}'.", color="dim",
            )
            ack_protocol_tool_calls(calls)
            msg = collision_msg
        else:
            msg = parse_protocol_message(text)
        if not msg or msg.get("operation") != "getPrompt":
            log(f"❌ Expected getPrompt. Got: {msg!r}", color="red")
            return 1

        # ---------------- Per-test loop ----------------
        for i, prompt_path in enumerate(prompts, 1):
            banner(f"Test {i}/{len(prompts)}  ·  {prompt_path.name}", color="magenta")

            test_stats = TestStats(
                test_file=prompt_path.name,
                test_stem=prompt_path.stem,
                started_at=datetime.now(timezone.utc).isoformat(),
            )

            try:
                test_prompt = prompt_path.read_text()
                text, calls, usage = send(
                    [{"role": "user", "content": test_prompt}],
                    f"prompt: {prompt_path.name}",
                )

                # Check whether the model emitted a protocol message as a tool
                # call (a common confusion with function-calling-trained models).
                # If so, ack the tool calls and lift the message into protocol form.
                collision_msg = detect_protocol_call_collision(calls)
                if collision_msg is not None:
                    log(
                        f"  · Protocol-as-tool-call detected: lifting "
                        f"'{calls[0].function.name}' into protocol form.",
                        color="dim",
                    )
                    ack_protocol_tool_calls(calls)
                    msg = collision_msg
                    calls = []  # consume them
                else:
                    msg = parse_protocol_message(text) if text else None

                is_get_evidence = bool(msg and msg.get("operation") == "getEvidence")
                is_verdict_directly = bool(msg and "verdict" in msg)

                if is_verdict_directly:
                    log("  · Model went straight to verdict (no evidence, no tools).",
                        color="dim")
                    final_text, final_usage = text, usage

                elif is_get_evidence:
                    requested = list(msg.get("args") or [])

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
                        ev_path = args.evidence_dir / name
                        if not ev_path.exists():
                            test_stats.evidence_missing.append(name)
                            payload_chunks.append(
                                f"=== {name}: not found "
                                f"(file does not exist in the evidence directory) ==="
                            )
                            continue
                        content = ev_path.read_text()
                        if name == "strings.json":
                            slim_content = navigator.slim_strings_json(content)
                            saved = len(content) - len(slim_content)
                            if saved > 0:
                                log(
                                    f"    strings.json slimmed: "
                                    f"{len(content):,} → {len(slim_content):,} chars "
                                    f"(saved {saved:,})",
                                    color="dim",
                                )
                            content = slim_content
                        payload_chunks.append(f"=== {name} ===\n{content}")
                        test_stats.evidence_delivered.append(name)

                    for d in test_stats.evidence_delivered:
                        log(f"  ✓ {d} (delivered inline)", color="green")
                    for s in test_stats.evidence_already_inline:
                        log(f"  · {s} (already provided — sent earlier in session)", color="dim")
                    for s in test_stats.evidence_already_via_tools:
                        log(f"  · {s} (already provided — reachable via tools)", color="dim")
                    for m in test_stats.evidence_missing:
                        log(f"  ✗ {m} (NOT FOUND in --evidence-dir)", color="red")

                    evidence_body = "Evidence:\n" + "\n\n".join(payload_chunks)
                    if test_stats.evidence_missing:
                        evidence_body += (
                            f"\n\n[Note: {len(test_stats.evidence_missing)} requested "
                            f"evidence file(s) could not be delivered. Proceed with "
                            f"the available evidence and reflect the gap in your verdict.]"
                        )

                    text, calls, usage = send(
                        [{"role": "user", "content": evidence_body}],
                        f"evidence ({len(test_stats.evidence_delivered)} new)",
                    )
                    sent_evidence_files.update(test_stats.evidence_delivered)
                    final_text, final_usage = resolve_tools(
                        text, calls, usage, test_stats,
                    )

                elif calls:
                    log("  · No getEvidence message — model is using tools directly. "
                        "Resolving tool calls...", color="dim")
                    final_text, final_usage = resolve_tools(
                        text, calls, usage, test_stats,
                    )

                else:
                    log(f"❌ Unexpected response shape. text={text!r} "
                        f"calls={len(calls)}", color="red")
                    test_stats.status = "protocol_error"
                    test_stats.error = (
                        "First response after per-test prompt was neither "
                        "getEvidence, a verdict, nor tool calls"
                    )
                    test_stats.raw_response = text
                    test_stats.finished_at = datetime.now(timezone.utc).isoformat()
                    summary.append(test_stats)
                    if i < len(prompts):
                        if not try_reset_prompt():
                            log("Reset failed; aborting batch.", color="red")
                            break
                    continue

                verdict = parse_protocol_message(final_text)
                test_stats.verdict_turn_tokens = final_usage
                if verdict is None:
                    log("❌ Verdict was not parseable JSON.", color="red")
                    test_stats.status = "parse_error"
                    test_stats.error = "Verdict could not be parsed"
                    test_stats.raw_response = final_text
                else:
                    out_path = args.output_dir / f"{prompt_path.stem}.json"
                    out_path.write_text(ujson.dumps(verdict, indent=2))
                    log(f"  ✓ Saved verdict to {out_path}", color="green")
                    test_stats.status = "ok"
                    test_stats.verdict = verdict.get("verdict")
                    test_stats.certainty = verdict.get("certainty_percent")
                    test_stats.evidence_table_rows = len(verdict.get("evidence_table") or [])
                    log(
                        f"    verdict={test_stats.verdict}  "
                        f"certainty={test_stats.certainty}  "
                        f"rows={test_stats.evidence_table_rows}  "
                        f"tool_calls={test_stats.tool_call_count}",
                        color="green",
                    )

            except Exception as e:
                log(f"❌ Test {prompt_path.name} crashed: {type(e).__name__}: {e}",
                    color="red")
                test_stats.status = "exception"
                test_stats.error = f"{type(e).__name__}: {e}"
                if args.abort_on_error:
                    test_stats.finished_at = datetime.now(timezone.utc).isoformat()
                    summary.append(test_stats)
                    raise

            test_stats.finished_at = datetime.now(timezone.utc).isoformat()
            summary.append(test_stats)

            if i < len(prompts):
                log("\n  ... resetting prompt state for next test ...", color="dim")
                if not try_reset_prompt():
                    log("Reset failed; aborting batch.", color="red")
                    break

        # ---------------- Summary ----------------
        banner("Run summary", color="bold")
        ok_count = sum(1 for r in summary if r.status == "ok")
        log(f"  Tests run:      {len(summary)}")
        log(f"  Successful:     {ok_count}",
            color="green" if ok_count == len(summary) else "yellow")
        log(f"  Errors:         {len(summary) - ok_count}",
            color="red" if ok_count < len(summary) else "")
        log("")
        log(f"  {'TEST':<28} {'STATUS':<13} {'VERDICT':<20} {'CERT':>5}  "
            f"{'ROWS':>5}  {'TOOLS':>5}  {'PROMPT-TOK':>10}")
        log(f"  {'-'*28} {'-'*13} {'-'*20} {'-'*5}  {'-'*5}  {'-'*5}  {'-'*10}")
        for r in summary:
            tokens = (r.verdict_turn_tokens or {}).get("prompt_tokens", "")
            log(
                f"  {r.test_stem[:28]:<28} "
                f"{r.status:<13} "
                f"{str(r.verdict or '')[:20]:<20} "
                f"{str(r.certainty or ''):>5}  "
                f"{str(r.evidence_table_rows or ''):>5}  "
                f"{r.tool_call_count:>5}  "
                f"{str(tokens):>10}"
            )

        summary_path = args.output_dir / "_summary.json"
        summary_path.write_text(ujson.dumps({
            "run_at": datetime.now(timezone.utc).isoformat(),
            "backend": "openai-compatible",
            "base_url": args.base_url,
            "model": args.model,
            "reasoning_effort": args.reasoning_effort,
            "temperature": args.temperature,
            "apk_root": str(args.apk_root),
            "evidence_dir": str(args.evidence_dir),
            "prompts_dir": str(args.prompts_dir),
            "index_stats": navigator.index.stats(),
            "tests": [r.to_dict() for r in summary],
        }, indent=2))
        log(f"\n  Summary written to {summary_path}", color="green")

        return 0 if ok_count == len(summary) else 2

    except Exception as e:
        log(f"\nFatal error: {type(e).__name__}: {e}", color="red")
        summary_path = args.output_dir / "_summary.json"
        summary_path.write_text(ujson.dumps({
            "run_at": datetime.now(timezone.utc).isoformat(),
            "backend": "openai-compatible",
            "base_url": args.base_url,
            "model": args.model,
            "fatal_error": f"{type(e).__name__}: {e}",
            "tests": [r.to_dict() for r in summary],
        }, indent=2))
        log(f"  Partial summary written to {summary_path}", color="yellow")
        return 1


if __name__ == "__main__":
    sys.exit(main())