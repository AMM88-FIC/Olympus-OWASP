"""
backends/openai_backend.py — OpenAI Chat Completions backend.

Works with any OpenAI-compatible endpoint: official OpenAI, Ollama (/v1),
vLLM, OpenWebUI (/api), llama-cpp-server, etc.
"""

from __future__ import annotations

import ujson
import re
import sys
import time

from openai import OpenAI

from app.layer4.backends.base import Backend, TurnResult, ToolCall, ToolResponse, Usage


# ============================================================
#  Retry-on-transient-error wrapper (OpenAI-compatible flavour)
# ============================================================

RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


def _extract_status_code(err: BaseException) -> int | None:
    """Best-effort HTTP status extraction across SDK exception shapes."""
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


def _with_transient_retry(
    fn,
    *,
    max_attempts: int = 6,
    base_backoff: float = 5.0,
    max_backoff: float = 120.0,
    on_wait=None,
):
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
                on_wait(status, wait, attempt, max_attempts)
            time.sleep(wait)
    assert last_error is not None
    raise last_error


# ============================================================
#  Protocol-as-tool-call collision detection
# ============================================================

PROTOCOL_OP_NAMES = {"getSchema", "getEvidence", "getPrompt", "reset"}


def detect_protocol_call_collision(tool_calls: list[ToolCall]) -> dict | None:
    """Detect when the model packaged a protocol message as a tool call
    instead of as JSON text. Returns the lifted protocol message, or None."""
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
#  Tool declarations builder
# ============================================================

def _build_tool_declarations(navigator) -> list[dict]:
    """Build OpenAI-style tool declarations for the navigator's tool surface."""
    # The descriptions are static; we don't introspect the navigator. If you
    # add a new tool to APKNavigator, add a matching declaration here.
    decls = [
        ("list_dir",
         "List immediate children of a directory in the extracted APK tree. "
         "Use to orient yourself before reading files. Directory entries end with '/'.",
         {"prefix": ("string", "Relative path from APK root, "
                     "e.g. 'jadx/sources/com/example/'. Empty string for root.")}),
        ("read_file",
         "Read a file from the extracted APK tree, optionally limited to a line range. "
         "When level 1 evidence cites Source.line_start and Source.line_end, ALWAYS "
         "pass them — never read full files when you have a range.",
         {"path": ("string", "Relative path from APK root."),
          "line_start": ("integer", "1-indexed start line (inclusive)."),
          "line_end": ("integer", "1-indexed end line (inclusive).")},
         ["path"]),
        ("find_class",
         "Resolve a Java/Kotlin class name (FQN or simple) to its file path(s). "
         "Returns ClassRef entries with `fqn`, `path`, `is_smali`. If is_smali is "
         "true, JADX failed to decompile the class and only smali is available.",
         {"name": ("string", "Fully-qualified name like 'com.foo.Bar' "
                   "or simple name like 'Bar'.")},
         ["name"]),
        ("find_subclasses",
         "Find classes that extend or implement the given fully-qualified type. "
         "Use to discover the concrete implementation of an abstract base or interface.",
         {"fqn": ("string", "Fully-qualified type name."),
          "transitive": ("boolean", "If true, include indirect subclasses. "
                         "Default false (direct only).")},
         ["fqn"]),
        ("list_imports",
         "Return imports declared at the top of a Java source file. Use to "
         "disambiguate which type a name refers to.",
         {"path": ("string", "Relative path to a .java file.")},
         ["path"]),
        ("grep",
         "Regex search across files under a path prefix. Use sparingly — prefer "
         "find_class + read_file when you already know the location.",
         {"pattern": ("string", "Python regex."),
          "path_prefix": ("string", "Limit search to this subtree."),
          "file_glob": ("string", "Filename glob, e.g. '*.java'. Default '*'.")},
         ["pattern"]),
        ("list_evidence_files",
         "List evidence files available for this APK with their record "
         "counts. The L1 schema (received at bootstrap) describes what "
         "fields each file contains; this tool tells you which files are "
         "actually present and how many records each has.",
         {},
         []),
        ("get_evidence_record",
         "Return one or more records by id from an evidence file. Pass a "
         "list of ids (or a single id string) to fetch in one call instead "
         "of many. Ids are stable identifiers from the L1 schema (e.g. "
         "'api-001', 'stor-014', 'cmp-002'). Returns {records: {id: ...}, "
         "missing: [id, ...]}. Missing ids are reported in `missing`, not "
         "as errors. Batch as many ids as you need — no cap.",
         {"file": ("string", "Evidence filename, e.g. 'api_usages.json'."),
          "ids": ("array", "List of record ids, e.g. ['api-001', 'api-002']. "
                  "A single id may also be passed as a bare string.",
                  {"type": "string"})},
         ["file", "ids"]),
        ("match_evidence_records",
        "Return records in an evidence file whose fields match the regex "
        "patterns in `filters`. Filter values are Python regex patterns "
        "applied via re.search. Substring match by default; use ^...$ to "
        "anchor; alternation works (Cipher|MessageDigest). Pass dots "
        "unescaped — e.g. 'a.b.C' rather than 'a\\.b\\.C'. Filter keys "
        "may use dotted paths for nested fields. Non-string values are "
        "coerced to JSON repr. Use the field-value vocabularies from "
        "the file's acknowledgement to avoid 0-match guesses. Returns "
        "{matched, match_count, truncated, limit}, or {error: ...} for "
        "malformed regex.",
         {"file": ("string", "Evidence filename, e.g. 'api_usages.json'."),
          "filters": ("object", "Map of field-or-dotted-path to regex "
                      "pattern. Empty object returns all records."),
          "limit": ("integer", "Max records to return (default 50, "
                    "server cap 100)."),
          "case_insensitive": ("boolean", "If true, regex matching is "
                               "case-insensitive. Default false.")},
         ["file"]),
        ("count_evidence_records",
         "Return record counts for an evidence file. Without group_by, "
         "returns the total. With group_by (a field name or dotted path), "
         "returns a histogram. Use this to survey a file's distribution "
         "before issuing targeted match_evidence_records calls.",
         {"file": ("string", "Evidence filename, e.g. 'api_usages.json'."),
          "group_by": ("string", "Optional: field name or dotted path to "
                       "group by, e.g. 'domain' or 'exported.effective'.")},
         ["file"]),
         ("find_callers",
         "Walk the call graph backwards from a method to find which "
         "methods invoke it (directly or transitively). For each input "
         "method, returns three boolean flags about what the chain of "
         "callers reaches: "
         "reachable_from_proprietary (true if any chain reaches a method "
         "in the app's own package namespace); "
         "reachable_from_named_third_party (true if any chain reaches a "
         "method in a named non-app namespace like 'com.sendbird.*' or "
         "'com.facebook.*'); "
         "all_chains_unresolved (true if no chains reach either — every "
         "caller is obfuscated or terminates without resolving). "
         "Also returns example_paths: up to 5 caller chains "
         "showing the actual call sequences. These chains can be useful "
         "context for understanding what obfuscated methods do",
         {"methods": ("array",
                      "Method FQNs in Java style 'package.Class.method' "
                      "(e.g. 'com.duolingo.session.X.persist' or "
                      "'ih.c.A'). Batch multiple methods in one call.",
                      {"type": "string"}),
          "max_depth": ("integer", "How many caller levels to traverse "
                        "(default 5, max 10). Higher depth catches "
                        "callers buried under several intermediate hops, "
                        "at the cost of more nodes visited per query.")},
         ["methods"]),
        ("search_code",
         "Semantic search over the decompiled APK source code. Returns "
         "code chunks ranked by similarity to a natural-language query — "
         "use this to FIND code by intent when you don't already have a "
         "path or class name. Returns empty list if RAG is not enabled.",
         {"query": ("string", "Natural language description of what to find."),
          "top_k": ("integer", "Number of results (1-20, default 5)."),
          "path_prefix": ("string", "Optional: scope to paths starting with this prefix."),
          "is_smali": ("boolean", "Optional: true for smali only, "
                       "false for Java only.")},
         ["query"]),
    ]

    out = []
    for entry in decls:
        if len(entry) == 3:
            name, description, params = entry
            required: list[str] = []
        else:
            name, description, params, required = entry
        properties = {}
        for pname, pspec in params.items():
            # Each param spec is either (type, desc) or (type, desc, items).
            # The third element is required only for "array"-typed params.
            if len(pspec) == 3:
                ptype, pdesc, pitems = pspec
                properties[pname] = {
                    "type": ptype, "description": pdesc, "items": pitems,
                }
            else:
                ptype, pdesc = pspec
                properties[pname] = {"type": ptype, "description": pdesc}
        out.append({
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    **({"required": required} if required else {}),
                },
            },
        })
    return out


# ============================================================
#  The Backend
# ============================================================

class OpenAIBackend(Backend):
    """OpenAI Chat Completions backend. Compatible with Ollama, vLLM,
    OpenWebUI, and the official OpenAI API."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        system_prompt: str,
        temperature: float = 0.2,
        num_ctx: int = 100000,
        max_tokens: int = 90000,
        reasoning_effort: str = "medium",
        json_mode: str = "off",
        request_timeout: float = 600.0,
        max_request_retries: int = 6,
        request_retry_base_seconds: float = 5.0,
        request_retry_max_seconds: float = 120.0,
        decorate_system_prompt: bool = True,
        log_fn=None,
    ):
        self._model = model
        self.client = OpenAI(
            base_url=base_url, api_key=api_key, timeout=request_timeout,
        )
        self.client.verify_ssl = False
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.max_tokens = max_tokens
        self.json_mode = json_mode
        self.max_request_retries = max_request_retries
        self.request_retry_base_seconds = request_retry_base_seconds
        self.request_retry_max_seconds = request_retry_max_seconds
        self.log = log_fn or (lambda *a, **k: None)

        # Build the system prompt with reasoning-effort prefix and protocol
        # clarification appended. Skipped (decorate_system_prompt=False) for
        # roles that need a clean prompt — e.g. the verdict verifier, which is
        # not an analyst and must not be told about getSchema/tools.
        if decorate_system_prompt:
            self.system_prompt = self._build_system_prompt(
                system_prompt, reasoning_effort,
            )
        else:
            self.system_prompt = system_prompt

        # Conversation state
        self.messages: list[dict] = [
            {"role": "system", "content": self.system_prompt}
        ]

        # Tools — populated by configure_tools()
        self.tools: list[dict] = []
        self.response_format: dict | None = self._build_response_format()

    @property
    def name(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    # ---------- system prompt construction ----------

    @staticmethod
    def _build_system_prompt(raw: str, reasoning_effort: str) -> str:
        clarification = (
            "\n\n## CRITICAL: Protocol messages are NOT function calls\n\n"
            "You have access to two distinct response mechanisms. Do not confuse them.\n\n"
            "1. **Protocol messages** (`getSchema`, `getPrompt`, `getEvidence`, "
            "`reset`, the verdict). These are emitted as JSON in your text response. "
            "They are NEVER function calls.\n\n"
            "2. **Function tools** (`read_file`, `find_class`, `find_subclasses`, "
            "`list_imports`, `list_dir`, `grep`, `list_evidence_files`, "
            "`get_evidence_record`, `match_evidence_records`, "
            "`count_evidence_records`, `search_code`). These are emitted "
            "via the function-calling mechanism. They are NEVER protocol messages.\n"
        )
        return f"Reasoning: {reasoning_effort}\n\n{raw}{clarification}"

    def _build_response_format(self) -> dict | None:
        if self.json_mode == "off":
            return None
        if self.json_mode == "object":
            return {"type": "json_object"}
        if self.json_mode == "schema":
            return {
                "type": "json_schema",
                "json_schema": {
                    "name": "ProtocolOrVerdict",
                    "strict": False,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "status": {"type": "string"},
                            "operation": {"type": "string"},
                            "args": {},
                            "response_code": {"type": "string"},
                            "test_id": {"type": "string"},
                            "verdict": {"type": "string"},
                            "certainty_percent": {"type": "integer"},
                            "evidence_table": {"type": "array"},
                            "rationale": {"type": "string"},
                            "mapped_maswe": {"type": "array"},
                            "recommended_mastg_tests": {"type": "array"},
                            "needs_dynamic_testing": {"type": "boolean"},
                            "false_positive_risks": {"type": "array"},
                        },
                        "additionalProperties": True,
                    },
                },
            }
        return None

    # ---------- conversation control ----------

    def reset_history(self) -> None:
        self.messages = [m for m in self.messages if m.get("role") == "system"]

    def history_length(self) -> int:
        return len(self.messages)

    def snapshot_history(self) -> list[dict]:
        # Shallow copy is fine because we never mutate dicts in place
        return list(self.messages)

    def restore_history(self, snapshot) -> None:
        self.messages = list(snapshot)

    # ---------- tools ----------

    def configure_tools(self, navigator) -> None:
        self.tools = _build_tool_declarations(navigator)

    # ---------- send ----------

    def _log_outgoing(self, new_messages: list[dict], label: str) -> None:
        """Print >>> USER lines for messages we're about to send. Mirrors the
        format the engine uses for incoming MODEL turns."""
        self.log(f"\n>>> USER  ({label})", color="yellow")
        for m in new_messages:
            role = m.get("role", "?")
            # Tool responses are formatted differently — check role first so
            # we don't fall through to the generic content branch (tool
            # messages also have a 'content' field).
            if role == "tool":
                resp_preview = str(m.get("content") or "")[:120].replace(
                    "\n", " ",
                )
                truncated = "..." if len(str(m.get("content") or "")) > 120 \
                    else ""
                self.log(
                    f"    [tool→{m.get('name','?')}] {resp_preview}{truncated}",
                    color="dim",
                )
            elif m.get("content"):
                preview = str(m["content"])[:160].replace("\n", " ")
                truncated = "..." if len(str(m["content"])) > 160 else ""
                self.log(f"    [{role}] {preview}{truncated}", color="dim")

    def send_user_message(
        self,
        content: str,
        *,
        label: str = "",
    ) -> TurnResult:
        return self._send([{"role": "user", "content": content}], label)

    def send_tool_responses(
        self, responses: list[ToolResponse], *, label: str = "",
    ) -> TurnResult:
        msgs = [
            {
                "role": "tool",
                "tool_call_id": r.tool_call_id,
                "name": r.name,
                "content": r.content if isinstance(r.content, str)
                           else ujson.dumps(r.content),
            }
            for r in responses
        ]
        return self._send(msgs, label)

    def _send(self, new_messages: list[dict], label: str) -> TurnResult:
        self.acquire_rate_budget()
        self._log_outgoing(new_messages, label)
        self.messages.extend(new_messages)

        def _on_wait(status, wait, attempt, max_attempts):
            self.log(
                f"  ⏳ HTTP {status} — pausing {wait:.1f}s "
                f"(attempt {attempt}/{max_attempts})",
                color="yellow",
            )

        def _do_call():
            kwargs = {
                "model": self._model,
                "messages": self.messages,
                "tools": self.tools,
                "tool_choice": "auto",
                "temperature": self.temperature,
                "extra_body": {"num_ctx": self.num_ctx}
            }
            if self.response_format is not None:
                kwargs["response_format"] = self.response_format
            return self.client.chat.completions.create(**kwargs)

        resp = _with_transient_retry(
            _do_call,
            max_attempts=self.max_request_retries,
            base_backoff=self.request_retry_base_seconds,
            max_backoff=self.request_retry_max_seconds,
            on_wait=_on_wait,
        )

        choice = resp.choices[0]
        msg = choice.message

        # Append the assistant turn to history exactly as returned. OpenAI
        # requires the assistant message be present (with tool_calls if any)
        # before tool responses can be appended.
        history_msg: dict = {"role": "assistant"}
        if msg.content is not None:
            history_msg["content"] = msg.content
        if msg.tool_calls:
            history_msg["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name,
                              "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        self.messages.append(history_msg)

        text = msg.content or ""
        tool_calls = []
        for tc in (msg.tool_calls or []):
            try:
                args =ujson.loads(tc.function.arguments or "{}")
            except ujson.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(
                id=tc.id, name=tc.function.name, args=args,
            ))

        usage = Usage()
        if resp.usage:
            usage = Usage(
                prompt_tokens=resp.usage.prompt_tokens,
                completion_tokens=resp.usage.completion_tokens,
                total_tokens=resp.usage.total_tokens,
            )
        self.record_usage(usage)

        return TurnResult(text=text, tool_calls=tool_calls, usage=usage)

    # ---------- protocol-as-tool-call recovery ----------

    def ack_protocol_tool_calls(self, tool_calls: list[ToolCall]) -> None:
        """When the model packages a protocol message as a tool call, we still
        need to ack each tool_call_id so OpenAI's history stays well-formed.
        Appends minimal tool responses directly to history without round-trip."""
        for call in tool_calls:
            self.messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "name": call.name,
                "content":ujson.dumps({
                    "result": "acknowledged",
                    "note": (
                        "Your function call was a protocol message, not a tool. "
                        "It has been processed by the protocol layer."
                    ),
                }),
            })