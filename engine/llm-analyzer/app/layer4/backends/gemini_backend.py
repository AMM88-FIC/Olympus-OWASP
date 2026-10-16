"""
backends/gemini_backend.py — Google Gemini backend (google-genai SDK).

Uses Gemini's native Parts/Content message format, function calling, and
TPM rate limiting (Gemini's quotas are token-per-minute based).
"""

from __future__ import annotations

import ujson
import re
import time
from collections import deque

from google import genai
from google.genai import types

from app.layer4.backends.base import Backend, TurnResult, ToolCall, ToolResponse, Usage


# ============================================================
#  Retry-on-transient-error wrapper
# ============================================================

RETRYABLE_STATUS_CODES = {429, 500, 503, 504}


def _extract_status_code(err: BaseException) -> int | None:
    for attr in ("code", "status_code"):
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
    return None


def _extract_retry_delay_seconds(err: BaseException) -> float | None:
    """Pull RetryInfo.retryDelay from a 429 response's details."""
    details = getattr(err, "details", None)
    if isinstance(details, dict):
        error_block = details.get("error", details) or {}
        for d in (error_block.get("details") or []):
            if isinstance(d, dict) and "RetryInfo" in d.get("@type", ""):
                delay = d.get("retryDelay") or d.get("retry_delay")
                if delay:
                    try:
                        return float(str(delay).rstrip("s"))
                    except ValueError:
                        pass
    m = re.search(r"retry[Dd]elay['\"]?\s*:?\s*['\"]?(\d+(?:\.\d+)?)\s*s",
                  str(err))
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _with_transient_retry(
    fn, *, max_attempts=6, base_backoff=5.0, max_backoff=120.0, on_wait=None,
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
            api_delay = (_extract_retry_delay_seconds(e)
                         if status == 429 else None)
            if api_delay is not None:
                wait = api_delay + 1.0
            else:
                wait = min(base_backoff * (2 ** (attempt - 1)), max_backoff)
            if on_wait:
                on_wait(status, wait, attempt, max_attempts)
            time.sleep(wait)
    assert last_error is not None
    raise last_error


# ============================================================
#  TPM sliding-window rate limiter
# ============================================================

class TPMRateLimiter:
    """In-process pacer for Gemini's input-tokens-per-minute quota."""

    DEFAULT_HEADROOM = 0.9
    COLD_START_ESTIMATE = 100_000
    GROWTH_FACTOR = 1.05

    def __init__(self, tokens_per_minute: int, log_fn=None):
        self.limit = tokens_per_minute
        self.budget = int(tokens_per_minute * self.DEFAULT_HEADROOM)
        self.window: deque = deque()
        self.last_prompt_tokens = 0
        self.log = log_fn or (lambda *a, **k: None)

    def _evict_stale(self, now: float) -> None:
        cutoff = now - 60.0
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()

    def _window_sum(self) -> int:
        return sum(tokens for _, tokens in self.window)

    def estimate_next_request(self) -> int:
        if self.last_prompt_tokens == 0:
            return self.COLD_START_ESTIMATE
        return int(self.last_prompt_tokens * self.GROWTH_FACTOR)

    def acquire(self) -> None:
        estimate = self.estimate_next_request()
        if estimate > self.budget:
            self.log(
                f"  ⚠ Estimated request size ({estimate:,} tokens) exceeds "
                f"the entire TPM budget ({self.budget:,}). Proceeding anyway.",
                color="yellow",
            )
            return
        while True:
            now = time.monotonic()
            self._evict_stale(now)
            current = self._window_sum()
            projected = current + estimate
            if projected <= self.budget:
                return
            need_to_free = projected - self.budget
            freed = 0
            wait_until = None
            for ts, tokens in self.window:
                freed += tokens
                if freed >= need_to_free:
                    wait_until = ts + 60.0
                    break
            if wait_until is None:
                return
            sleep_for = max(0.1, wait_until - now + 0.2)
            self.log(
                f"  ⏸ TPM pacing: window at {current:,}/{self.budget:,}, "
                f"sleeping {sleep_for:.1f}s",
                color="dim",
            )
            time.sleep(sleep_for)

    def record(self, prompt_tokens: int) -> None:
        if prompt_tokens <= 0:
            return
        self.window.append((time.monotonic(), prompt_tokens))
        self.last_prompt_tokens = prompt_tokens


# ============================================================
#  Tool declarations builder
# ============================================================

def _build_tool_declarations(navigator) -> types.Tool:
    """Build Gemini-style tool declarations for the navigator's tool surface.
    Mirrors the OpenAI declarations one-for-one."""
    S = types.Schema
    T = types.Type

    decls = [
        ("list_dir",
         "List immediate children of a directory in the extracted APK tree.",
         {"prefix": (T.STRING, "Relative path from APK root.")}),
        ("read_file",
         "Read a file from the extracted APK tree, optionally limited to a line range. "
         "When level 1 evidence cites Source.line_start and Source.line_end, ALWAYS pass them.",
         {"path": (T.STRING, "Relative path from APK root."),
          "line_start": (T.INTEGER, "1-indexed start line (inclusive)."),
          "line_end": (T.INTEGER, "1-indexed end line (inclusive).")},
         ["path"]),
        ("find_class",
         "Resolve a Java/Kotlin class name to its file path(s).",
         {"name": (T.STRING, "FQN or simple name.")},
         ["name"]),
        ("find_subclasses",
         "Find classes that extend or implement the given fully-qualified type.",
         {"fqn": (T.STRING, "Fully-qualified type name."),
          "transitive": (T.BOOLEAN, "If true, include indirect subclasses.")},
         ["fqn"]),
        ("list_imports",
         "Return imports declared at the top of a Java source file.",
         {"path": (T.STRING, "Relative path to a .java file.")},
         ["path"]),
        ("grep",
         "Regex search across files under a path prefix. Returns a "
         "list of matches with path, line number, and snippet (capped "
         "at 300 chars). Capped at 200 total matches. "
         "Patterns are Python-regex syntax; most patterns also work in "
         "ripgrep, which backs this tool for speed. Use literal "
         "patterns when possible (faster than regex); for regex, stick "
         "to basics (character classes, alternation, anchors). "
         "Avoid backreferences and lookahead — those force a slow "
         "fallback path. Use file_glob to narrow by extension "
         "(e.g. '*.java', '*.smali') when you don't need to search "
         "everything; this is significantly faster than searching the "
         "whole tree.",
         {"pattern": (T.STRING, "Regex pattern (Python syntax). "
                      "Prefer literal strings when possible — they're "
                      "the fastest queries and unambiguous across "
                      "regex flavors."),
          "path_prefix": (T.STRING, "Limit search to this subtree, "
                          "e.g. 'jadx/sources/com/example' or "
                          "'apktool/res'."),
          "file_glob": (T.STRING, "Filename glob, default '*'. "
                        "Use '*.java' to restrict to JADX sources, "
                        "'*.smali' for smali, 'AndroidManifest.xml' "
                        "for the manifest specifically.")},
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
         {"file": (T.STRING, "Evidence filename, e.g. 'api_usages.json'."),
          "ids": (T.ARRAY, "List of record ids, e.g. ['api-001', 'api-002']. "
                  "A single id may also be passed as a bare string.",
                  types.Schema(type=T.STRING))},
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
         {"file": (T.STRING, "Evidence filename, e.g. 'api_usages.json'."),
          "filters": (T.OBJECT, "Map of field-or-dotted-path to regex "
                      "pattern. Empty object returns all records."),
          "limit": (T.INTEGER, "Max records to return (default 50, "
                    "server cap 100)."),
          "case_insensitive": (T.BOOLEAN, "If true, regex matching is "
                               "case-insensitive. Default false.")},
         ["file"]),
        ("count_evidence_records",
         "Return record counts for an evidence file. Without group_by, "
         "returns the total. With group_by (a field name or dotted path), "
         "returns a histogram. Use this to survey a file's distribution "
         "before issuing targeted match_evidence_records calls.",
         {"file": (T.STRING, "Evidence filename, e.g. 'api_usages.json'."),
          "group_by": (T.STRING, "Optional: field name or dotted path to "
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
         {"methods": (T.ARRAY,
                      "Method FQNs in Java style 'package.Class.method' "
                      "(e.g. 'com.duolingo.session.X.persist' or "
                      "'ih.c.A'). Batch multiple methods in one call.",
                      types.Schema(type=T.STRING)),
          "max_depth": (T.INTEGER, "How many caller levels to traverse "
                        "(default 5, max 10). Higher depth catches "
                        "callers buried under several intermediate hops, "
                        "at the cost of more nodes visited per query.")},
         ["methods"]),
         ("find_callees",
         "Walk the call graph forward from a method to find what it "
         "invokes, directly or transitively. Symmetric to find_callers "
         "but in the forward direction — use it to map an IPC entry "
         "point's call tree, see what platform sinks (new File, "
         "FileOutputStream, ContentResolver.query, openFileDescriptor) "
         "a handler reaches, or trace a workflow from an exported "
         "component into the app's helper classes. For each input "
         "method, returns: "
         "direct_callees (immediate calls); "
         "reaches_proprietary / reaches_platform / "
         "reaches_named_third_party / reaches_obfuscated_leaf "
         "(booleans about what the call tree reaches); "
         "transitive_callees_by_class (deduplicated lists of methods "
         "reached, classified — scan the 'platform' list for sink "
         "patterns); "
         "example_paths (up to 5 chains); "
         "stopped_at_depth_limit, not_in_graph (standard flags). "
         "JADX-form class names (with C0123-prefix on case-collision "
         "classes) are normalized to bytecode form automatically; "
         "pass either form.",
         {"methods": (T.ARRAY,
                      "Method FQNs in Java style 'package.Class.method' "
                      "(e.g. 'com.android.fileexplorer.activity.FileActivity"
                      ".handleIntent'). Batch multiple methods in one "
                      "call. JADX-form names like 'com.android.fileexplorer."
                      "h.C0334g.a' are normalized to bytecode form "
                      "automatically.",
                      types.Schema(type=T.STRING)),
          "max_depth": (T.INTEGER, "How many callee levels to traverse "
                        "forward (default 5, max 10). Deeper walks find "
                        "sinks buried under several layers of helper "
                        "methods, at the cost of more nodes visited per "
                        "query.")},
         ["methods"]),
        ("search_code",
         "Semantic search over the decompiled APK source code.",
         {"query": (T.STRING, "Natural language description of what to find."),
          "top_k": (T.INTEGER, "Number of results (1-20, default 5)."),
          "path_prefix": (T.STRING, "Optional: scope to paths starting with this prefix."),
          "is_smali": (T.BOOLEAN, "Optional: true for smali only.")},
         ["query"]),
    ]

    function_declarations = []
    for entry in decls:
        if len(entry) == 3:
            name, description, params = entry
            required: list[str] = []
        else:
            name, description, params, required = entry
        properties = {}
        for pname, pspec in params.items():
            # Each param spec is either (type, desc) or (type, desc, items).
            # The third element is required only for ARRAY-typed params,
            # where it specifies the schema for list elements.
            if len(pspec) == 3:
                ptype, pdesc, pitems = pspec
                properties[pname] = S(
                    type=ptype, description=pdesc, items=pitems,
                )
            else:
                ptype, pdesc = pspec
                properties[pname] = S(type=ptype, description=pdesc)
        kw = {"type": T.OBJECT, "properties": properties}
        if required:
            kw["required"] = required
        function_declarations.append(types.FunctionDeclaration(
            name=name, description=description, parameters=S(**kw),
        ))
    return types.Tool(function_declarations=function_declarations)


# ============================================================
#  The Backend
# ============================================================

class GeminiBackend(Backend):
    """Google Gemini backend using the google-genai SDK."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        system_prompt: str,
        tpm_limit: int = 2_000_000,
        max_request_retries: int = 6,
        request_retry_base_seconds: float = 5.0,
        request_retry_max_seconds: float = 120.0,
        cached_content: str | None = None,
        rate_limiter=None,
        log_fn=None,
    ):
        self._model = model
        self.client = genai.Client(api_key=api_key)
        self.system_prompt = system_prompt
        self.max_request_retries = max_request_retries
        self.request_retry_base_seconds = request_retry_base_seconds
        self.request_retry_max_seconds = request_retry_max_seconds
        self.log = log_fn or (lambda *a, **k: None)

        # When set, the model's system_instruction (and tool declarations)
        # come from a server-side explicit cache rather than being re-sent
        # inline on every turn. Set by the parallel orchestrator; None for
        # the normal sequential runner.
        self.cached_content = cached_content

        # Conversation state
        self.history: list[types.Content] = []

        # Tools — populated by configure_tools()
        self.tools: list[types.Tool] = []

        # Rate limiter. An external (shared) limiter takes precedence — the
        # parallel orchestrator passes one shared across all worker backends
        # so the account-level TPM/RPM quota is enforced collectively. If
        # none is supplied, fall back to a per-backend TPM limiter (the
        # sequential runner's behaviour).
        self.rate_limiter = rate_limiter
        if self.rate_limiter is None and tpm_limit > 0:
            self.rate_limiter = TPMRateLimiter(tpm_limit, log_fn=log_fn)

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def model(self) -> str:
        return self._model

    # ---------- conversation control ----------

    def reset_history(self) -> None:
        self.history = []

    def history_length(self) -> int:
        return len(self.history)

    def snapshot_history(self) -> list[types.Content]:
        return list(self.history)

    def restore_history(self, snapshot) -> None:
        self.history = list(snapshot)

    # ---------- rate limiting ----------

    def acquire_rate_budget(self) -> None:
        if self.rate_limiter is not None:
            self.rate_limiter.acquire()

    def record_usage(self, usage: Usage) -> None:
        if self.rate_limiter is not None and usage.prompt_tokens:
            self.rate_limiter.record(usage.prompt_tokens)

    # ---------- tools ----------

    def configure_tools(self, navigator) -> None:
        self.tools = [_build_tool_declarations(navigator)]

    # ---------- send ----------

    def send_user_message(
        self,
        content: str,
        *,
        label: str = "",
    ) -> TurnResult:
        parts = [types.Part.from_text(text=content)]
        return self._send_parts(parts, label)

    def send_tool_responses(
        self, responses: list[ToolResponse], *, label: str = "",
    ) -> TurnResult:
        parts = [
            types.Part.from_function_response(
                name=r.name,
                response=(r.content if isinstance(r.content, dict)
                          else {"result": r.content}),
            )
            for r in responses
        ]
        return self._send_parts(parts, label)

    def _log_outgoing(self, parts: list, label: str) -> None:
        """Print >>> USER lines for parts we're about to send. Mirrors the
        format the engine uses for incoming MODEL turns."""
        self.log(f"\n>>> USER  ({label})", color="yellow")
        for p in parts:
            text = getattr(p, "text", None)
            if text:
                preview = text[:160].replace("\n", " ")
                truncated = "..." if len(text) > 160 else ""
                self.log(f"    text: {preview}{truncated}", color="dim")
                continue
            fr = getattr(p, "function_response", None)
            if fr is not None:
                import ujson as _json
                try:
                    resp_preview = _json.dumps(fr.response)[:120].replace(
                        "\n", " ",
                    )
                except Exception:
                    resp_preview = str(fr.response)[:120]
                self.log(
                    f"    fn-response: {fr.name}({resp_preview}...)",
                    color="dim",
                )

    def _send_parts(self, parts: list[types.Part], label: str) -> TurnResult:
        self.acquire_rate_budget()
        self._log_outgoing(parts, label)
        self.history.append(types.Content(role="user", parts=parts))

        def _on_wait(status, wait, attempt, max_attempts):
            self.log(
                f"  ⏳ HTTP {status} — pausing {wait:.1f}s "
                f"(attempt {attempt}/{max_attempts})",
                color="yellow",
            )

        def _do_call():
            if self.cached_content:
                # system_instruction + tool declarations live in the
                # explicit cache; passing them again here is rejected by
                # the API, so the request carries only the live history.
                gen_config = types.GenerateContentConfig(
                    cached_content=self.cached_content,
                )
            else:
                gen_config = types.GenerateContentConfig(
                    system_instruction=self.system_prompt,
                    tools=self.tools,
                )
            return self.client.models.generate_content(
                model=self._model,
                contents=self.history,
                config=gen_config,
            )

        resp = _with_transient_retry(
            _do_call,
            max_attempts=self.max_request_retries,
            base_backoff=self.request_retry_base_seconds,
            max_backoff=self.request_retry_max_seconds,
            on_wait=_on_wait,
        )

        # Append the assistant turn to history
        if resp.candidates and resp.candidates[0].content:
            self.history.append(resp.candidates[0].content)

        # Extract text and function calls
        text_parts = []
        tool_calls = []
        if resp.candidates and resp.candidates[0].content:
            for i, part in enumerate(resp.candidates[0].content.parts or []):
                if getattr(part, "text", None):
                    text_parts.append(part.text)
                fc = getattr(part, "function_call", None)
                if fc and fc.name:
                    tool_calls.append(ToolCall(
                        id=f"call_{i}",  # Gemini doesn't supply ids
                        name=fc.name,
                        args=dict(fc.args or {}),
                    ))
        text = "".join(text_parts).strip()

        usage = Usage()
        u = getattr(resp, "usage_metadata", None)
        if u:
            usage = Usage(
                prompt_tokens=getattr(u, "prompt_token_count", None),
                completion_tokens=getattr(u, "candidates_token_count", None),
                total_tokens=getattr(u, "total_token_count", None),
                cached_tokens=getattr(u, "cached_content_token_count", None),
            )
        self.record_usage(usage)

        return TurnResult(text=text, tool_calls=tool_calls, usage=usage)

    def ack_protocol_tool_calls(self, tool_calls: list[ToolCall]) -> None:
        """Gemini doesn't strictly require this (tool_calls aren't id-paired),
        but for symmetry with OpenAIBackend we still emit ack responses so
        the conversation history clearly shows the model's tool calls were
        addressed. Otherwise the next turn might re-emit them."""
        if not tool_calls:
            return
        parts = [
            types.Part.from_function_response(
                name=call.name,
                response={"result": "acknowledged",
                          "note": "Your function call was a protocol message."},
            )
            for call in tool_calls
        ]
        self.history.append(types.Content(role="user", parts=parts))


# ============================================================
#  Explicit cache creation
# ============================================================

def create_explicit_cache(
    *,
    api_key: str,
    model: str,
    system_prompt: str,
    navigator,
    handshake_contents=None,
    ttl_seconds: int = 3600,
    display_name: str = "verdict_engine_prefix",
    log_fn=None,
) -> str:
    """Create a server-side explicit cache holding the constant conversation
    prefix and return its handle (``cache.name``).

    The cache holds, all at cache-hit rate:
      - ``system_instruction`` = the system prompt,
      - ``tools`` = the navigator's tool declarations, and
      - ``contents`` = ``handshake_contents``: the deterministic bootstrap
        transcript (Begin → getSchema → schema delivery → getPrompt).

    Embedding the handshake — schema included — is what lets the schema be
    cached. Gemini does NOT implicitly cache a request's dynamic ``contents``
    on top of an explicit cache, so anything left in live history (like the
    schema) would otherwise be full-billed on every turn. With the whole
    prefix in the cache, each worker's live history starts empty and the
    model is already in the ``initialized`` state (it has 'just' emitted
    getPrompt in the cached transcript).

    The cache is keyed to ``model`` — requests referencing it MUST use the
    same model. Raises on failure (e.g. content below the model's minimum
    cacheable token count); callers may catch and fall back to inline delivery.
    """
    log = log_fn or (lambda *a, **k: None)
    client = genai.Client(api_key=api_key)
    tools = [_build_tool_declarations(navigator)]
    cfg = types.CreateCachedContentConfig(
        display_name=display_name,
        system_instruction=system_prompt,
        tools=tools,
        ttl=f"{int(ttl_seconds)}s",
    )
    if handshake_contents:
        cfg.contents = handshake_contents
    cache = client.caches.create(model=model, config=cfg)
    cached_tokens = None
    usage = getattr(cache, "usage_metadata", None)
    if usage is not None:
        cached_tokens = getattr(usage, "total_token_count", None)
    if cached_tokens is not None:
        log(
            f"  Explicit cache created: {cache.name} "
            f"({cached_tokens:,} tokens, ttl {ttl_seconds}s)",
            color="green",
        )
    else:
        log(
            f"  Explicit cache created: {cache.name} (ttl {ttl_seconds}s)",
            color="green",
        )
    return cache.name


def explicit_cache_exists(*, api_key: str, cache_name: str) -> bool:
    """Return True if ``cache_name`` still resolves to a live cache server-side.

    A persisted handle can go stale (cache deleted, TTL elapsed, different
    project/key); callers use this to decide whether to reuse or recreate.
    Any error — including a not-found — is treated as 'not usable'.
    """
    try:
        client = genai.Client(api_key=api_key)
        client.caches.get(name=cache_name)
        return True
    except Exception:
        return False