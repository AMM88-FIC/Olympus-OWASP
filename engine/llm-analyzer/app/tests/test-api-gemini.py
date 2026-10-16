"""
test_gemini_apk.py — Batch verdict-engine runner with function calling.

L2/L3 access is via on-demand tool calls (read_file, find_class, list_dir,
find_subclasses, list_imports, grep) backed by an extracted APK directory
on disk. No bulk upload — only the specific bytes the model requests
through tool calls reach the context window.

Conversation flow per session:

    Initialization:
        Code: "Begin." (kickoff)
        LLM:  getSchema
        Code: schema text
        LLM:  getPrompt

    Per-test loop:
        Code: per-test prompt
        LLM:  getEvidence (list of L1 file names; tars/xmls silently dropped)
        Code: requested L1 evidence inline (only files not already sent)
        LLM:  reasoning turns with tool calls (read_file, find_class, ...)
              → resolved locally via APKNavigator
              → results fed back as function_response parts
              → loop until LLM emits a turn with only text (the verdict)
        Code: stores verdict, sends `reset prompt`
        LLM:  ack {"status":"initialized","response_code":"ok"}

Requires the system prompt to be patched for the L2/L3-via-tools mechanic
(see system_prompt_patch.md) and the per-row L2 verification rule (see
system_prompt_patch_v1.3.2.md).

Usage:
    export GEMINI_API_KEY=...
    python test_gemini_apk.py \\
        --apk-root /extracted/diva \\
        --system-prompt 1.system_prompt-v1.3.3.md \\
        --schema 2.layer3_schema_v1_2_4_full_spec.md \\
        --evidence-dir /extracted/diva/evidence \\
        --prompts-dir app/layer4/prompts/ada-mobile-profile-certification/ \\
        --output-dir verdicts/diva/
"""

from __future__ import annotations

import argparse
import ujson
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from google import genai
from google.genai import types

# Local library: builds an index from the extracted APK and exposes the tools.
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
#  Tool declarations (mirror APKNavigator.TOOL_NAMES exactly)
# ============================================================

def build_tool_declarations() -> types.Tool:
    S = types.Schema
    T = types.Type
    return types.Tool(function_declarations=[
        types.FunctionDeclaration(
            name="list_dir",
            description=(
                "List immediate children of a directory in the extracted APK tree. "
                "Use to orient yourself before reading files. Directory entries end with '/'."
            ),
            parameters=S(type=T.OBJECT, properties={
                "prefix": S(type=T.STRING, description=(
                    "Relative path from APK root, e.g. 'jadx/sources/com/example/'. "
                    "Empty string for root."
                )),
            }),
        ),
        types.FunctionDeclaration(
            name="read_file",
            description=(
                "Read a file from the extracted APK tree, optionally limited to a line range. "
                "When level 1 evidence cites Source.line_start and Source.line_end, ALWAYS "
                "pass them — never read full files when you have a range. Reading the whole "
                "file when a 30-line range is sufficient is wasteful and forbidden."
            ),
            parameters=S(type=T.OBJECT, properties={
                "path": S(type=T.STRING, description=(
                    "Relative path from APK root, e.g. "
                    "'jadx/sources/com/example/MainActivity.java' or "
                    "'apktool/AndroidManifest.xml' or "
                    "'apktool/smali/com/example/MainActivity.smali'."
                )),
                "line_start": S(type=T.INTEGER, description="1-indexed start line (inclusive)."),
                "line_end":   S(type=T.INTEGER, description="1-indexed end line (inclusive)."),
            }, required=["path"]),
        ),
        types.FunctionDeclaration(
            name="find_class",
            description=(
                "Resolve a Java/Kotlin class name (FQN or simple) to its file path(s). "
                "Returns ClassRef entries with `fqn`, `path`, `is_smali`. If is_smali is "
                "true, JADX failed to decompile the class and only smali is available — "
                "treat that as L3 and follow the escalation rules accordingly."
            ),
            parameters=S(type=T.OBJECT, properties={
                "name": S(type=T.STRING, description=(
                    "Fully-qualified name like 'com.foo.Bar' or simple name like 'Bar'."
                )),
            }, required=["name"]),
        ),
        types.FunctionDeclaration(
            name="find_subclasses",
            description=(
                "Find classes that extend or implement the given fully-qualified type. "
                "Use to discover the concrete implementation of an abstract base or interface "
                "cited in evidence (e.g. when an L1 record points at BaseAuthActivity but the "
                "actual logic lives in a subclass)."
            ),
            parameters=S(type=T.OBJECT, properties={
                "fqn": S(type=T.STRING, description="Fully-qualified type name."),
                "transitive": S(type=T.BOOLEAN, description=(
                    "If true, include indirect subclasses. Default false (direct only)."
                )),
            }, required=["fqn"]),
        ),
        types.FunctionDeclaration(
            name="list_imports",
            description=(
                "Return imports declared at the top of a Java source file. Use to "
                "disambiguate which type a name refers to (e.g. javax.crypto.Cipher vs a "
                "third-party shim with the same simple name)."
            ),
            parameters=S(type=T.OBJECT, properties={
                "path": S(type=T.STRING, description="Relative path to a .java file."),
            }, required=["path"]),
        ),
        types.FunctionDeclaration(
            name="grep",
            description=(
                "Regex search across files under a path prefix. Use sparingly — prefer "
                "find_class + read_file when you already know the location. Returns up to "
                "200 matches with snippets capped at 300 chars."
            ),
            parameters=S(type=T.OBJECT, properties={
                "pattern": S(type=T.STRING, description="Python regex."),
                "path_prefix": S(type=T.STRING, description=(
                    "Limit search to this subtree, e.g. 'jadx/sources/com/example/'."
                )),
                "file_glob": S(type=T.STRING, description=(
                    "Filename glob, e.g. '*.java' or '*.smali'. Default '*'."
                )),
            }, required=["pattern"]),
        ),
        types.FunctionDeclaration(
            name="get_string_record",
            description=(
                "Return the full record for a given strings.json id. The strings.json "
                "file is delivered inline in slim form (id, category, value, path only) "
                "to keep token cost manageable. Use this tool to expand a specific "
                "record when you need its snippet_context, noise_signals, or any other "
                "field beyond the four delivered inline. Always pass the id exactly "
                "as it appears in the slim manifest."
            ),
            parameters=S(type=T.OBJECT, properties={
                "string_id": S(type=T.STRING, description=(
                    "The id from the slim strings.json record, e.g. 'str-2206'."
                )),
            }, required=["string_id"]),
        ),
        types.FunctionDeclaration(
            name="list_string_records_by_category",
            description=(
                "Return up to N full strings.json records under a given category, "
                "e.g. 'API_KEY', 'CREDENTIAL', 'SECRET_KEY', 'URL'. Use when you "
                "want to enumerate all records of a class up front rather than "
                "picking ids one by one from the slim manifest. Capped server-side "
                "at 100 records per call."
            ),
            parameters=S(type=T.OBJECT, properties={
                "category": S(type=T.STRING, description=(
                    "Category name as it appears in records, e.g. 'API_KEY'."
                )),
                "limit": S(type=T.INTEGER, description=(
                    "Max records to return. Default 50. Capped at 100."
                )),
            }, required=["category"]),
        ),
    ])


# ============================================================
#  Protocol helpers
# ============================================================

def parse_protocol_message(text: str) -> dict | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if "\n" in cleaned:
            cleaned = cleaned.split("\n", 1)[1]
        if "```" in cleaned:
            cleaned = cleaned.rsplit("```", 1)[0]
    try:
        return ujson.loads(cleaned.strip())
    except ujson.JSONDecodeError:
        return None


def extract_text(response) -> str:
    if not response.candidates or not response.candidates[0].content:
        return ""
    return "".join(
        p.text or "" for p in (response.candidates[0].content.parts or [])
        if getattr(p, "text", None)
    ).strip()


def extract_function_calls(response) -> list:
    if not response.candidates or not response.candidates[0].content:
        return []
    out = []
    for part in response.candidates[0].content.parts or []:
        fc = getattr(part, "function_call", None)
        if fc and fc.name:
            out.append(fc)
    return out


def extract_usage(response) -> dict:
    u = getattr(response, "usage_metadata", None)
    if not u:
        return {}
    return {
        "prompt_tokens": getattr(u, "prompt_token_count", None),
        "output_tokens": getattr(u, "candidates_token_count", None),
        "total_tokens":  getattr(u, "total_token_count", None),
    }


# Names the model might list in getEvidence that no longer apply with function
# calling. Drop them silently — the system prompt patch tells it not to list
# them, but tolerate it for backward compat.
ALREADY_PROVIDED_VIA_TOOLS = {
    "apktool.xml", "jadx.xml", "apktool.tar", "jadx.tar",
}


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
    tool_calls: list = field(default_factory=list)  # {name, args}
    tool_call_count: int = 0
    verdict_turn_tokens: dict = field(default_factory=dict)
    error: str | None = None
    raw_response: str | None = None

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if v not in (None, [], {})}


# ============================================================
#  Retry-on-transient-error wrapper
# ============================================================

# These status codes are treated as transient and retried with backoff:
#   429 RESOURCE_EXHAUSTED — quota/rate limit; the API typically returns a
#       RetryInfo with a precise retry_delay we should honor.
#   503 UNAVAILABLE        — server-side deadline/availability blip.
#   500 INTERNAL           — server-side transient.
#   504 DEADLINE_EXCEEDED  — gateway timeout, retryable.
RETRYABLE_STATUS_CODES = {429, 500, 503, 504}


def _extract_status_code(err: BaseException) -> int | None:
    """Pull an HTTP status code out of an SDK exception.

    The genai SDK raises several different exception classes (APIError,
    ClientError, ServerError, ...) and the status code is exposed on different
    attributes across versions: `code`, `status_code`, `response.status_code`,
    or sometimes only inside a stringified payload. We check all of them.
    """
    # Direct attributes
    for attr in ("code", "status_code"):
        v = getattr(err, attr, None)
        if isinstance(v, int):
            return v
        # Sometimes 'code' is a string like "429"
        if isinstance(v, str) and v.isdigit():
            return int(v)

    # Nested response object
    response = getattr(err, "response", None)
    if response is not None:
        v = getattr(response, "status_code", None)
        if isinstance(v, int):
            return v

    # Last resort: parse the message. Errors like
    #   "ClientError: 429 RESOURCE_EXHAUSTED. {...}"
    # always start with the status code.
    msg = str(err)
    head = msg.split(" ", 1)[0]
    if head.isdigit():
        return int(head)
    # Or "code': 429" inside a dict-stringified payload
    import re
    m = re.search(r"['\"]code['\"]\s*:\s*(\d{3})", msg)
    if m:
        return int(m.group(1))
    return None


def _extract_retry_delay_seconds(err: BaseException) -> float | None:
    """If the API attached a RetryInfo with a retryDelay, return it in seconds.

    Tries the structured `details` attribute first; falls back to regex over
    the stringified error if the SDK didn't surface a parsed payload.
    """
    # Structured form
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

    # Regex fallback for "retryDelay': '34s'" or "retryDelay: 34s"
    import re
    m = re.search(r"retry[Dd]elay['\"]?\s*:?\s*['\"]?(\d+(?:\.\d+)?)\s*s", str(err))
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def with_transient_retry(
    fn,
    *,
    max_attempts: int = 6,
    base_backoff_seconds: float = 5.0,
    max_backoff_seconds: float = 120.0,
    on_wait=None,
):
    """Call fn(); retry on transient API errors with backoff. Returns fn's result.

    For 429s the wait honors the API's RetryInfo.retryDelay when available.
    For other transient codes we use exponential backoff capped at max_backoff_seconds.
    Non-transient errors (or errors without an extractable status) propagate
    immediately.

    This catches ANY exception, not just SDK-typed ones, because the SDK's
    exception class hierarchy varies across versions (APIError vs ClientError
    vs ServerError vs raw HTTPError) and we don't want a class-name mismatch
    to turn a retryable 429 into a fatal crash. We dispatch purely on status
    code; non-API exceptions won't have one and will be re-raised.
    """
    last_error: BaseException | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except Exception as e:
            status = _extract_status_code(e)
            if status is None or status not in RETRYABLE_STATUS_CODES:
                # Not a transient API error we know how to retry; let it propagate.
                raise

            last_error = e
            if attempt >= max_attempts:
                break

            api_delay = _extract_retry_delay_seconds(e) if status == 429 else None
            if api_delay is not None:
                wait = api_delay + 1.0  # small buffer past quota refresh
                reason = f"server says retry in {api_delay:.1f}s"
            else:
                wait = min(
                    base_backoff_seconds * (2 ** (attempt - 1)),
                    max_backoff_seconds,
                )
                reason = f"backoff (attempt {attempt}/{max_attempts})"

            if on_wait:
                on_wait(status, wait, reason, attempt, max_attempts)
            time.sleep(wait)

    assert last_error is not None
    raise last_error


# ============================================================
#  TPM rate limiter (sliding 60-second window)
# ============================================================

class TPMRateLimiter:
    """Sliding-window pacer for input-token-per-minute quotas.

    The Gemini API enforces an input-tokens-per-minute quota that counts
    EVERY request's prompt token count, summed over a rolling 60-second
    window. A multi-turn tool loop re-sends the full conversation history
    on each turn, so a verdict that takes 4 API round-trips at 150k tokens
    each consumes ~600k TPM in seconds — and an 8-turn verdict can blow
    past a 2M TPM cap before the script even notices.

    This limiter sits in front of every generate_content call. Before each
    request, it estimates the prompt size, evicts stale entries from its
    log, and sleeps just long enough to keep the projected window total
    under the configured limit.

    The limiter is in-process only; if you run multiple batches against
    the same API key in parallel, you'd need to coordinate across them.
    """

    # Headroom factor: aim for this fraction of the hard limit so we don't
    # repeatedly approach the ceiling and trigger 429s anyway. 0.9 = use up
    # to 90% of the quota before pacing.
    DEFAULT_HEADROOM = 0.9

    # If we have no historical data yet, assume the first request will use
    # this many tokens. Conservative — better to delay an early request than
    # blow the budget on a cold start.
    COLD_START_ESTIMATE = 100_000

    # Multiply the previous turn's prompt tokens by this factor to estimate
    # the next turn's. Captures growth from tool responses being appended.
    GROWTH_FACTOR = 1.05

    def __init__(self, tokens_per_minute: int, log_fn=None):
        from collections import deque
        self.limit = tokens_per_minute
        self.budget = int(tokens_per_minute * self.DEFAULT_HEADROOM)
        # Each entry: (timestamp_seconds, prompt_tokens_used)
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
        """Estimate prompt tokens for the next request based on the previous."""
        if self.last_prompt_tokens == 0:
            return self.COLD_START_ESTIMATE
        return int(self.last_prompt_tokens * self.GROWTH_FACTOR)

    def acquire(self) -> None:
        """Block until enough TPM budget is available for the next request.

        Sleeps the minimum amount needed for stale entries to age out of the
        60-second window. May sleep multiple times if eviction unblocks only
        partially.
        """
        estimate = self.estimate_next_request()
        if estimate > self.budget:
            # Single request exceeds even the full budget. There's nothing
            # we can do — let the request go through and let the API decide.
            self.log(
                f"  ⚠ Estimated request size ({estimate:,} tokens) exceeds "
                f"the entire TPM budget ({self.budget:,}). Proceeding anyway "
                f"— the API will likely reject with 429.",
                color="yellow",
            )
            return

        while True:
            now = time.monotonic()
            self._evict_stale(now)
            current = self._window_sum()
            projected = current + estimate
            if projected <= self.budget:
                return  # We have room

            # Need to wait for the oldest entry to age out. Compute how long
            # until evicting it brings us under budget.
            need_to_free = projected - self.budget
            freed = 0
            wait_until = None
            for ts, tokens in self.window:
                freed += tokens
                if freed >= need_to_free:
                    wait_until = ts + 60.0
                    break

            if wait_until is None:
                # Shouldn't happen given the budget check above, but defensive.
                return

            sleep_for = max(0.1, wait_until - now + 0.2)  # 200ms cushion
            self.log(
                f"  ⏸ TPM pacing: window at {current:,}/{self.budget:,}, "
                f"projected {projected:,} would exceed; sleeping {sleep_for:.1f}s",
                color="dim",
            )
            time.sleep(sleep_for)

    def record(self, prompt_tokens: int) -> None:
        """Log the actual prompt token count from a completed request."""
        if prompt_tokens <= 0:
            return
        self.window.append((time.monotonic(), prompt_tokens))
        self.last_prompt_tokens = prompt_tokens

    def status(self) -> str:
        """Format current window state for logging."""
        now = time.monotonic()
        self._evict_stale(now)
        current = self._window_sum()
        pct = (current / self.budget * 100) if self.budget else 0
        return (
            f"TPM window: {current:,}/{self.budget:,} ({pct:.0f}%) "
            f"across {len(self.window)} requests"
        )


# ============================================================
#  Main
# ============================================================

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--apk-root", required=True, type=Path, help=(
        "Root of the extracted APK directory (must contain jadx/sources/ and "
        "apktool/ subdirectories)."
    ))
    ap.add_argument("--system-prompt", required=True, type=Path)
    ap.add_argument("--schema",        required=True, type=Path)
    ap.add_argument("--evidence-dir",  required=True, type=Path)
    ap.add_argument("--prompts-dir",   required=True, type=Path)
    ap.add_argument("--output-dir",    required=True, type=Path)
    ap.add_argument("--model",         default="gemini-2.5-pro")
    ap.add_argument("--api-key",       default=None)
    ap.add_argument("--max-tool-iterations", type=int, default=50, help=(
        "Max rounds of tool calls per verdict before giving up. With per-row "
        "verification a single fail can spawn many read_file calls; 50 is generous."
    ))
    ap.add_argument("--tpm-limit", type=int, default=2_000_000, help=(
        "Input tokens-per-minute quota for your account/model. The runner "
        "will pace requests to stay under 90%% of this. Set to 0 to disable "
        "pacing (rely on retry only). Default: 2,000,000 (Gemini paid tier)."
    ))
    ap.add_argument("--max-retries", type=int, default=6, help=(
        "Max attempts per request when the API returns 429/500/503/504. "
        "The default of 6 with exponential backoff (5s, 10s, 20s, 40s, 80s, "
        "120s capped) handles ~5 minutes of transient unavailability."
    ))
    ap.add_argument("--retry-base-seconds", type=float, default=5.0, help=(
        "Initial backoff delay between retries when the server doesn't supply "
        "a RetryInfo (i.e. for 500/503/504, not 429)."
    ))
    ap.add_argument("--retry-max-seconds", type=float, default=120.0, help=(
        "Cap on individual retry delays. 429 responses with a longer "
        "RetryInfo.retryDelay are still honored in full — this only caps "
        "exponential backoff for non-quota transient errors."
    ))
    ap.add_argument("--abort-on-error", action="store_true")
    args = ap.parse_args()

    api_key = args.api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        sys.exit("Set GEMINI_API_KEY or pass --api-key.")

    # Discover prompts
    prompts = sorted(args.prompts_dir.glob("*.md"))
    if not prompts:
        sys.exit(f"No .md files in {args.prompts_dir}")

    log(f"Found {len(prompts)} test prompt(s):", color="cyan")
    for p in prompts:
        log(f"  · {p.name}", color="cyan")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Read system prompt and schema
    system_prompt = args.system_prompt.read_text()
    schema_text   = args.schema.read_text()

    # Build the navigator (this builds the index — one-time cost per APK)
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

    # Tool declarations
    tools = [build_tool_declarations()]

    # Conversation state
    client = genai.Client(api_key=api_key)
    history: list[types.Content] = []
    sent_evidence_files: set[str] = set()
    summary: list[TestStats] = []

    # TPM rate limiter (in-process; assumes one batch at a time per API key).
    rate_limiter: TPMRateLimiter | None = None
    if args.tpm_limit > 0:
        rate_limiter = TPMRateLimiter(args.tpm_limit, log_fn=log)
        log(
            f"  TPM pacing enabled: {args.tpm_limit:,} tokens/min "
            f"(targeting {int(args.tpm_limit * 0.9):,})",
            color="cyan",
        )

    # ----- send() -----
    def send(parts: list[types.Part], label: str) -> tuple[str, list, dict]:
        """Send one user turn; return (text, function_calls, usage)."""
        log(f"\n>>> USER  ({label})", color="yellow")
        for p in parts:
            if getattr(p, "text", None):
                preview = p.text[:160].replace("\n", " ")
                log(f"    text: {preview}{'...' if len(p.text) > 160 else ''}",
                    color="dim")
            elif getattr(p, "function_response", None):
                fr = p.function_response
                resp_preview =ujson.dumps(fr.response)[:120].replace("\n", " ")
                log(f"    fn-response: {fr.name}({resp_preview}...)", color="dim")

        history.append(types.Content(role="user", parts=parts))

        # Pace ourselves before issuing the request, to stay under the
        # configured TPM ceiling and avoid 429s in the steady state.
        if rate_limiter is not None:
            rate_limiter.acquire()

        def _on_wait(status, wait, reason, attempt, max_attempts):
            log(
                f"  ⏳ HTTP {status} — pausing {wait:.1f}s ({reason}); "
                f"will retry [{attempt}/{max_attempts}]",
                color="yellow",
            )

        def _do_call():
            return client.models.generate_content(
                model=args.model,
                contents=history,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    tools=tools,
                ),
            )

        resp = with_transient_retry(
            _do_call,
            max_attempts=args.max_retries,
            base_backoff_seconds=args.retry_base_seconds,
            max_backoff_seconds=args.retry_max_seconds,
            on_wait=_on_wait,
        )
        if resp.candidates and resp.candidates[0].content:
            history.append(resp.candidates[0].content)

        text = extract_text(resp)
        calls = extract_function_calls(resp)
        usage = extract_usage(resp)

        # Record the actual prompt-token usage so the next acquire() call has
        # accurate window data. The retry path may have made earlier failed
        # attempts that we couldn't measure; those were rejected without
        # consuming quota, so we only record the successful response.
        if rate_limiter is not None and usage.get("prompt_tokens"):
            rate_limiter.record(usage["prompt_tokens"])

        if calls:
            log(f"<<< MODEL  [{len(calls)} tool call(s)]", color="green")
            for c in calls:
                args_preview =ujson.dumps(dict(c.args or {}))[:200]
                log(f"  → {c.name}({args_preview})", color="cyan")
        if text:
            log("<<< MODEL  [text]", color="green")
            log(text)
        if not calls and not text:
            log("<<< MODEL  [empty response]", color="red")

        if usage:
            log(
                f"    [tokens: prompt={usage.get('prompt_tokens')} "
                f"output={usage.get('output_tokens')} "
                f"total={usage.get('total_tokens')}]",
                color="dim",
            )
        return text, calls, usage

    # ----- resolve_tools() -----
    def resolve_tools(initial_text: str, initial_calls: list, initial_usage: dict,
                      stats: TestStats) -> tuple[str, dict]:
        """
        Loop: while the model emits tool calls, execute them and feed results back.
        Returns the final text + the usage from the final turn.
        """
        text, calls, usage = initial_text, initial_calls, initial_usage

        for iteration in range(args.max_tool_iterations):
            if not calls:
                return text, usage

            # Execute tool calls (parallel within a turn)
            tool_response_parts: list[types.Part] = []
            for call in calls:
                stats.tool_call_count += 1
                stats.tool_calls.append({
                    "name": call.name,
                    "args": dict(call.args or {}),
                })
                try:
                    result = navigator.call(call.name, dict(call.args or {}))
                    payload = {"result": result}
                except Exception as e:
                    err = f"{type(e).__name__}: {e}"
                    log(f"    ⚠ tool error in {call.name}: {err}", color="yellow")
                    payload = {"error": err}
                tool_response_parts.append(
                    types.Part.from_function_response(
                        name=call.name, response=payload,
                    )
                )

            # Feed responses back
            text, calls, usage = send(
                tool_response_parts,
                f"tool responses (iter {iteration + 1}, {len(tool_response_parts)} result(s))",
            )

        raise RuntimeError(
            f"Exceeded {args.max_tool_iterations} tool iterations without a final response. "
            "Increase --max-tool-iterations or check the system prompt for runaway tool use."
        )

    # ----- try_reset_prompt() -----
    def try_reset_prompt() -> bool:
        text, calls, _ = send(
            [types.Part.from_text(text=ujson.dumps({"operation": "reset", "args": "prompt"}))],
            "reset prompt",
        )
        if calls:
            log("  ⚠ Reset triggered tool calls; treating ack-text as authoritative.",
                color="yellow")
        msg = parse_protocol_message(text)
        ok = bool(msg and msg.get("response_code") == "ok")
        if not ok:
            log(f"  ⚠ Reset failed. Model said: {text}", color="yellow")
        return ok

    try:
        # ---------------- Phase 1: bootstrap ----------------
        banner("Phase 1  ·  Bootstrap (expect getSchema)")
        text, _, _ = send([types.Part.from_text(text="Begin.")], "kickoff")
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
            "list_imports, list_dir, grep) to fetch the specific bytes you need. "
            "The tools operate against the extracted APK directory and return "
            "exactly the lines you ask for."
        )
        text, _, _ = send(
            [
                types.Part.from_text(text=intro),
                types.Part.from_text(text=f"\n=== schema.md ===\n{schema_text}"),
            ],
            "schema",
        )
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
                # ----- Send per-test prompt -----
                # The model's response can take three legitimate shapes:
                #   1. A getEvidence JSON message (it wants L1 evidence inline)
                #   2. Tool calls (no evidence to request — everything it needs
                #      is either already in context or reachable via tools)
                #   3. Both text and tool calls (rare; we still resolve tools)
                # Only a fourth shape — text that is neither getEvidence nor a
                # final verdict — is a protocol error.
                test_prompt = prompt_path.read_text()
                text, calls, usage = send(
                    [types.Part.from_text(text=test_prompt)],
                    f"prompt: {prompt_path.name}",
                )

                msg = parse_protocol_message(text) if text else None
                is_get_evidence = bool(msg and msg.get("operation") == "getEvidence")
                is_verdict_directly = bool(msg and "verdict" in msg)

                if is_verdict_directly:
                    # The model emitted a verdict on the first turn (no evidence
                    # needed, no tools needed). Skip the evidence step entirely.
                    log("  · No evidence requested and no tools needed — "
                        "model went straight to verdict.", color="dim")
                    final_text, final_usage = text, usage

                elif is_get_evidence:
                    # Standard path: deliver requested L1 evidence, then resolve
                    # any tool calls the model makes during reasoning.
                    requested = list(msg.get("args") or [])

                    # ----- Build L1 evidence payload -----
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
                        # strings.json gets slimmed for inline delivery: each
                        # record reduces to id/category/value/path. The full
                        # records remain retrievable via the get_string_record
                        # and list_string_records_by_category tools.
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

                    evidence_parts = [types.Part.from_text(text="Evidence:")] + [
                        types.Part.from_text(text="\n" + chunk) for chunk in payload_chunks
                    ]
                    if test_stats.evidence_missing:
                        evidence_parts.append(types.Part.from_text(text=(
                            f"\n[Note: {len(test_stats.evidence_missing)} requested "
                            f"evidence file(s) could not be delivered (see entries marked "
                            f"'not found' above). Proceed with the available evidence and "
                            f"reflect the gap in your verdict.]"
                        )))

                    # ----- Send evidence; resolve any tool calls; expect verdict -----
                    text, calls, usage = send(
                        evidence_parts,
                        f"evidence ({len(test_stats.evidence_delivered)} new)",
                    )
                    sent_evidence_files.update(test_stats.evidence_delivered)
                    final_text, final_usage = resolve_tools(
                        text, calls, usage, test_stats,
                    )

                elif calls:
                    # The model skipped getEvidence and jumped directly to tool
                    # calls. This is legitimate when nothing it needs is in the
                    # L1 evidence files (e.g. a follow-up test in the same
                    # session where every relevant evidence record is already
                    # in context, or a test whose verification only needs
                    # source-code reads).
                    log("  · No getEvidence message — model is using tools "
                        "directly. Resolving tool calls...", color="dim")
                    final_text, final_usage = resolve_tools(
                        text, calls, usage, test_stats,
                    )

                else:
                    # Neither getEvidence, nor tool calls, nor a verdict —
                    # genuine protocol error.
                    log(f"❌ Unexpected response shape. text={text!r} "
                        f"calls={len(calls)}", color="red")
                    test_stats.status = "protocol_error"
                    test_stats.error = (
                        "First response after per-test prompt was neither "
                        "getEvidence, a verdict, nor tool calls"
                    )
                    test_stats.raw_response = text
                    summary.append(test_stats)
                    test_stats.finished_at = datetime.now(timezone.utc).isoformat()
                    if i < len(prompts):
                        if not try_reset_prompt():
                            log("Reset failed; aborting batch.", color="red")
                            break
                    continue

                # ----- Parse verdict -----
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

            # ----- Reset for next test -----
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

        # Persist summary
        summary_path = args.output_dir / "_summary.json"
        summary_path.write_text(ujson.dumps({
            "run_at": datetime.now(timezone.utc).isoformat(),
            "model": args.model,
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
        # Save what we have so far
        summary_path = args.output_dir / "_summary.json"
        summary_path.write_text(ujson.dumps({
            "run_at": datetime.now(timezone.utc).isoformat(),
            "model": args.model,
            "apk_root": str(args.apk_root),
            "fatal_error": f"{type(e).__name__}: {e}",
            "tests": [r.to_dict() for r in summary],
        }, indent=2))
        log(f"  Partial summary written to {summary_path}", color="yellow")
        return 1


if __name__ == "__main__":
    sys.exit(main())