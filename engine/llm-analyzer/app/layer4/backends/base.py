"""
backends/base.py — Abstract Backend interface for the verdict engine.

A Backend represents a chat-completion-style LLM endpoint (Gemini, OpenAI,
local Ollama, etc.). The verdict engine speaks to backends through this
interface and never touches an SDK directly.

Each backend is responsible for:
  - Maintaining its own conversation history representation (Gemini Parts vs
    OpenAI messages — we don't try to unify these).
  - Translating the engine's "neutral" send requests into native API calls.
  - Translating the API's responses back into a neutral form: text, tool
    calls, and usage metadata.
  - Exposing the navigator's tools in whatever format the API expects.

The engine controls the conversation; the backend executes the conversation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# ============================================================
#  Neutral types passed between engine and backend
# ============================================================

@dataclass
class ToolCall:
    """A function/tool call emitted by the model.

    Fields are normalised across backends:
      - id: unique identifier (used by OpenAI for matching tool responses;
        Gemini doesn't use it but we generate one anyway for consistency).
      - name: the tool's function name.
      - args: parsed kwargs as a dict. Backends do the JSON-string-to-dict
        conversion before returning.
    """
    id: str
    name: str
    args: dict


@dataclass
class Usage:
    """Token usage from one model turn. All fields optional because not every
    backend reports them the same way."""
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    cached_tokens: int | None = None


@dataclass
class TurnResult:
    """The result of one turn (one round-trip with the model).

    text:       The assistant's text content. Empty string if the turn was
                purely tool-calls.
    tool_calls: List of ToolCall objects, one per tool the model invoked
                this turn. Empty if the turn was purely text.
    usage:      Token usage stats for the turn.
    """
    text: str
    tool_calls: list[ToolCall]
    usage: Usage


@dataclass
class ToolResponse:
    """A tool execution result fed back to the model.

    Fields:
      - tool_call_id: matches the ToolCall.id from the model's prior turn.
      - name: the tool name (some backends require it; some don't).
      - content: JSON-serialisable result OR an error dict like
                 {"error": "FileNotFoundError: ..."}.
    """
    tool_call_id: str
    name: str
    content: dict | list | str


# ============================================================
#  The Backend interface
# ============================================================

class Backend(ABC):
    """Abstract Backend interface. Implementations encapsulate everything
    SDK-specific."""

    # ----- Identification (for logging/summary) -----

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this backend, e.g. 'openai', 'gemini'."""

    @property
    @abstractmethod
    def model(self) -> str:
        """The model name being used."""

    @property
    def description(self) -> str:
        """Human-readable description for log banners. Default uses name+model."""
        return f"{self.name} / {self.model}"

    # ----- Conversation control -----

    @abstractmethod
    def reset_history(self) -> None:
        """Clear all conversation history except the system prompt."""

    @abstractmethod
    def history_length(self) -> int:
        """Return the number of messages currently in history. Used by the
        engine for snapshot purposes (the engine snapshots before each test
        and restores on retry)."""

    @abstractmethod
    def snapshot_history(self) -> object:
        """Return an opaque snapshot of the current conversation state. The
        engine doesn't introspect this; it just hands it back to
        restore_history() on retry."""

    @abstractmethod
    def restore_history(self, snapshot: object) -> None:
        """Restore the conversation state from a snapshot returned by
        snapshot_history()."""

    # ----- The main turn-execution call -----

    @abstractmethod
    def send_user_message(
        self,
        content: str,
        *,
        label: str = "",
    ) -> TurnResult:
        """Append a single user-role text message and trigger a model turn.
        Returns the model's response."""

    @abstractmethod
    def send_tool_responses(
        self, responses: list[ToolResponse], *, label: str = "",
    ) -> TurnResult:
        """Append tool-result messages (matching prior tool_calls in history)
        and trigger a model turn."""

    # ----- Tool handling -----

    @abstractmethod
    def configure_tools(self, navigator) -> None:
        """Register the navigator's tool surface with this backend. Called
        once at engine startup. Backends translate APKNavigator.TOOL_NAMES
        into whatever native format the API expects."""

    # ----- Optional: rate limiting -----

    def acquire_rate_budget(self) -> None:
        """Called before every send. Backends with rate limiters override
        this to pace requests; default is a no-op."""
        pass

    def record_usage(self, usage: Usage) -> None:
        """Called after every successful send. Backends with rate limiters
        record actuals here; default is a no-op."""
        pass