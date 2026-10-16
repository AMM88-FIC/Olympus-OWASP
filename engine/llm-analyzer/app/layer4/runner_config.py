"""
runner_config.py — Config plumbing for the verdict-engine runners.

This module owns everything between "the user typed a command" and "the engine
has a Backend and a RunConfig": INI loading, the CLI argument surface, the
merge rules between the two, and backend instantiation.

It is deliberately import-safe: no side effects, no argument parsing at import
time, and nothing here talks to a model. Both runners import it normally.

    run_verdict_engine.py   sequential CLI (main() lives there)
    run_parallel.py         threaded CLI (its own main(), reuses these five)

History: these functions previously lived in a root-level script named
`run_verdict_engine-parallel-tools-optimized.py`. Because that filename
contains hyphens it is not a valid Python module name, so `run_parallel.py`
had to load it through an `importlib.util.spec_from_file_location` shim at
import time. Moving them here removes the shim, gives the config rules one
importable home, and makes them unit-testable without spawning a run.

Merge precedence, in order:

    CLI flag  >  config file value  >  built-in default

Path resolution differs by source, and the difference is deliberate:

    config paths  → resolved relative to the CONFIG FILE's directory
    CLI paths     → resolved relative to the CURRENT WORKING DIRECTORY

so a config file stays portable regardless of where you invoke it from, while
a path you type on the command line means what it looks like it means.
"""

from __future__ import annotations

import argparse
import configparser
import sys
from pathlib import Path

from app.layer4.verdict_engine import log


# ============================================================
#  Config loading
# ============================================================

def load_config_file(path: Path) -> configparser.ConfigParser:
    if not path.is_file():
        sys.exit(f"Config file not found: {path}")
    cp = configparser.ConfigParser()
    cp.read(path)
    return cp


def cfg_get(
    cp: configparser.ConfigParser | None,
    section: str,
    key: str,
    default=None,
    *,
    cast=str,
):
    """Read a value from the config; return default if absent. Cast applies
    a type conversion (str/int/float/bool)."""
    if cp is None or not cp.has_option(section, key):
        return default
    raw = cp.get(section, key)
    if cast is bool:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if cast is int:
        return int(raw)
    if cast is float:
        return float(raw)
    return raw


def resolve_path(value: str | None, *, relative_to: Path) -> Path | None:
    """Resolve a path string. Absolute paths are kept as-is; relative paths
    are resolved against `relative_to` (typically the config file's dir)."""
    if value is None:
        return None
    p = Path(value)
    if p.is_absolute():
        return p
    return (relative_to / p).resolve()


# ============================================================
#  CLI argument parsing
# ============================================================

def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Unified verdict-engine runner. Supports OpenAI-compatible "
                    "and Gemini backends. Settings can be supplied via "
                    "--config (INI file) and/or individual CLI flags. "
                    "CLI flags override config values.",
    )
    ap.add_argument("--config", type=Path, default=None, help=(
        "Path to an INI config file. CLI flags override values from this file."
    ))

    # Backend selection
    ap.add_argument("--backend", choices=["openai", "gemini"], default=None,
                    help="Which backend to use. Overrides [backend].type.")

    # Common
    ap.add_argument("--model", default=None,
                    help="Model identifier. Overrides [backend].model "
                         "or [openai|gemini].model.")
    ap.add_argument("--api-key", default=None,
                    help="API key. Otherwise read from the env var named in "
                         "config (api_key_env).")

    # Paths
    ap.add_argument("--apk-root", type=Path, default=None)
    ap.add_argument("--system-prompt", type=Path, default=None)
    ap.add_argument("--schema", type=Path, default=None)
    ap.add_argument("--evidence-dir", type=Path, default=None)
    ap.add_argument("--test-plan-dir", type=Path, default=None)
    ap.add_argument("--output-dir", type=Path, default=None)

    ap.add_argument("--test-filter", type=str, default=None)

    # OpenAI-specific
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--temperature", type=float, default=None)
    ap.add_argument("--reasoning-effort",
                    choices=["low", "medium", "high"], default=None)
    ap.add_argument("--json-mode",
                    choices=["off", "object", "schema"], default=None)
    ap.add_argument("--request-timeout", type=float, default=None)
    ap.add_argument("--num-ctx", type=int, default=None)

    # Gemini-specific
    ap.add_argument("--tpm-limit", type=int, default=None)

    # Retry
    ap.add_argument("--max-tool-iterations", type=int, default=None)
    ap.add_argument("--max-test-retries", type=int, default=None)
    ap.add_argument("--retry-delay-seconds", type=float, default=None)
    ap.add_argument("--max-request-retries", type=int, default=None)
    ap.add_argument("--request-retry-base-seconds", type=float, default=None)
    ap.add_argument("--request-retry-max-seconds", type=float, default=None)

    # RAG
    ap.add_argument("--rag", action="store_true", default=None,
                    help="Enable semantic code search via search_code.")
    ap.add_argument("--rag-index-smali", action="store_true", default=None)
    ap.add_argument("--rag-embed-model", default=None)

    # Evidence delivery
    ap.add_argument("--inline-evidence-max-bytes", type=int, default=None,
                    help="Files at or below this size (in bytes on disk) "
                         "are delivered inline as full content in response "
                         "to getEvidence. Larger files are NOT inlined; the "
                         "model uses the navigator's evidence tools "
                         "(get_evidence_record, match_evidence_records, "
                         "count_evidence_records) to access their records. "
                         "Default: 10240 (10KB).")

    # Behavior
    ap.add_argument("--abort-on-error", action="store_true", default=None)

    return ap


# ============================================================
#  Settings resolution: merge config + CLI
# ============================================================

def resolve_settings(args: argparse.Namespace) -> dict:
    """Return a dict of effective settings: CLI flag if provided, else config
    value, else default. Required values are validated at the end."""
    cp = load_config_file(args.config) if args.config else None
    config_dir = args.config.parent.resolve() if args.config else Path.cwd()

    def first_set(*values, default=None):
        """Return the first non-None value, else default."""
        for v in values:
            if v is not None:
                return v
        return default

    backend_type = first_set(
        args.backend, cfg_get(cp, "backend", "type"),
    )
    if not backend_type:
        sys.exit("Backend not specified. Set --backend or [backend].type "
                 "in the config.")

    settings = {"backend_type": backend_type}

    # Backend-section lookups: prefer [backend].model, then [openai|gemini].model
    settings["model"] = first_set(
        args.model,
        cfg_get(cp, "backend", "model"),
        cfg_get(cp, backend_type, "model"),
    )
    if not settings["model"]:
        sys.exit("Model not specified. Set --model or "
                 "[backend].model / [<backend>].model.")

    # API key: CLI > the [<backend>].api_key_env value.
    #
    # NOTE - preserved verbatim from the original runner, quirk included:
    # despite its name, `api_key_env` is used as the key ITSELF, not as the
    # name of an environment variable to read. The config comments and the
    # README both describe the env-var behaviour instead. Harmless for a
    # local Ollama server (no auth), but it means a cloud key has to be
    # written into the INI to work. Changing it here would break any config
    # that currently relies on the literal reading, so it is left alone and
    # tracked as TODO F6 rather than silently altered.
    api_key_env = cfg_get(cp, backend_type, "api_key_env")
    settings["api_key"] = (
        args.api_key
        or api_key_env
    )

    # Paths - CLI relative to CWD; config relative to config file's dir
    def path_setting(arg_value: Path | None, section: str, key: str,
                     *, required: bool) -> Path | None:
        if arg_value is not None:
            return arg_value.resolve()
        cfg_value = cfg_get(cp, section, key)
        if cfg_value:
            return resolve_path(cfg_value, relative_to=config_dir)
        if required:
            sys.exit(
                f"Path required: {key}. Set --{key.replace('_', '-')} or "
                f"[{section}].{key}."
            )
        return None

    settings["apk_root"] = path_setting(args.apk_root, "paths", "apk_root",
                                        required=True)
    settings["system_prompt"] = path_setting(args.system_prompt, "paths",
                                              "system_prompt", required=True)
    settings["schema"] = path_setting(args.schema, "paths", "schema",
                                      required=True)
    settings["evidence_dir"] = path_setting(args.evidence_dir, "paths",
                                             "evidence_dir", required=True)
    settings["test_plan_dir"] = path_setting(args.test_plan_dir, "paths",
                                            "test_plan_dir", required=True)
    settings["output_dir"] = path_setting(args.output_dir, "paths",
                                           "output_dir", required=True)

    # NOTE: reads the LEGACY [paths].prompts_mask key only. The current
    # [paths].test_filter key is picked up by run_parallel.py after this
    # returns (see its main(), "Effective test filter"). Preserved as-is so
    # the two runners keep identical precedence; unifying it is TODO F7.
    settings["test_filter"] = first_set(
        args.test_filter, cfg_get(cp, "paths", "prompts_mask"),
        default=""
    )

    # OpenAI-specific
    settings["base_url"] = first_set(
        args.base_url, cfg_get(cp, "openai", "base_url"),
    )
    settings["temperature"] = first_set(
        args.temperature, cfg_get(cp, "openai", "temperature", cast=float),
        default=0.2,
    )
    settings["reasoning_effort"] = first_set(
        args.reasoning_effort, cfg_get(cp, "openai", "reasoning_effort"),
        default="medium",
    )
    settings["json_mode"] = first_set(
        args.json_mode, cfg_get(cp, "openai", "json_mode"),
        default="off",
    )
    settings["request_timeout"] = first_set(
        args.request_timeout,
        cfg_get(cp, "openai", "request_timeout", cast=float),
        default=600.0,
    )

    settings["num_ctx"] = first_set(
        args.num_ctx,
        cfg_get(cp, "openai", "num_ctx", cast=int),
        default=100000.0,
    )

    # Gemini-specific
    settings["tpm_limit"] = first_set(
        args.tpm_limit, cfg_get(cp, "gemini", "tpm_limit", cast=int),
        default=2_000_000,
    )

    # Retry
    settings["max_tool_iterations"] = first_set(
        args.max_tool_iterations,
        cfg_get(cp, "tools", "max_tool_iterations", cast=int),
        default=50,
    )
    settings["max_test_retries"] = first_set(
        args.max_test_retries,
        cfg_get(cp, "retry", "max_test_retries", cast=int),
        default=2,
    )
    settings["retry_delay_seconds"] = first_set(
        args.retry_delay_seconds,
        cfg_get(cp, "retry", "retry_delay_seconds", cast=float),
        default=10.0,
    )
    settings["max_request_retries"] = first_set(
        args.max_request_retries,
        cfg_get(cp, "retry", "max_request_retries", cast=int),
        default=6,
    )
    settings["request_retry_base_seconds"] = first_set(
        args.request_retry_base_seconds,
        cfg_get(cp, "retry", "request_retry_base_seconds", cast=float),
        default=5.0,
    )
    settings["request_retry_max_seconds"] = first_set(
        args.request_retry_max_seconds,
        cfg_get(cp, "retry", "request_retry_max_seconds", cast=float),
        default=120.0,
    )

    # RAG
    settings["rag_enabled"] = first_set(
        args.rag, cfg_get(cp, "rag", "enabled", cast=bool),
        default=False,
    )
    settings["rag_index_smali"] = first_set(
        args.rag_index_smali, cfg_get(cp, "rag", "index_smali", cast=bool),
        default=False,
    )
    settings["rag_embed_model"] = first_set(
        args.rag_embed_model, cfg_get(cp, "rag", "embed_model"),
        default="BAAI/bge-small-en-v1.5",
    )

    # Behavior
    settings["abort_on_error"] = first_set(
        args.abort_on_error, cfg_get(cp, "behavior", "abort_on_error",
                                      cast=bool),
        default=False,
    )

    # Evidence delivery. Tiny files (at or below inline_evidence_max_bytes)
    # are delivered inline as full content in response to getEvidence. Larger
    # files are not inlined - the model accesses their records via the
    # navigator's evidence tools (get_evidence_record, match_evidence_records,
    # count_evidence_records). The L1 schema delivered at bootstrap tells
    # the model what fields each evidence file's records contain, so
    # tool-driven access is sufficient without paying for full-file delivery.
    settings["inline_evidence_max_bytes"] = first_set(
        args.inline_evidence_max_bytes,
        cfg_get(cp, "evidence", "inline_max_bytes", cast=int),
        default=10_240,
    )

    # Backend-specific validation
    if backend_type == "openai" and not settings["base_url"]:
        sys.exit("OpenAI backend requires --base-url or [openai].base_url.")

    return settings


# ============================================================
#  Backend instantiation
# ============================================================

def make_backend(settings: dict, system_prompt: str, *, rate_limiter=None):
    """Build a backend from resolved settings.

    `rate_limiter` is a `SharedRateLimiter` shared by every backend in one run.
    Only the Gemini backend takes one; passing it is how an embedded host gets
    the same TPM/RPM pacing `run_parallel` has, without reimplementing the
    reservation logic. None means unpaced, which is correct for a single
    sequential caller.
    """
    bt = settings["backend_type"]
    if bt == "openai":
        from app.layer4.backends.openai_backend import OpenAIBackend
        return OpenAIBackend(
            base_url=settings["base_url"],
            api_key=settings["api_key"],
            model=settings["model"],
            system_prompt=system_prompt,
            temperature=settings["temperature"],
            reasoning_effort=settings["reasoning_effort"],
            json_mode=settings["json_mode"],
            request_timeout=settings["request_timeout"],
            max_request_retries=settings["max_request_retries"],
            request_retry_base_seconds=settings["request_retry_base_seconds"],
            request_retry_max_seconds=settings["request_retry_max_seconds"],
            num_ctx=settings["num_ctx"],
            max_tokens=settings["num_ctx"],
            log_fn=log,
        )
    if bt == "gemini":
        from app.layer4.backends.gemini_backend import GeminiBackend
        return GeminiBackend(
            api_key=settings["api_key"],
            model=settings["model"],
            system_prompt=system_prompt,
            tpm_limit=settings["tpm_limit"],
            rate_limiter=rate_limiter,
            max_request_retries=settings["max_request_retries"],
            request_retry_base_seconds=settings["request_retry_base_seconds"],
            request_retry_max_seconds=settings["request_retry_max_seconds"],
            log_fn=log,
        )
    sys.exit(f"Unknown backend type: {bt}")
