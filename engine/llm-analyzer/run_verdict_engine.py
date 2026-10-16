"""
run_verdict_engine.py — Sequential CLI for the verdict engine.

Runs every test case in the plan one at a time through a single stateful
backend session. For concurrent execution across worker threads (plus Gemini
explicit caching and account-level rate limiting), use ``run_parallel.py``
instead — or set ``[parallel].max_workers = 1`` there for sequential behaviour
with the parallel runner's richer phase reporting.

Supports both the OpenAI/Ollama and Gemini backends, selected by
``[backend].type`` in the config or ``--backend`` on the command line. CLI
flags override config file values where both are present.

Usage:
    # Read everything from config.ini:
    python run_verdict_engine.py --config config.ini

    # Override individual settings on the command line:
    python run_verdict_engine.py --config config.ini --model gpt-oss:120b

    # Skip config entirely and pass everything as flags:
    python run_verdict_engine.py \\
        --backend openai \\
        --base-url http://localhost:11434/v1 \\
        --model qwen2.5:32b-instruct \\
        --apk-root storage/artifacts/diva \\
        ...

A sample config.ini is provided in the project root.

The config surface (INI loading, the CLI flags, the merge rules, and backend
construction) lives in ``app/layer4/runner_config.py`` and is shared with
``run_parallel.py``, so both runners agree on precedence and defaults. This
file owns only the sequential run itself.
"""

from __future__ import annotations

import sys

from app.layer4.apk_navigator import APKNavigator
from app.layer4.runner_config import (
    build_argparser, make_backend, resolve_settings,
)
from app.layer4.verdict_engine import RunConfig, banner, log, run_batch


def main() -> int:
    args = build_argparser().parse_args()
    settings = resolve_settings(args)

    system_prompt = settings["system_prompt"].read_text()

    # Optional RAG
    rag = None
    if settings["rag_enabled"]:
        from app.layer4.apk_rag import APKCodeRAG
        rag = APKCodeRAG(
            settings["apk_root"],
            index_smali=settings["rag_index_smali"],
            embed_model=settings["rag_embed_model"],
            log_fn=log,
        )

    # Index APK
    banner("Phase 0  ·  Indexing APK")
    log(f"  Backend: {settings['backend_type']} / {settings['model']}",
        color="cyan")
    log(f"  APK root: {settings['apk_root']}", color="cyan")
    log(f"  Num CTX:  {settings['num_ctx']}", color="cyan")

    navigator = APKNavigator(
        settings["apk_root"],
        evidence_dir=settings["evidence_dir"],
        rag=rag,
        log_fn=log,
    )
    stats = navigator.index.stats()
    log(
        f"  Index: {stats['classes']} classes "
        f"({stats['java_classes']} java, {stats['smali_classes']} smali only), "
        f"{stats['indexed_files_with_imports']} files with imports",
        color="green",
    )
    # Survey evidence files without forcing a load — list_files only stats
    # the directory; per-file parsing happens lazily on first tool call.
    evidence_files = navigator.evidence_index.list_files()
    if evidence_files:
        log(
            f"  Evidence: {len(evidence_files)} files in "
            f"{settings['evidence_dir']} "
            f"(loaded lazily on first evidence-tool call)",
            color="green",
        )
    if rag is not None:
        if rag.is_indexed():
            rs = rag.stats()
            log(f"  RAG: existing index — {rs['chunks']:,} chunks at "
                f"{rs['index_dir']}", color="green")
        else:
            log("  RAG: no existing index, building...", color="cyan")
            rag.build()

    backend = make_backend(settings, system_prompt)

    log(
        f"  Inline evidence threshold: "
        f"{settings['inline_evidence_max_bytes']:,} bytes "
        f"(larger files reachable via evidence tools)",
        color="cyan",
    )

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

    return run_batch(backend, navigator, config)


if __name__ == "__main__":
    sys.exit(main())
