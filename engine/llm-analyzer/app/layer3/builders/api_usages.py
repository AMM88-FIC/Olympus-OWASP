import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.snippet import get_snippet_context
from ..helpers.taint import detect_taint_sources
from ..models import (
    ApiParameter, ApiUsageRecord, ApiUsagesFile,
    GeneratedBy, SnippetContext, Source,
)
from ._patterns import (
    API_USAGE_PATTERNS, extract_class_name, current_method, iter_java_files,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "api_usage_matcher_v1"
TOOL = "androguard-4.1.3+jadx-1.5.5"

# One record per (domain, file) pair to avoid flooding with duplicates
# from the same class. For domains where every call matters (e.g. logging)
# we record all hits within a file.
_RECORD_ALL_DOMAINS = frozenset({"logging", "root_detection", "debug_detection"})


def build(job_id: str, jadx_result) -> ApiUsagesFile:
    """
    Scan JADX Java source for general security-relevant API calls.

    Covers: logging, IPC, auth, clipboard, screenshots, biometric,
    dynamic loading, reflection, root detection, debug detection,
    notification, and file_io.

    Crypto, WebView, network, and storage each have dedicated builders.

    Args:
        job_id:       Analysis job identifier.
        jadx_result:  JadxResult from the extraction coordinator.

    Returns:
        Populated ApiUsagesFile.
    """
    if not jadx_result.success or not jadx_result.source_dir:
        logger.warning("JADX output unavailable for job %s — skipping api_usages scan", job_id)
        return _empty(job_id)

    source_dir = jadx_result.source_dir
    records: list[ApiUsageRecord] = []

    for java_file in iter_java_files(source_dir):
        try:
            _scan_file(job_id, java_file, source_dir, records)
        except Exception as exc:
            logger.debug("Error scanning %s: %s", java_file, exc)

    return ApiUsagesFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_file(
    job_id: str,
    java_file: Path,
    source_dir: Path,
    records: list[ApiUsageRecord],
) -> None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    class_name = extract_class_name(java_file, source_dir)

    for domain, patterns in API_USAGE_PATTERNS.items():
        record_all = domain in _RECORD_ALL_DOMAINS
        domain_hits = 0

        for pattern in patterns:
            for line_idx, line in enumerate(lines):
                if not pattern.search(line):
                    continue

                if not record_all and domain_hits >= 1:
                    break   # one record per non-logging domain per file

                line_no = line_idx + 1
                method = current_method(lines, line_idx)
                ctx = get_snippet_context(java_file, line_no, line_no)
                all_ctx = ctx["before"] + ctx["after"]
                taint = detect_taint_sources(all_ctx, [None])

                records.append(ApiUsageRecord(
                    id=next_id(job_id, "api"),
                    domain=domain,
                    api_call=_api_call_from_line(line, domain),
                    caller_class=class_name,
                    caller_method=method,
                    caller_descriptor=None,
                    parameters=_extract_params(line),
                    snippet=line.strip(),
                    snippet_context=SnippetContext(**ctx),
                    taint_sources=taint,
                    reachable_from=[],
                    extraction_track="readable",
                    confidence=0.87,
                    related_ids=[],
                    source=Source(
                        artifact="java",
                        path=str(java_file.relative_to(source_dir.parent)),
                        line_start=line_no,
                        line_end=line_no,
                        extractor=EXTRACTOR,
                        tool="jadx-1.5.5",
                    ),
                ))
                domain_hits += 1

                if not record_all:
                    break

            if not record_all and domain_hits >= 1:
                break


def _api_call_from_line(line: str, domain: str) -> str:
    """Extract a best-effort API call name from a matched line."""
    # Try to pull out a Class.method pattern
    m = re.search(r'([\w.]+)\s*\(', line.strip())
    if m:
        return m.group(1)
    return domain


def _extract_params(line: str) -> list[ApiParameter]:
    """
    Extract literal string arguments from a call site.
    Only captures the first string literal argument — enough for tag/message
    patterns in logging calls.
    """
    m = re.search(r'\(\s*"(?P<p0>[^"]*)"', line)
    if m:
        return [ApiParameter(
            position=0,
            type="String",
            literal_value=m.group("p0"),
            source_expression=None,
        )]
    return []


def _empty(job_id: str) -> ApiUsagesFile:
    return ApiUsagesFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )