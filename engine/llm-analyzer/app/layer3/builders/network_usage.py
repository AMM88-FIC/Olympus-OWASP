import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.snippet import get_snippet_context
from ..helpers.taint import detect_taint_sources
from ..models import (
    GeneratedBy, NetworkUsageFile, NetworkUsageRecord,
    SnippetContext, Source,
)
from ._patterns import (
    NETWORK_PATTERNS, extract_class_name, current_method, iter_java_files,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "network_usage_matcher_v1"
TOOL = "androguard-4.1.3+jadx-1.5.5"

# Window around onReceivedSslError to check if handler.proceed() is called
_SSL_ERROR_WINDOW = 10


def build(job_id: str, jadx_result) -> NetworkUsageFile:
    """
    Scan JADX Java source for TLS/trust/pinning API calls.

    Detects: custom TrustManagers, permissive HostnameVerifiers, SSLContext
    with legacy protocols, OkHttp client builders, and onReceivedSslError
    handlers that call proceed() unconditionally.

    Args:
        job_id:       Analysis job identifier.
        jadx_result:  JadxResult from the extraction coordinator.

    Returns:
        Populated NetworkUsageFile.
    """
    if not jadx_result.success or not jadx_result.source_dir:
        logger.warning("JADX output unavailable for job %s — skipping network scan", job_id)
        return _empty(job_id)

    source_dir = jadx_result.source_dir
    records: list[NetworkUsageRecord] = []

    for java_file in iter_java_files(source_dir):
        try:
            _scan_file(job_id, java_file, source_dir, records)
        except Exception as exc:
            logger.debug("Error scanning %s: %s", java_file, exc)

    return NetworkUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_file(
    job_id: str,
    java_file: Path,
    source_dir: Path,
    records: list[NetworkUsageRecord],
) -> None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    class_name = extract_class_name(java_file, source_dir)

    # Detect empty TrustManager (checkServerTrusted with empty body)
    _detect_trust_manager(job_id, java_file, source_dir, lines, class_name, records)

    # Detect HostnameVerifier returning true
    _detect_hostname_verifier(job_id, java_file, source_dir, lines, class_name, records)

    # Detect SSLContext with legacy protocol
    _detect_ssl_context(job_id, java_file, source_dir, lines, class_name, records)

    # Detect OkHttp builder
    _detect_okhttp(job_id, java_file, source_dir, lines, class_name, records)

    # Detect onReceivedSslError calling proceed
    _detect_ssl_error_handler(job_id, java_file, source_dir, lines, class_name, records)

    # Detect HttpURLConnection (for cleartext evidence)
    _detect_url_connection(job_id, java_file, source_dir, lines, class_name, records)


def _detect_trust_manager(job_id, java_file, source_dir, lines, class_name, records):
    check_re = re.compile(r'void\s+checkServerTrusted\s*\(')
    empty_body_re = re.compile(r'^\s*\}\s*$')

    for i, line in enumerate(lines):
        if not check_re.search(line):
            continue
        # Look ahead up to 5 lines for an empty body (just closing brace)
        body_lines = lines[i + 1: i + 6]
        body = "\n".join(body_lines)
        is_empty = all(
            not l.strip() or l.strip() in ("{", "}")
            for l in body_lines
            if l.strip()
        )
        line_no = i + 1
        ctx = get_snippet_context(java_file, line_no, line_no + 5)

        records.append(_make_record(
            job_id=job_id,
            java_file=java_file,
            source_dir=source_dir,
            class_name=class_name,
            method="checkServerTrusted",
            category="trust_manager",
            api_call="javax.net.ssl.X509TrustManager.checkServerTrusted",
            pattern_detected="empty_trust_manager" if is_empty else None,
            returns_without_validation=is_empty,
            line_no=line_no,
            ctx=ctx,
            lines=lines,
            line_idx=i,
        ))


def _detect_hostname_verifier(job_id, java_file, source_dir, lines, class_name, records):
    verifier_re = re.compile(r'HostnameVerifier|verify\s*\(\s*String\s+hostname')
    returns_true_re = re.compile(r'return\s+true\s*;')

    for i, line in enumerate(lines):
        if not verifier_re.search(line):
            continue
        # Check next 5 lines for return true
        window = "\n".join(lines[i: i + 6])
        returns_true = bool(returns_true_re.search(window))
        line_no = i + 1
        ctx = get_snippet_context(java_file, line_no, line_no)

        records.append(_make_record(
            job_id=job_id,
            java_file=java_file,
            source_dir=source_dir,
            class_name=class_name,
            method=current_method(lines, i),
            category="hostname_verifier",
            api_call="javax.net.ssl.HostnameVerifier.verify",
            pattern_detected="verifier_returns_true" if returns_true else None,
            returns_without_validation=returns_true,
            line_no=line_no,
            ctx=ctx,
            lines=lines,
            line_idx=i,
        ))
        break   # one record per file for HostnameVerifier


def _detect_ssl_context(job_id, java_file, source_dir, lines, class_name, records):
    ssl_re = re.compile(r'SSLContext\.getInstance\(\s*"(?P<proto>[^"]+)"')

    for i, line in enumerate(lines):
        m = ssl_re.search(line)
        if not m:
            continue
        proto = m.group("proto").upper()
        line_no = i + 1
        ctx = get_snippet_context(java_file, line_no, line_no)

        pattern = None
        if proto in ("TLSV1", "TLS1", "TLSV1.0"):
            pattern = "ssl_context_tls_v1"
        elif proto in ("TLSV1.1", "TLS1.1"):
            pattern = "ssl_context_tls_v1_1"

        records.append(_make_record(
            job_id=job_id,
            java_file=java_file,
            source_dir=source_dir,
            class_name=class_name,
            method=current_method(lines, i),
            category="ssl_context",
            api_call="javax.net.ssl.SSLContext.getInstance",
            pattern_detected=pattern,
            returns_without_validation=None,
            line_no=line_no,
            ctx=ctx,
            lines=lines,
            line_idx=i,
        ))


def _detect_okhttp(job_id, java_file, source_dir, lines, class_name, records):
    okhttp_re = re.compile(r'OkHttpClient\.Builder\s*\(')

    for i, line in enumerate(lines):
        if not okhttp_re.search(line):
            continue
        line_no = i + 1
        ctx = get_snippet_context(java_file, line_no, line_no)

        records.append(_make_record(
            job_id=job_id,
            java_file=java_file,
            source_dir=source_dir,
            class_name=class_name,
            method=current_method(lines, i),
            category="http_client",
            api_call="okhttp3.OkHttpClient.Builder",
            pattern_detected=None,
            returns_without_validation=None,
            line_no=line_no,
            ctx=ctx,
            lines=lines,
            line_idx=i,
        ))


def _detect_ssl_error_handler(job_id, java_file, source_dir, lines, class_name, records):
    ssl_error_re = re.compile(r'onReceivedSslError\s*\(')
    proceed_re = re.compile(r'handler\.proceed\s*\(')

    for i, line in enumerate(lines):
        if not ssl_error_re.search(line):
            continue
        window = "\n".join(lines[i: i + _SSL_ERROR_WINDOW])
        calls_proceed = bool(proceed_re.search(window))
        line_no = i + 1
        ctx = get_snippet_context(java_file, line_no, line_no + _SSL_ERROR_WINDOW)

        records.append(_make_record(
            job_id=job_id,
            java_file=java_file,
            source_dir=source_dir,
            class_name=class_name,
            method="onReceivedSslError",
            category="trust_manager",
            api_call="android.webkit.WebViewClient.onReceivedSslError",
            pattern_detected="ssl_error_proceed" if calls_proceed else None,
            returns_without_validation=calls_proceed,
            line_no=line_no,
            ctx=ctx,
            lines=lines,
            line_idx=i,
        ))


def _detect_url_connection(job_id, java_file, source_dir, lines, class_name, records):
    url_re = re.compile(r'HttpURLConnection|HttpsURLConnection')

    for i, line in enumerate(lines):
        if not url_re.search(line):
            continue
        line_no = i + 1
        ctx = get_snippet_context(java_file, line_no, line_no)

        records.append(_make_record(
            job_id=job_id,
            java_file=java_file,
            source_dir=source_dir,
            class_name=class_name,
            method=current_method(lines, i),
            category="url_connection",
            api_call="java.net.HttpURLConnection",
            pattern_detected=None,
            returns_without_validation=None,
            line_no=line_no,
            ctx=ctx,
            lines=lines,
            line_idx=i,
        ))
        break   # one record per file


def _make_record(
    job_id, java_file, source_dir, class_name, method,
    category, api_call, pattern_detected, returns_without_validation,
    line_no, ctx, lines, line_idx,
) -> NetworkUsageRecord:
    all_ctx = ctx["before"] + ctx["after"]
    taint = detect_taint_sources(all_ctx, [None])

    return NetworkUsageRecord(
        id=next_id(job_id, "net"),
        category=category,
        api_call=api_call,
        caller_class=class_name,
        caller_method=method,
        pattern_detected=pattern_detected,
        returns_without_validation=returns_without_validation,
        snippet=lines[line_idx].strip() if line_idx < len(lines) else "",
        snippet_context=SnippetContext(**ctx),
        taint_sources=taint,
        reachable_from=[],
        extraction_track="readable",
        confidence=0.91,
        related_ids=[],
        source=Source(
            artifact="java",
            path=str(java_file.relative_to(source_dir.parent)),
            line_start=line_no,
            line_end=line_no,
            extractor=EXTRACTOR,
            tool="jadx-1.5.5",
        ),
    )


def _empty(job_id: str) -> NetworkUsageFile:
    return NetworkUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )