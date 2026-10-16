import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.snippet import get_snippet_context
from ..helpers.taint import detect_taint_sources
from ..models import (
    ExposedMethod, GeneratedBy, JavascriptInterface,
    SnippetContext, Source, TaintSource, UrlLoad,
    WebViewRecord, WebViewSettings, WebViewUsageFile,
)
from ._patterns import (
    WEBVIEW_PATTERNS, extract_class_name, iter_java_files,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "webview_scanner_v1"
TOOL = "androguard-4.1.3+jadx-1.5.5"

_JS_INTERFACE_RE = re.compile(
    r'addJavascriptInterface\s*\(\s*(?P<obj>[^,]+),\s*"(?P<name>[^"]+)"'
)
_LOAD_URL_RE = re.compile(r'\.loadUrl\s*\(\s*(?P<url>[^)]+)\)')
_LITERAL_URL_RE = re.compile(r'^"(?P<u>https?://[^"]+)"$')
_INTENT_URL_RE = re.compile(r'getIntent\(\)|getStringExtra|getData\(\)')


def build(job_id: str, jadx_result) -> WebViewUsageFile:
    """
    Scan JADX Java source for WebView usage.

    Aggregates all WebView configuration within each class into a single
    record per class — settings, JS bridges, and URL loads. Multiple
    classes may each have their own WebViewRecord.

    Args:
        job_id:       Analysis job identifier.
        jadx_result:  JadxResult from the extraction coordinator.

    Returns:
        Populated WebViewUsageFile.
    """
    if not jadx_result.success or not jadx_result.source_dir:
        logger.warning("JADX output unavailable for job %s — skipping webview scan", job_id)
        return _empty(job_id)

    source_dir = jadx_result.source_dir
    records: list[WebViewRecord] = []

    for java_file in iter_java_files(source_dir):
        try:
            record = _scan_file(job_id, java_file, source_dir)
            if record:
                records.append(record)
        except Exception as exc:
            logger.debug("Error scanning %s: %s", java_file, exc)

    return WebViewUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_file(
    job_id: str,
    java_file: Path,
    source_dir: Path,
) -> WebViewRecord | None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Quick pre-filter — skip files with no WebView references
    if "WebView" not in content:
        return None

    lines = content.splitlines()
    class_name = extract_class_name(java_file, source_dir)

    settings = WebViewSettings()
    js_interfaces: list[JavascriptInterface] = []
    url_loads: list[UrlLoad] = []
    taint_sources: list[TaintSource] = []
    first_line = None
    last_line = None

    for line_idx, line in enumerate(lines):
        line_no = line_idx + 1

        for pattern_name, pattern in WEBVIEW_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue

            first_line = first_line or line_no
            last_line = line_no

            _apply_setting(settings, pattern_name, m, line)

            if pattern_name == "js_interface":
                ji = _extract_js_interface(m, java_file, source_dir)
                if ji:
                    js_interfaces.append(ji)

            if pattern_name == "load_url":
                url_load = _extract_url_load(
                    m, line, lines, line_idx, java_file, source_dir
                )
                url_loads.append(url_load)
                ctx = get_snippet_context(java_file, line_no, line_no)
                ts = detect_taint_sources(
                    ctx["before"] + ctx["after"], [m.group("url")]
                )
                taint_sources.extend(ts)

    if first_line is None:
        return None

    ctx = get_snippet_context(java_file, first_line, last_line or first_line)

    return WebViewRecord(
        id=next_id(job_id, "wv"),
        caller_class=class_name,
        caller_method="onCreate",   # WebView setup is typically in onCreate
        settings=settings,
        javascript_interfaces=js_interfaces,
        url_loads=url_loads,
        taint_sources=taint_sources,
        reachable_from=[],
        extraction_track="readable",
        confidence=0.93,
        related_ids=[],
        source=Source(
            artifact="java",
            path=str(java_file.relative_to(source_dir.parent)),
            line_start=first_line,
            line_end=last_line or first_line,
            extractor=EXTRACTOR,
            tool="jadx-1.5.5",
        ),
    )


def _apply_setting(
    settings: WebViewSettings,
    pattern_name: str,
    m: re.Match,
    line: str,
) -> None:
    val_str = m.groupdict().get("val")
    val = val_str.lower() == "true" if val_str else None

    if pattern_name == "js_enabled":
        settings.javascript_enabled = val
    elif pattern_name == "file_access":
        settings.allow_file_access = val
    elif pattern_name == "universal_access":
        settings.allow_universal_access_from_file_urls = val
    elif pattern_name == "content_access":
        settings.allow_content_access = val
    elif pattern_name == "dom_storage":
        settings.dom_storage_enabled = val
    elif pattern_name == "safe_browsing":
        settings.safe_browsing_enabled = val
    elif pattern_name == "mixed_content":
        settings.mixed_content_mode = None   # value needs more parsing; flagged as set
    elif pattern_name == "debugging_enabled":
        pass   # captured via network_usage builder's ssl_error_handler


def _extract_js_interface(m: re.Match, java_file: Path, source_dir: Path) -> JavascriptInterface | None:
    obj_expr = m.group("obj").strip()
    exposed_name = m.group("name")
    return JavascriptInterface(
        bridge_object_class=obj_expr,
        exposed_name=exposed_name,
        exposed_methods=[],   # method-level extraction requires AST; deferred
    )


def _extract_url_load(
    m: re.Match,
    line: str,
    lines: list[str],
    line_idx: int,
    java_file: Path,
    source_dir: Path,
) -> UrlLoad:
    url_expr = m.group("url").strip()
    ctx = get_snippet_context(java_file, line_idx + 1, line_idx + 1)

    # Classify URL source
    if _LITERAL_URL_RE.match(url_expr):
        url_source = "literal"
        literal_url = url_expr.strip('"')
    elif _INTENT_URL_RE.search(url_expr):
        url_source = "intent_extra"
        literal_url = None
    else:
        url_source = "unknown"
        literal_url = None

    return UrlLoad(
        api="loadUrl",
        url_source=url_source,
        literal_url=literal_url,
        snippet=line.strip(),
        snippet_context=SnippetContext(**ctx),
        line=line_idx + 1,
    )


def _empty(job_id: str) -> WebViewUsageFile:
    return WebViewUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )