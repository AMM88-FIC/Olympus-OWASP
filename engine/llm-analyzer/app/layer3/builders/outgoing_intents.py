import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.snippet import get_snippet_context
from ..helpers.taint import detect_taint_sources
from ..models import (
    GeneratedBy, IntentExtra, OutgoingIntentRecord,
    OutgoingIntentsFile, SnippetContext, Source,
)
from ._patterns import (
    OUTGOING_INTENT_APIS, extract_class_name, current_method, iter_java_files,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "outgoing_intent_matcher_v1"
TOOL = "androguard-4.1.3+jadx-1.5.5"

_INTENT_ACTION_RE = re.compile(r'new\s+Intent\s*\(\s*"(?P<a>[^"]+)"')
_INTENT_CLASS_RE = re.compile(
    r'new\s+Intent\s*\(\s*\w+\.this\s*,\s*(?P<cls>[\w.]+)\.class\s*\)'
)
_EXTRA_RE = re.compile(r'putExtra\s*\(\s*"(?P<k>[^"]+)"')
_PERMISSION_RE = re.compile(r'sendBroadcast\s*\(\s*\w+\s*,\s*"(?P<p>[^"]+)"')


def build(job_id: str, jadx_result) -> OutgoingIntentsFile:
    """
    Scan JADX Java source for outgoing Intent calls.

    Detects startActivity, sendBroadcast, startService and similar,
    classifying each as explicit or implicit and capturing extras.

    Args:
        job_id:       Analysis job identifier.
        jadx_result:  JadxResult from the extraction coordinator.

    Returns:
        Populated OutgoingIntentsFile.
    """
    if not jadx_result.success or not jadx_result.source_dir:
        logger.warning("JADX output unavailable for job %s — skipping outgoing intent scan", job_id)
        return _empty(job_id)

    source_dir = jadx_result.source_dir
    records: list[OutgoingIntentRecord] = []

    for java_file in iter_java_files(source_dir):
        try:
            _scan_file(job_id, java_file, source_dir, records)
        except Exception as exc:
            logger.debug("Error scanning %s: %s", java_file, exc)

    return OutgoingIntentsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_file(
    job_id: str,
    java_file: Path,
    source_dir: Path,
    records: list[OutgoingIntentRecord],
) -> None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    if "Intent" not in content:
        return

    lines = content.splitlines()
    class_name = extract_class_name(java_file, source_dir)

    for api_name, pattern in OUTGOING_INTENT_APIS:
        for line_idx, line in enumerate(lines):
            if not pattern.search(line):
                continue

            line_no = line_idx + 1
            method = current_method(lines, line_idx)
            ctx = get_snippet_context(java_file, line_no, line_no)
            all_ctx = ctx["before"] + ctx["after"]

            action, target_class, intent_type = _classify_intent(
                lines, line_idx
            )
            extras = _extract_extras(lines, line_idx)
            permission, has_permission = _detect_permission(line, api_name)
            taint = detect_taint_sources(all_ctx, [None])

            records.append(OutgoingIntentRecord(
                id=next_id(job_id, "oint"),
                api_call=api_name,
                intent_type=intent_type,
                target_component=None,
                target_package=None,
                action=action,
                categories=[],
                data_uri=None,
                mime_type=None,
                has_permission_guard=has_permission,
                permission_guard=permission,
                extras_summary=extras,
                flags=[],
                caller_class=class_name,
                caller_method=method,
                snippet=line.strip(),
                snippet_context=SnippetContext(**ctx),
                taint_sources=taint,
                reachable_from=[],
                extraction_track="readable",
                confidence=0.88,
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
            break   # one record per API per file


def _classify_intent(
    lines: list[str],
    pivot: int,
) -> tuple[str | None, str | None, str]:
    """
    Look backwards up to 10 lines to find the Intent construction.
    Returns (action, target_class, intent_type).
    """
    window = lines[max(0, pivot - 10): pivot + 1]
    combined = "\n".join(window)

    action_m = _INTENT_ACTION_RE.search(combined)
    class_m = _INTENT_CLASS_RE.search(combined)

    action = action_m.group("a") if action_m else None
    target = class_m.group("cls") if class_m else None

    if target:
        intent_type = "explicit"
    elif action:
        intent_type = "implicit"
    else:
        intent_type = "unknown"

    return action, target, intent_type


def _extract_extras(lines: list[str], pivot: int) -> list[IntentExtra]:
    window = "\n".join(lines[max(0, pivot - 10): pivot + 3])
    extras = []
    for m in _EXTRA_RE.finditer(window):
        extras.append(IntentExtra(
            key=m.group("k"),
            type_hint=None,
            source_expression=None,
        ))
    return extras


def _detect_permission(line: str, api_name: str) -> tuple[str | None, bool]:
    if api_name not in ("sendBroadcast", "sendOrderedBroadcast"):
        return None, False
    m = _PERMISSION_RE.search(line)
    if m:
        return m.group("p"), True
    return None, False


def _empty(job_id: str) -> OutgoingIntentsFile:
    return OutgoingIntentsFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )