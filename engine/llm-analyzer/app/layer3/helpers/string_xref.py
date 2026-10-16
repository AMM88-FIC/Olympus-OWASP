"""
Back-reference scanner for strings.json.

For each string record, finds JADX Java files that reference the
string's literal value and populates the StringRecord.referenced_in list.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_MAX_REFS_PER_STRING = 10
_MIN_STRING_LENGTH = 8


def populate_string_references(
    strings_file,
    source_dir: Path,
    tool: str = "jadx-1.5.5",
) -> None:
    """
    Mutate StringRecord.referenced_in in-place for each record in strings_file.

    Args:
        strings_file: StringsFile produced by the strings builder.
        source_dir:   JADX sources directory (jadx_result.source_dir).
        tool:         Tool string to embed in Source objects.
    """
    if not source_dir or not source_dir.exists():
        logger.debug("string_xref: source_dir not available, skipping")
        return

    # Build (value → record) map, skip short strings
    candidates = {
        rec.value: rec
        for rec in strings_file.records
        if len(rec.value) >= _MIN_STRING_LENGTH
    }
    if not candidates:
        return

    for java_file in sorted(source_dir.rglob("*.java")):
        try:
            _scan_file(java_file, source_dir, candidates, tool)
        except Exception as exc:
            logger.debug("string_xref scan error on %s: %s", java_file, exc)


def _scan_file(
    java_file: Path,
    source_dir: Path,
    candidates: dict,
    tool: str,
) -> None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    rel_path = str(java_file.relative_to(source_dir.parent))
    class_name = _class_name(java_file, source_dir)

    for value, rec in candidates.items():
        if len(rec.referenced_in) >= _MAX_REFS_PER_STRING:
            continue
        if value not in content:
            continue

        for line_idx, line in enumerate(lines):
            if value not in line:
                continue
            if len(rec.referenced_in) >= _MAX_REFS_PER_STRING:
                break

            from ..models import Source, StringCaller
            rec.referenced_in.append(StringCaller(
                caller_class=class_name,
                caller_method=_find_method(lines, line_idx),
                source=Source(
                    artifact="java",
                    path=rel_path,
                    line_start=line_idx + 1,
                    line_end=line_idx + 1,
                    extractor="string_xref_v1",
                    tool=tool,
                ),
            ))


def _class_name(java_file: Path, source_dir: Path) -> str:
    try:
        rel = java_file.relative_to(source_dir)
        return str(rel.with_suffix("")).replace("/", ".")
    except ValueError:
        return java_file.stem


def _find_method(lines: list[str], line_idx: int) -> str:
    method_re = re.compile(
        r'(?:public|private|protected|static|final|synchronized)'
        r'[\w\s<>\[\]]+\s+(\w+)\s*\('
    )
    for i in range(line_idx, max(-1, line_idx - 60), -1):
        m = method_re.search(lines[i])
        if m:
            return m.group(1)
    return "unknown"