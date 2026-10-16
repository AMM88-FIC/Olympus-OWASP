import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from ..helpers.ids import next_id
from ..helpers.snippet import get_snippet_context
from ..helpers.taint import detect_taint_sources
from ..models import (
    GeneratedBy, SnippetContext, Source,
    StorageTarget, StorageUsageFile, StorageUsageRecord,
)
from ._patterns import (
    STORAGE_PATTERNS, extract_class_name, current_method, iter_java_files,
)

logger = logging.getLogger(__name__)

EXTRACTOR = "storage_usage_matcher_v1"
TOOL = "androguard-4.1.3+jadx-1.5.5"

_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "token", "secret", "api_key", "apikey",
    "credential", "auth", "pin", "ssn", "dob", "credit",
})

_PREFS_NAME_RE = re.compile(r'getSharedPreferences\s*\(\s*"(?P<n>[^"]+)"')
_PREFS_MODE_RE = re.compile(r',\s*(?P<m>MODE_\w+)\s*\)')
_FILE_PATH_RE = re.compile(r'(?:openFileOutput|FileOutputStream)\s*\(\s*"(?P<p>[^"]+)"')


def build(job_id: str, jadx_result) -> StorageUsageFile:
    """
    Scan JADX Java source for storage API calls.

    Detects: SharedPreferences, SQLite (raw query and execSQL), Room,
    Realm, external storage, DataStore, and world-readable/writable modes.

    Args:
        job_id:       Analysis job identifier.
        jadx_result:  JadxResult from the extraction coordinator.

    Returns:
        Populated StorageUsageFile.
    """
    if not jadx_result.success or not jadx_result.source_dir:
        logger.warning("JADX output unavailable for job %s — skipping storage scan", job_id)
        return _empty(job_id)

    source_dir = jadx_result.source_dir
    records: list[StorageUsageRecord] = []

    for java_file in iter_java_files(source_dir):
        try:
            _scan_file(job_id, java_file, source_dir, records)
        except Exception as exc:
            logger.debug("Error scanning %s: %s", java_file, exc)

    return StorageUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=records,
    )


def _scan_file(
    job_id: str,
    java_file: Path,
    source_dir: Path,
    records: list[StorageUsageRecord],
) -> None:
    try:
        content = java_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    lines = content.splitlines()
    class_name = extract_class_name(java_file, source_dir)

    _CATEGORY_MAP = {
        "shared_prefs":     "shared_preferences",
        "shared_prefs_edit": "shared_preferences",
        "sqlite_raw_query": "sqlite",
        "sqlite_exec_sql":  "sqlite",
        "sqlite_open":      "sqlite",
        "room_db":          "room",
        "realm_open":       "realm",
        "external_storage": "file_external",
        "file_output":      "file_internal",
        "datastore":        "datastore",
        "world_readable":   "shared_preferences",
    }

    _API_MAP = {
        "shared_prefs":      "android.content.Context.getSharedPreferences",
        "shared_prefs_edit": "android.content.SharedPreferences.edit",
        "sqlite_raw_query":  "android.database.sqlite.SQLiteDatabase.rawQuery",
        "sqlite_exec_sql":   "android.database.sqlite.SQLiteDatabase.execSQL",
        "sqlite_open":       "android.database.sqlite.SQLiteOpenHelper",
        "room_db":           "androidx.room.Room.databaseBuilder",
        "realm_open":        "io.realm.Realm.getInstance",
        "external_storage":  "android.os.Environment.getExternalStorageDirectory",
        "file_output":       "java.io.FileOutputStream",
        "datastore":         "androidx.datastore.DataStore",
        "world_readable":    "android.content.Context.MODE_WORLD_READABLE",
    }

    seen_patterns: set[str] = set()

    for pattern_name, pattern in STORAGE_PATTERNS:
        if pattern_name in seen_patterns:
            continue

        for line_idx, line in enumerate(lines):
            if not pattern.search(line):
                continue

            seen_patterns.add(pattern_name)
            category = _CATEGORY_MAP.get(pattern_name, "file_internal")
            api_call = _API_MAP.get(pattern_name, pattern_name)
            line_no = line_idx + 1
            method = current_method(lines, line_idx)
            ctx = get_snippet_context(java_file, line_no, line_no)
            all_ctx = ctx["before"] + ctx["after"]

            storage_target = _extract_storage_target(
                pattern_name, line, lines, line_idx
            )
            sensitive_keys = _detect_sensitive_keys(lines, line_idx)
            taint = detect_taint_sources(all_ctx, [None])

            records.append(StorageUsageRecord(
                id=next_id(job_id, "stor"),
                category=category,
                api_call=api_call,
                caller_class=class_name,
                caller_method=method,
                storage_target=storage_target,
                contains_sensitive_keys_heuristic=sensitive_keys,
                snippet=line.strip(),
                snippet_context=SnippetContext(**ctx),
                taint_sources=taint,
                reachable_from=[],
                extraction_track="readable",
                confidence=0.92,
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
            break   # one record per pattern per file


def _extract_storage_target(
    pattern_name: str,
    line: str,
    lines: list[str],
    pivot: int,
) -> StorageTarget | None:
    if pattern_name in ("shared_prefs", "world_readable"):
        name_m = _PREFS_NAME_RE.search(line)
        mode_m = _PREFS_MODE_RE.search(line)
        name = name_m.group("n") if name_m else None
        mode = mode_m.group("m") if mode_m else None
        world_r = "MODE_WORLD_READABLE" in (mode or "")
        world_w = "MODE_WORLD_WRITEABLE" in (mode or "")
        return StorageTarget(
            name=name,
            mode=mode,
            mode_is_world_readable=world_r,
            mode_is_world_writable=world_w,
        )

    if pattern_name == "file_output":
        path_m = _FILE_PATH_RE.search(line)
        return StorageTarget(
            name=path_m.group("p") if path_m else None,
            mode=None,
        )

    return None


def _detect_sensitive_keys(lines: list[str], pivot: int) -> list[str]:
    """
    Look for putString/putInt calls with sensitive key names in a ±15 line window.
    """
    window = "\n".join(lines[max(0, pivot - 5): pivot + 15]).lower()
    found = []
    for key in _SENSITIVE_KEYS:
        if f'"{key}"' in window or f"'{key}'" in window:
            found.append(key)
    return found


def _empty(job_id: str) -> StorageUsageFile:
    return StorageUsageFile(
        job_id=job_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        generated_by=GeneratedBy(extractor=EXTRACTOR, tool=TOOL),
        records=[],
    )