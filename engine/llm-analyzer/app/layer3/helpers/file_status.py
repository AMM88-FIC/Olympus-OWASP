"""
Per-job file status registry.

Each builder calls register() after it finishes. The coverage builder
calls get_all() to assemble the file_status dict for coverage.json.

The registry is a simple dict keyed by job_id — no global state bleeds
across concurrent jobs.
"""

import time
from threading import Lock

_registry: dict[str, dict[str, dict]] = {}
_lock = Lock()


def register(
    job_id: str,
    file_key: str,
    extractor: str,
    tool: str,
    scan_completed: bool,
    records_emitted: int,
    duration_ms: int | None = None,
    errors: list[str] | None = None,
    blind_spots: list[str] | None = None,
    notes: list[str] | None = None,
) -> None:
    """
    Record the scan status for one evidence file.

    Args:
        job_id:          Analysis job identifier.
        file_key:        Evidence file key, e.g. "crypto_usage".
        extractor:       Extractor name string.
        tool:            Tool version string.
        scan_completed:  True if the builder ran to completion.
        records_emitted: Number of records in the output file.
        duration_ms:     Wall-clock time for this builder in milliseconds.
        errors:          List of error messages from this builder.
        blind_spots:     Analysis areas this builder cannot cover.
        notes:           Additional human-readable notes.
    """
    with _lock:
        if job_id not in _registry:
            _registry[job_id] = {}
        _registry[job_id][file_key] = {
            "scan_completed": scan_completed,
            "records_emitted": records_emitted,
            "extractor": extractor,
            "tool": tool,
            "duration_ms": duration_ms,
            "errors": errors or [],
            "blind_spots": blind_spots or [],
            "notes": notes or [],
        }


def get_all(job_id: str) -> dict[str, dict]:
    """Return all registered statuses for a job."""
    with _lock:
        return dict(_registry.get(job_id, {}))


def reset(job_id: str) -> None:
    """Clear all statuses for a job. Call at the start of each analysis."""
    with _lock:
        _registry.pop(job_id, None)