"""
Per-job validation error registry.

Builders call record() when they catch an exception or produce a record
that fails validation. The validation_errors builder reads all_errors()
and writes _validation_errors.json.
"""

from threading import Lock

_registry: dict[str, list[dict]] = {}
_lock = Lock()


def record(
    job_id: str,
    builder: str,
    file: str,
    error_type: str,
    error_message: str,
    record_partial: dict | None = None,
) -> None:
    """
    Register a validation or extraction error.

    Args:
        job_id:          Analysis job identifier.
        builder:         Builder module name (e.g. "crypto_usage").
        file:            Output evidence file that would have received
                         this record (e.g. "crypto_usage.json").
        error_type:      Exception class name or short error category.
        error_message:   Human-readable description.
        record_partial:  Whatever fields were assembled before failure.
    """
    from datetime import datetime, timezone
    with _lock:
        if job_id not in _registry:
            _registry[job_id] = []
        _registry[job_id].append({
            "builder": builder,
            "file": file,
            "record_partial": record_partial or {},
            "error_type": error_type,
            "error_message": error_message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


def all_errors(job_id: str) -> list[dict]:
    """Return all errors for a job."""
    with _lock:
        return list(_registry.get(job_id, []))


def reset(job_id: str) -> None:
    """Clear all errors for a job. Call at the start of each analysis."""
    with _lock:
        _registry.pop(job_id, None)