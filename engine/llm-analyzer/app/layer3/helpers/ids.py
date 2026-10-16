from threading import Lock

_counters: dict[str, int] = {}
_lock = Lock()

VALID_PREFIXES = frozenset({
    "cmp", "api", "crypto", "wv", "net", "stor",
    "oint", "str", "sdk", "asset", "jni", "perm",
    "dl", "nsc", "meta", "nlib", "nstr", "sens",
    "lib"
})


def reset(job_id: str) -> None:
    """Reset all counters for a new job. Call once at the start of each analysis."""
    with _lock:
        for prefix in VALID_PREFIXES:
            _counters[f"{job_id}:{prefix}"] = 0


def next_id(job_id: str, prefix: str) -> str:
    """
    Return the next globally unique ID for this job and prefix.
    Format: {prefix}-{zero_padded_count}  e.g. cmp-001, api-042

    Raises ValueError for unknown prefixes so typos surface immediately.
    """
    if prefix not in VALID_PREFIXES:
        raise ValueError(
            f"Unknown ID prefix '{prefix}'. Valid prefixes: {sorted(VALID_PREFIXES)}"
        )
    key = f"{job_id}:{prefix}"
    with _lock:
        _counters[key] = _counters.get(key, 0) + 1
        return f"{prefix}-{_counters[key]:03d}"