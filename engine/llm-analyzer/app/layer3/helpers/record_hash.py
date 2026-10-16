import hashlib
import ujson


def compute_record_hash(
    caller_class: str | None = None,
    caller_method: str | None = None,
    line_start: int | None = None,
    api_call: str | None = None,
    path: str | None = None,
    xpath: str | None = None,
    extra: str | None = None,
) -> str:
    """
    Compute a stable, content-based SHA-256 hash for an evidence record.

    The hash is derived from a canonical subset of the record's fields.
    Two records with the same hash represent the same finding regardless
    of iteration order or run number.

    All fields default to empty string when None so the hash remains
    deterministic across optional fields.

    Args:
        caller_class:   Fully qualified class name containing the finding.
        caller_method:  Method name containing the finding.
        line_start:     Line number of the finding (1-indexed).
        api_call:       The API call or field name that triggered the record.
        path:           Source file path.
        xpath:          XPath into an XML document (for manifest records).
        extra:          Any additional discriminator string.

    Returns:
        Lowercase hex SHA-256 string (64 characters).
    """
    canonical =ujson.dumps(
        {
            "caller_class": caller_class or "",
            "caller_method": caller_method or "",
            "line_start": line_start or 0,
            "api_call": api_call or "",
            "path": path or "",
            "xpath": xpath or "",
            "extra": extra or "",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_from_source(source, api_call: str = "", extra: str = "") -> str:
    """
    Convenience wrapper that accepts a Source object directly.

    Args:
        source:   Source object from a BaseRecord.
        api_call: The API call or field name for this record.
        extra:    Additional discriminator if multiple records share
                  the same source location.
    """
    return compute_record_hash(
        path=getattr(source, "path", None),
        xpath=getattr(source, "xpath", None),
        line_start=getattr(source, "line_start", None),
        api_call=api_call,
        extra=extra,
    )