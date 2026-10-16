"""
preprocessors/slim_strings.py — Reduce strings.json records to id, category,
value, and a combined source-path field.

The full strings.json is delivered to the navigator's index for tool-driven
expansion (get_string_record, list_string_records_by_category). This
preprocessor produces a slim form for inline delivery — typically a 60-75%
size reduction depending on how heavy snippet_context is in the original.

Slim record shape:
    {
      "id": "str-001",
      "category": "API_KEY",
      "value": "deadbeef-...",
      "path": "jadx/sources/com/example/Foo.java:78"
    }
"""

from __future__ import annotations

from app.layer4.preprocessors.base import EvidencePreprocessor


# The records list lives under one of these keys in different schema versions.
_RECORDS_KEYS = ("records", "strings", "string_records")


def _find_records_list(data: dict) -> list | None:
    """Best-effort: locate the records list in a strings.json blob."""
    if not isinstance(data, dict):
        return None
    for key in _RECORDS_KEYS:
        if key in data and isinstance(data[key], list):
            return data[key]
    # Fallback: any top-level list of dicts with 'id' fields
    for value in data.values():
        if (
            isinstance(value, list)
            and value
            and isinstance(value[0], dict)
            and "id" in value[0]
        ):
            return value
    return None


def _records_key(data: dict) -> str:
    """Return the key under which the records list lives, defaulting to 'records'."""
    for key in _RECORDS_KEYS:
        if key in data:
            return key
    return "records"


class SlimStringsPreprocessor(EvidencePreprocessor):
    """Trim strings.json records to id/category/value/path. Adds a `_slim_note`
    explaining how to retrieve the full records via tools."""

    name = "slim_strings"

    def applies_to(self, evidence_name: str) -> bool:
        # Only act on strings.json — running on anything else is a no-op.
        return evidence_name == "strings.json"

    def process_object(self, evidence_name: str, parsed: object) -> object:
        if not isinstance(parsed, dict):
            return parsed

        records = _find_records_list(parsed)
        if not records:
            return parsed

        slim_records = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            rid = rec.get("id")
            if not rid:
                continue
            src = rec.get("source") or {}
            path = src.get("path")
            line_start = src.get("line_start")
            line_end = src.get("line_end")
            if path and line_start is not None:
                if line_end is not None and line_end != line_start:
                    path_str = f"{path}:{line_start}-{line_end}"
                else:
                    path_str = f"{path}:{line_start}"
            else:
                path_str = path  # may be None
            slim = {
                "id": rid,
                "category": rec.get("category"),
                "value": rec.get("value"),
            }
            if path_str:
                slim["path"] = path_str
            slim_records.append(slim)

        # Preserve top-level metadata (schema_version etc.) but replace the
        # records array with the slim version.
        out = {k: v for k, v in parsed.items() if not isinstance(v, list)}
        out[_records_key(parsed)] = slim_records
        out["_slim_note"] = (
            f"This file has been slimmed for inline delivery. Each record "
            f"contains only id, category, value, and path. To get the full "
            f"record (including snippet_context, noise_signals, and any other "
            f"fields), call the get_string_record tool with the record's id. "
            f"To enumerate full records by category, call "
            f"list_string_records_by_category. {len(slim_records)} records "
            f"available."
        )
        return out