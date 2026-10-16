"""
preprocessors/slim_records.py — Generic record-list slimmer.

Drops named bulky fields from each record in a record-list file, optionally
compacts the source object into a single path:line string. Designed for
files like api_usages.json, storage_usage.json, outgoing_intents.json
where snippet_context dominates the size.

Configuration via inline parameters in config.ini:
    api_usages.json = slim_records(drop=snippet_context;compact_source=true)

Parameters:
    drop=field1,field2     Comma-separated list of field names to drop
                           from every record. Default: snippet_context.
    compact_source=true    Replace the verbose source object with a single
                           "path:line_start-line_end" string. Saves ~150
                           bytes per record. Default: false.
    threshold_bytes=N      Skip slimming entirely when the input is below
                           N bytes. Default: 200_000 (200KB).

The full original records remain accessible via the navigator's
get_evidence_record / read_file tools — slim is for inline delivery only.
"""

from __future__ import annotations

from app.layer4.preprocessors.base import EvidencePreprocessor


# Same record-list-locating logic as slim_strings. Kept here rather than
# imported so each preprocessor module is self-contained.
_RECORDS_KEYS = ("records", "strings", "string_records")


def _find_records_list(data: dict) -> tuple[list, str] | tuple[None, None]:
    """Return (records_list, key_name) or (None, None) if no list found."""
    if not isinstance(data, dict):
        return None, None
    for key in _RECORDS_KEYS:
        if key in data and isinstance(data[key], list):
            return data[key], key
    for key, value in data.items():
        if (
            isinstance(value, list)
            and value
            and isinstance(value[0], dict)
            and "id" in value[0]
        ):
            return value, key
    return None, None


def _compact_source(source: dict | None) -> str | None:
    """Reduce a Source object to 'path:line_start-line_end' or 'path:line'."""
    if not isinstance(source, dict):
        return None
    path = source.get("path")
    if not path:
        return None
    line_start = source.get("line_start")
    line_end = source.get("line_end")
    if line_start is None:
        return path
    if line_end is None or line_end == line_start:
        return f"{path}:{line_start}"
    return f"{path}:{line_start}-{line_end}"


class SlimRecordsPreprocessor(EvidencePreprocessor):
    """Drop bulky fields from each record of a record-list file. Configurable
    per evidence file via inline parameters in config.ini."""

    name = "slim_records"

    # Defaults — overridden by parse_params() if the chain entry uses
    # inline parameters like 'slim_records(drop=foo;compact_source=true)'.
    DEFAULT_DROP_FIELDS = ("snippet_context",)
    DEFAULT_COMPACT_SOURCE = False
    DEFAULT_THRESHOLD_BYTES = 200_000

    def __init__(
        self,
        *,
        drop_fields: tuple[str, ...] = DEFAULT_DROP_FIELDS,
        compact_source: bool = DEFAULT_COMPACT_SOURCE,
        threshold_bytes: int = DEFAULT_THRESHOLD_BYTES,
    ):
        self.drop_fields = tuple(drop_fields)
        self.compact_source = compact_source
        self.threshold_bytes = int(threshold_bytes)

    @classmethod
    def from_params(cls, params: dict[str, str]) -> "SlimRecordsPreprocessor":
        """Construct from a parsed parameter dict (see parse_inline_params
        in base.py). Validates and converts string values to typed kwargs."""
        kwargs: dict = {}

        if "drop" in params:
            drop_str = params["drop"].strip()
            if drop_str:
                kwargs["drop_fields"] = tuple(
                    f.strip() for f in drop_str.split(",") if f.strip()
                )
            else:
                kwargs["drop_fields"] = ()

        if "compact_source" in params:
            kwargs["compact_source"] = (
                params["compact_source"].strip().lower()
                in ("1", "true", "yes", "on")
            )

        if "threshold_bytes" in params:
            try:
                kwargs["threshold_bytes"] = int(params["threshold_bytes"])
            except ValueError as e:
                raise ValueError(
                    f"slim_records: threshold_bytes must be an integer, "
                    f"got {params['threshold_bytes']!r}"
                ) from e

        # Reject unknown keys so typos surface at config-load time
        unknown = set(params) - {"drop", "compact_source", "threshold_bytes"}
        if unknown:
            raise ValueError(
                f"slim_records: unknown parameter(s) {sorted(unknown)}. "
                f"Known: drop, compact_source, threshold_bytes."
            )

        return cls(**kwargs)

    def applies_to(self, evidence_name: str) -> bool:
        # No file-name restriction — use config to scope per-file.
        return True

    def process_object(self, evidence_name: str, parsed: object) -> object:
        if not isinstance(parsed, dict):
            return parsed

        # Threshold check — measured against the parsed object's serialized
        # size. We useujson.dumps with no whitespace so the threshold matches
        # the eventual delivery size, not the on-disk pretty-printed size.
        import ujson
        size = len(ujson.dumps(parsed, separators=(",", ":"),
                              ensure_ascii=False))
        if size < self.threshold_bytes:
            return parsed

        records, records_key = _find_records_list(parsed)
        if records is None:
            return parsed

        slim_records: list[dict] = []
        n_dropped = 0
        for rec in records:
            if not isinstance(rec, dict):
                slim_records.append(rec)
                continue
            new_rec = {}
            for k, v in rec.items():
                if k in self.drop_fields:
                    n_dropped += 1
                    continue
                if k == "source" and self.compact_source:
                    compact = _compact_source(v)
                    if compact is not None:
                        new_rec["source"] = compact
                        continue
                new_rec[k] = v
            slim_records.append(new_rec)

        # Rebuild the parent object preserving non-list metadata fields and
        # adding a slim_note explaining what changed.
        out = {k: v for k, v in parsed.items() if not isinstance(v, list)}
        out[records_key] = slim_records

        note_parts = []
        if self.drop_fields:
            note_parts.append(
                f"Dropped fields: {', '.join(self.drop_fields)}"
            )
        if self.compact_source:
            note_parts.append(
                "source objects compacted to 'path:line_start-line_end' strings"
            )
        out["_slim_note"] = (
            f"This file has been slimmed for inline delivery. "
            f"{'. '.join(note_parts)}. "
            f"To get full record content (including dropped fields), use "
            f"the read_file tool with the source path and line range. "
            f"{len(slim_records)} records present."
        )
        return out