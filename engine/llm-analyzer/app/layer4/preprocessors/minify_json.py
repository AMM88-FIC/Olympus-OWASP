"""
preprocessors/minify_json.py — Terminal preprocessor that emits the parsed
evidence as compact JSON with no whitespace.

This is the preferred default for token reduction. On record-heavy evidence
files it produces ~25-35% size reduction over prettified JSON without any
semantic change — the model receives identical content, just without
indentation and inter-token spaces.

Why this beats flattened YAML / dotted-path flattening for our data:
  - Record arrays cause repeated `records[N].x` prefixes that bloat output.
  - YAML quoting rules add quotes back for paths and URLs (anything with
    colons), erasing most of YAML's bare-string advantage.
  - The model already expects JSON for protocol messages — staying in JSON
    means no format-switching cost.

Compose with slim_strings to combine record-shape reduction (slim_strings)
with whitespace removal (minify_json) for maximum token savings.
"""

from __future__ import annotations

import ujson

from app.layer4.preprocessors.base import EvidencePreprocessor


class MinifyJsonPreprocessor(EvidencePreprocessor):
    """Terminal preprocessor: serialize the parsed object as compact JSON
    (no whitespace, no indentation)."""

    name = "minify_json"
    is_terminal = True

    def applies_to(self, evidence_name: str) -> bool:
        # Apply to all evidence files unless overridden in config.
        return True

    def process_object(self, evidence_name: str, parsed: object) -> str:
        # ensure_ascii=False keeps non-ASCII characters as-is (UTF-8 in the
        # output) which is more compact than \uXXXX escape sequences.
        return ujson.dumps(parsed, separators=(",", ":"), ensure_ascii=False)