import re
from pathlib import Path

# Known taint source patterns — matched against variable assignment lines
# within the same method as the API call being analyzed.
# Intra-procedural only: we look within the same method body extracted from
# the snippet context, not across call boundaries.

_TAINT_PATTERNS: list[tuple[str, str]] = [
    (r"getIntent\(\)\s*\.get\w+Extra\s*\(", "intent_extra"),
    (r"getIntent\(\)\s*\.getData\s*\(", "intent_data"),
    (r"getIntent\(\)\s*\.getExtras\s*\(", "intent_extra"),
    (r"Uri\.parse\s*\(", "uri_parse"),
    (r"onReceive\s*\(.*Intent", "broadcast_receive"),
    (r"\.query\s*\(.*selection", "provider_query"),
    (r"ClipboardManager", "clipboard"),
    (r"openFileInput\s*\(|FileInputStream\s*\(", "file_read"),
    (r"EditText|getText\(\)|getInput", "user_input"),
    (r"HttpURLConnection|OkHttpClient|Retrofit|getResponseBody", "network_input"),
]


def detect_taint_sources(
    context_lines: list[str],
    parameter_expressions: list[str | None],
    job_id: str = "",
) -> list[dict]:
    """
    Intra-procedural taint source detection.

    Scans context_lines (before + after snippet lines) for patterns that
    indicate the origin of data flowing into the API call being analyzed.
    Cross-references against parameter_expressions to assign taint to the
    correct parameter position.

    Returns a list of taint source dicts matching the TaintSource schema.
    Always sets intraprocedural_only=True.

    Args:
        context_lines:         Lines surrounding the call site (before + after).
        parameter_expressions: Source expressions per parameter position,
                               as recorded during extraction. None if unknown.
        job_id:                Used for logging only.

    Returns:
        List of TaintSource dicts, empty when nothing is detected.
    """
    all_lines = "\n".join(context_lines)
    results: list[dict] = []

    for pattern, source_type in _TAINT_PATTERNS:
        match = re.search(pattern, all_lines)
        if not match:
            continue

        # Try to match to a parameter position
        position = 0
        for i, expr in enumerate(parameter_expressions):
            if expr and re.search(pattern, expr):
                position = i
                break

        results.append({
            "source_type": source_type,
            "expression": match.group(0).strip(),
            "parameter_position": position,
            "intraprocedural_only": True,
            "confidence": 0.75,
        })

    # Deduplicate by source_type
    seen: set[str] = set()
    unique = []
    for r in results:
        if r["source_type"] not in seen:
            seen.add(r["source_type"])
            unique.append(r)

    return unique