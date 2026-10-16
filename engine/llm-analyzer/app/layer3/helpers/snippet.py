from pathlib import Path


def get_snippet_context(
    java_file: Path,
    line_start: int,
    line_end: int,
    window: int = 5,
) -> dict:
    """
    Return a snippet_context dict for a code-derived record.

    Reads the Java file and returns up to `window` lines before line_start
    and up to `window` lines after line_end. Line numbers are 1-indexed,
    matching JADX output.

    Returns a dict matching the SnippetContext schema:
        {before: [...], after: [...], window_lines: int}

    Falls back gracefully if the file cannot be read or line numbers are
    out of range.
    """
    try:
        lines = java_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"before": [], "after": [], "window_lines": window}

    total = len(lines)

    # Convert to 0-indexed, clamp to file bounds
    start_idx = max(0, line_start - 1)
    end_idx = min(total - 1, line_end - 1)

    before_start = max(0, start_idx - window)
    after_end = min(total, end_idx + 1 + window)

    before = lines[before_start:start_idx]
    after = lines[end_idx + 1:after_end]

    return {
        "before": before,
        "after": after,
        "window_lines": window,
    }


def get_snippet_line(java_file: Path, line: int) -> str:
    """Return a single line from a Java file (1-indexed). Empty string on error."""
    try:
        lines = java_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
    except OSError:
        pass
    return ""