#!/usr/bin/env python3
"""
Build the review-mode system prompt and schema.

Review mode differs from analysis mode in its framing, not in how the engine
reads evidence. So the ~350 lines covering the three evidence levels, tool-use
discipline, escalation, the proprietary-code scope filter, fail-finding
verification, certainty calibration, coverage limits and citation rules are
INHERITED from the analysis prompt rather than copied. A fork would drift, and
the drift would be silent.

    review system prompt = validation/header.md
                         + <analysis prompt, "How to read evidence" .. "Self-verification">
                         + validation/footer.md

    review schema        = <analysis schema>
                         + validation/schema_addendum.md

Run after editing either source, or after bumping the analysis prompt/schema:

    python tools/build_validation_prompts.py

Both outputs carry a generated-file banner. Edit the sources, never the output.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SYSTEM = REPO / "app" / "layer4" / "prompts" / "system"
SRC = SYSTEM / "validation"

# Inherited slice of the analysis prompt, delimited by headings rather than
# line numbers so edits inside the slice do not break the build.
INHERIT_FROM = "# How to read evidence — three levels"
INHERIT_TO = "# Self-verification before emitting"

BANNER = (
    "<!-- GENERATED FILE — do not edit.\n"
    "     Built by tools/build_validation_prompts.py from:\n"
    "{sources}\n"
    "     Edit those, then re-run the builder. -->\n\n"
)


def newest(*paths: Path) -> str:
    return "\n".join(f"       - {p.relative_to(REPO).as_posix()}" for p in paths)


def build_prompt(analysis_prompt: Path, out: Path) -> None:
    text = analysis_prompt.read_text(encoding="utf-8")
    if INHERIT_FROM not in text:
        sys.exit(f"Cannot find inherit-start heading in {analysis_prompt.name}:\n"
                 f"  {INHERIT_FROM!r}\n"
                 f"The analysis prompt's headings changed; update INHERIT_FROM.")
    if INHERIT_TO not in text:
        sys.exit(f"Cannot find inherit-end heading in {analysis_prompt.name}:\n"
                 f"  {INHERIT_TO!r}\n"
                 f"The analysis prompt's headings changed; update INHERIT_TO.")

    inherited = text[text.index(INHERIT_FROM):text.index(INHERIT_TO)].rstrip()
    header = (SRC / "header.md").read_text(encoding="utf-8").rstrip()
    footer = (SRC / "footer.md").read_text(encoding="utf-8").rstrip()

    note = (
        "\n\n---\n\n"
        "*The sections that follow — evidence levels, tool-use discipline, "
        "escalation, scope filtering, fail-finding verification, certainty "
        f"calibration, coverage limits and citation rules — are inherited "
        f"verbatim from `{analysis_prompt.name}` and apply here identically.*\n\n"
    )

    banner = BANNER.format(sources=newest(
        SRC / "header.md", SRC / "footer.md", analysis_prompt))
    out.write_text(banner + header + note + inherited + "\n\n" + footer + "\n",
                   encoding="utf-8")
    print(f"  {out.relative_to(REPO).as_posix()}  "
          f"({out.read_text(encoding='utf-8').count(chr(10))} lines)")


def build_schema(analysis_schema: Path, out: Path) -> None:
    base = analysis_schema.read_text(encoding="utf-8").rstrip()
    addendum = (SRC / "schema_addendum.md").read_text(encoding="utf-8").rstrip()
    banner = BANNER.format(sources=newest(
        analysis_schema, SRC / "schema_addendum.md"))
    out.write_text(banner + base + "\n\n" + addendum + "\n", encoding="utf-8")
    print(f"  {out.relative_to(REPO).as_posix()}  "
          f"({out.read_text(encoding='utf-8').count(chr(10))} lines)")


def version_key(path: Path) -> list[int]:
    """Sort by numeric version, not lexically.

    Plain sorted() puts `v1.3.8` after `v1.3.10` because "8" > "1" as a
    string — which silently selected the older prompt on the first run of this
    builder. Compare the digit groups as integers instead.
    """
    import re
    return [int(n) for n in re.findall(r"\d+", path.name)]


def main() -> int:
    prompts = sorted(SYSTEM.glob("1.system_prompt-v*.md"), key=version_key)
    schemas = sorted(SYSTEM.glob("2.layer3_schema_v*.md"), key=version_key)
    if not prompts or not schemas:
        sys.exit(f"No analysis prompt/schema found under {SYSTEM}")

    analysis_prompt, analysis_schema = prompts[-1], schemas[-1]
    print(f"Inheriting from:\n  {analysis_prompt.name}\n  {analysis_schema.name}\n")
    print("Wrote:")
    build_prompt(analysis_prompt, SYSTEM / "1.system_prompt-validation-v1.md")
    build_schema(analysis_schema, SYSTEM / "2.layer3_schema-validation-v1.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
