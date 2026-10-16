"""
generate_report.py — Build a full Mobile Security Assessment Report from a
folder of verdict JSON files.

Reads every *.json in --verdicts-dir (skipping the `_summary.json` aggregate),
groups them into the report layout used by the assessment template, and writes
a single self-contained HTML file to --output.

Usage:
    python generate_report.py \\
        --verdicts-dir storage/verdicts/diva/ \\
        --output storage/output/diva-report.html

    # Optionally pass a title or generation timestamp override:
    python generate_report.py \\
        --verdicts-dir storage/verdicts/diva/ \\
        --output report.html \\
        --apk-name DIVA-1.0 \\
        --title "DIVA APK Security Assessment"

Verdict JSON shape (per file):
    {
        "test_id": "MASTG-TEST-0001",      # required
        "verdict": "fail",                  # fail|pass|partial_static_only|requires_dynamic_testing|not_applicable|inconclusive
        "certainty_percent": 95,            # int 0-100
        "evidence_table": [
            {"id": "stor-014", "level": "L1", "description": "...", "reference": "storage_usage.json#stor-014"},
            ...
        ],
        "rationale": "...",                 # client-readable explanation
        "mapped_maswe": ["MASWE-0001"],     # optional
        "needs_dynamic_testing": false,     # optional
        "false_positive_risks": [...],      # optional
        # Some pipelines add a friendly case_id / title; we fall back to filename if missing.
        "case_id": "STORAGE-1-1",           # optional, derived from filename if absent
        "title": "Sensitive Data in Local Storage",  # optional
    }
"""

from __future__ import annotations

import argparse
import ujson
import re
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path


# ============================================================
#  Verdict → CSS class + label mapping
# ============================================================

# Keys are normalised verdict strings (lowercase, underscored). Values are
# (css_class, display_label) tuples. The CSS classes match the template's
# stylesheet so existing styles apply unchanged.
VERDICT_STYLES: dict[str, tuple[str, str]] = {
    "fail": ("fail", "fail"),
    "pass": ("pass", "pass"),
    "partial": ("partial", "partial static only"),
    "partial_static_only": ("partial", "partial static only"),
    "requires_dynamic_testing": ("dynamic", "requires dynamic testing"),
    "dynamic": ("dynamic", "requires dynamic testing"),
    "not_applicable": ("na", "not applicable"),
    "na": ("na", "not applicable"),
    "n/a": ("na", "not applicable"),
    "inconclusive": ("partial", "inconclusive"),
}

# How a verdict string contributes to summary metrics.
SUMMARY_BUCKETS = {
    "fail": "fail",
    "pass": "pass",
    "partial": "partial",
    "partial_static_only": "partial",
    "requires_dynamic_testing": "partial",
    "dynamic": "partial",
    "not_applicable": "na",
    "na": "na",
    "n/a": "na",
    "inconclusive": "partial",
}


def normalise_verdict(v: str | None) -> str:
    if not v:
        return "inconclusive"
    return str(v).strip().lower().replace("-", "_").replace(" ", "_")


def normalise_certainty(v: str) -> int:
    if v == "No-LLM" or v == "Non-LLM":
        return 100
    
    if not v:
        return 0
    
    return int(v)

# ============================================================
#  Filename → case ID helpers
# ============================================================

# Filenames follow patterns like '1-STORAGE-1-1.md.json' or 'STORAGE-1-1.json'.
# The case id is the dash-separated category and indices.
CASE_ID_FROM_NAME_RE = re.compile(
    r"^(?:\d+-)?"                    # optional ordering prefix like "1-"
    r"(?P<case>[A-Z]+(?:-\d+)+)"     # CATEGORY-X-Y or CATEGORY-X-Y-alt
    r"(?:\.[A-Za-z]+)?"               # optional sub-extension like ".md"
    r"$"
)


def derive_case_id(verdict_data: dict, json_path: Path) -> str:
    """Determine the friendly case ID. Prefer an explicit field; else parse
    the filename; else fall back to test_id."""
    if verdict_data.get("case_id"):
        return verdict_data["case_id"]
    # Strip extensions like '.json' and '.md.json'
    stem = json_path.name
    for ext in (".json", ".md"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
    m = CASE_ID_FROM_NAME_RE.match(stem)
    if m:
        return m.group("case")
    # Last resort
    return verdict_data.get("test_id") or stem


# ============================================================
#  Title inference
# ============================================================

# Lookup table for MASTG test IDs → human-readable titles. Derived from the
# template; extend as needed.
KNOWN_TITLES: dict[str, str] = {
    "MASTG-TEST-0001": "Sensitive Data in Local Storage",
    "MASTG-TEST-0003": "Sensitive Data in Logs",
    "MASTG-TEST-0006": "Keyboard Cache Disabled for Sensitive Inputs",
    "MASTG-TEST-0007": "Content Provider Exposure and Query Hardening",
    "MASTG-TEST-0013": "Testing Symmetric Cryptography",
    "MASTG-TEST-0014": "Cryptographic Standard Algorithm Configuration",
    "MASTG-TEST-0015": "Purposes of Cryptographic Keys",
    "MASTG-TEST-0019": "Data Encryption on the Network",
    "MASTG-TEST-0020": "TLS Settings",
    "MASTG-TEST-0021": "Endpoint Identity Verification",
    "MASTG-TEST-0025": "Injection Flaws in Content Providers",
    "MASTG-TEST-0027": "Arbitrary URL Loading / Redirects in WebViews",
    "MASTG-TEST-0028": "Deep Links",
    "MASTG-TEST-0029": "Sensitive Functionality Exposure Through IPC",
    "MASTG-TEST-0030": "PendingIntent Implementation",
    "MASTG-TEST-0031": "JavaScript Execution in WebViews",
    "MASTG-TEST-0032": "WebView Protocol Handlers",
    "MASTG-TEST-0042": "Known Vulnerabilities in Third-party Components",
    "MASTG-TEST-0044": "Compiler Security Features",
    "MASTG-TEST-0046": "App Signing — v1-only / Janus",
    "MASTG-TEST-0062": "Cryptographic Key Management",
    "CODE-1-1": "Up-to-date targetSdkVersion",
}


def derive_title(verdict_data: dict) -> str:
    if verdict_data.get("title"):
        return verdict_data["title"]
    test_id = verdict_data.get("test_id") or ""
    if test_id in KNOWN_TITLES:
        return KNOWN_TITLES[test_id]
    return test_id or "Untitled assessment"


# ============================================================
#  Sorting — preserve a sensible order across categories
# ============================================================

CATEGORY_ORDER = [
    "STORAGE", "CRYPTO", "AUTH", "NETWORK", "PLATFORM", "CODE", "RESILIENCE",
    "PRIVACY", "AUTHENTICATION",
]


def sort_key(case_id: str) -> tuple:
    """Sort by category index, then numerically within category."""
    parts = case_id.split("-")
    category = parts[0]
    cat_idx = (CATEGORY_ORDER.index(category) if category in CATEGORY_ORDER
               else len(CATEGORY_ORDER) + 1)
    # Convert remaining parts to integers when possible for natural ordering
    nums = []
    for p in parts[1:]:
        try:
            nums.append((0, int(p)))
        except ValueError:
            nums.append((1, p))
    return (cat_idx, category, *nums)


# ============================================================
#  HTML generation
# ============================================================

def render_badges(verdict_data: dict) -> str:
    """Build the badges HTML for one case. Includes verdict + certainty +
    optional 'dynamic follow-up' tag when needs_dynamic_testing is true."""
    parts = []
    v_norm = normalise_verdict(verdict_data.get("verdict"))
    c_norm = normalise_certainty(verdict_data.get("certainty_percent"))
    css_class, label = VERDICT_STYLES.get(v_norm, ("partial", v_norm))
    parts.append(f'<span class="badge {css_class}">{escape(label)}</span>')

    certainty = c_norm
    if certainty is not None:
        parts.append(
            f'<span class="badge cert">{(certainty)}% certainty</span>'
        )

    # Surface a dynamic-follow-up flag in addition to the main verdict, when
    # the verdict is partial/static-only AND the test still needs dynamic.
    needs_dynamic = bool(verdict_data.get("needs_dynamic_testing"))
    if needs_dynamic and v_norm != "requires_dynamic_testing":
        parts.append('<span class="badge dynamic">dynamic follow-up</span>')

    return "".join(parts)


def render_evidence_row(row: dict) -> str:
    rid = escape(str(row.get("id", "")))
    level = escape(str(row.get("level", "")))
    description = escape(str(row.get("description", "")))
    reference = escape(str(row.get("reference", "")))
    return (
        "<tr>"
        f'<td class="ref">{rid}</td>'
        f'<td class="level">{level}</td>'
        f"<td>{description}</td>"
        f'<td class="ref">{reference}</td>'
        "</tr>"
    )


def render_evidence_table(verdict_data: dict) -> str:
    rows = verdict_data.get("evidence_table") or []
    if not rows:
        return '<p class="meta"><em>No evidence rows.</em></p>'
    body_rows = "".join(render_evidence_row(r) for r in rows)
    return (
        '<h3>Evidence table</h3>'
        '<div class="table-wrap"><table>'
        '<thead><tr><th>ID</th><th>Level</th><th>Description</th>'
        '<th>Reference</th></tr></thead>'
        f'<tbody>{body_rows}</tbody>'
        '</table></div>'
    )


def render_meta_line(verdict_data: dict) -> str:
    """The small grey 'MASTG-TEST-XXXX · MASWE: ...' line under the title."""
    pieces = []
    test_id = verdict_data.get("test_id")
    if test_id:
        pieces.append(escape(test_id))
    maswe = verdict_data.get("mapped_maswe") or []
    if maswe:
        pieces.append("MASWE: " + escape(", ".join(maswe)))
    return " · ".join(pieces)


def render_case(case_idx: int, case_id: str, verdict_data: dict) -> str:
    title = derive_title(verdict_data)
    rationale = (verdict_data.get("rationale")
                 or "No rationale provided.")
    explain = (
        '<div class="explain"><strong>Client-readable explanation:</strong>'
        f"<br>{escape(rationale)}</div>"
    )
    return (
        f'<section class="case" id="case-{case_idx}">'
        '<div class="case-head"><div>'
        f'<h2>{escape(case_id)} — {escape(title)}</h2>'
        f'<div class="meta">{render_meta_line(verdict_data)}</div>'
        '</div>'
        f'<div class="badges">{render_badges(verdict_data)}</div>'
        '</div>'
        f'<div class="body">{explain}{render_evidence_table(verdict_data)}'
        '</div></section>'
    )


def render_toc(cases: list[tuple[int, str, dict]]) -> str:
    """Index of all cases at the top of the report."""
    items = []
    for idx, case_id, vd in cases:
        v_norm = normalise_verdict(vd.get("verdict"))
        css_class, label = VERDICT_STYLES.get(v_norm, ("partial", v_norm))
        title = derive_title(vd)
        items.append(
            f'<div><a href="#case-{idx}">{escape(case_id)}</a> '
            f'<span class="badge {css_class}">{escape(label)}</span><br>'
            f'<small>{escape(title)}</small></div>'
        )
    return (
        '<section class="toc"><h2>Assessment index</h2>'
        f'<div class="toc-grid">{"".join(items)}</div></section>'
    )


def render_summary_metrics(cases: list[tuple[int, str, dict]]) -> str:
    """Top metric cards: total / fail / pass / partial / na."""
    counts = {"fail": 0, "pass": 0, "partial": 0, "na": 0}
    for _, _, vd in cases:
        bucket = SUMMARY_BUCKETS.get(normalise_verdict(vd.get("verdict")),
                                      "partial")
        counts[bucket] = counts.get(bucket, 0) + 1
    metrics = [
        ("Total cases", len(cases)),
        ("Fail", counts["fail"]),
        ("Pass", counts["pass"]),
        ("Partial / Dynamic", counts["partial"]),
        ("Not applicable", counts["na"]),
    ]
    cards = "".join(
        f'<div class="metric"><div class="n">{n}</div>'
        f'<div class="l">{escape(label)}</div></div>'
        for label, n in metrics
    )
    return f'<section class="summary">{cards}</section>'


# ============================================================
#  Stylesheet (inlined from the template — kept verbatim so visual output
#  matches the reference exactly)
# ============================================================

STYLESHEET = """
:root{--bg:#f6f8fb;--card:#fff;--text:#172033;--muted:#667085;--line:#e7edf5;--blue:#244a8f;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;color:var(--text);line-height:1.45}
.hero{background:linear-gradient(135deg,#12264d,#244a8f 58%,#5b7fc7);color:#fff;padding:36px 44px}
.hero h1{margin:0 0 8px;font-size:30px}.hero p{margin:0;color:#dbe7ff;max-width:980px}
.wrap{padding:28px 44px 48px;max-width:1440px;margin:auto}
.summary{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:14px;margin-top:-46px;margin-bottom:24px}
.metric{background:#fff;border-radius:16px;padding:18px 18px;box-shadow:0 10px 28px rgba(22,34,66,.12);border:1px solid rgba(255,255,255,.7)}
.metric .n{font-size:26px;font-weight:800}.metric .l{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.05em}
.toc{background:#fff;border:1px solid var(--line);border-radius:16px;padding:18px 20px;margin-bottom:24px}
.toc h2{margin:0 0 10px;font-size:18px}.toc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px 16px}
.toc a{color:#244a8f;text-decoration:none;font-weight:600}.toc small{color:var(--muted)}
.case{background:var(--card);border:1px solid var(--line);border-radius:18px;margin:18px 0;overflow:hidden;box-shadow:0 2px 12px rgba(20,32,56,.04)}
.case-head{padding:20px 22px;border-bottom:1px solid var(--line);display:flex;gap:16px;justify-content:space-between;align-items:flex-start}
.case h2{font-size:20px;margin:0 0 6px}.meta{color:var(--muted);font-size:13px}.badges{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.badge{border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
.pass{background:#dcfae6;color:#067647}.fail{background:#fee4e2;color:#b42318}.partial{background:#fef0c7;color:#b54708}.dynamic{background:#e0e7ff;color:#3538cd}.na{background:#eaecf0;color:#475467}
.cert{background:#eef4ff;color:#244a8f}
.body{padding:20px 22px}.explain{background:#f8fbff;border-left:4px solid #5b7fc7;padding:14px 16px;border-radius:10px;margin-bottom:16px}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}
table{width:100%;border-collapse:collapse;min-width:900px}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
th{background:#f4f7fb;color:#344054;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}.ref{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:#344054}
.level{font-weight:800;color:#244a8f}.footer{color:var(--muted);font-size:12px;margin-top:28px}
@media print{.hero{padding:24px 28px}.wrap{padding:18px 28px}.case{break-inside:avoid}.summary{margin-top:0}.toc{display:none}body{background:white}}
"""


def build_full_html(
    cases: list[tuple[int, str, dict]],
    *,
    title: str,
    apk_name: str | None,
    generated_at: str,
) -> str:
    hero_subtitle = (
        f"Client-facing summary of MASVS / MASTG evaluation case assessments "
        f"for {escape(apk_name) if apk_name else 'the analyzed Android APK'}. "
        f"Generated {escape(generated_at)}."
    )
    summary = render_summary_metrics(cases)
    toc = render_toc(cases)
    case_html = "".join(render_case(i, cid, vd) for i, cid, vd in cases)
    footer = (
        '<div class="footer"><p>Notes: Level 1 evidence refers to structured '
        'extractor output. Level 2 evidence refers to corroborating source/'
        'resource references such as JADX or apktool file paths and line '
        'ranges. Generated automatically from per-test verdict JSON files.</p>'
        '</div>'
    )

    return (
        '<!doctype html>'
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{escape(title)}</title>'
        f'<style>{STYLESHEET}</style></head><body>'
        f'<section class="hero"><h1>{escape(title)}</h1>'
        f'<p>{hero_subtitle}</p></section>'
        '<main class="wrap">'
        f'{summary}{toc}{case_html}{footer}'
        '</main></body></html>'
    )


# ============================================================
#  Verdict loading
# ============================================================

def load_verdicts(verdicts_dir: Path) -> list[tuple[str, dict, Path]]:
    """Read every *.json under verdicts_dir except _summary.json. Returns
    (case_id, verdict_data, source_path) tuples."""
    out: list[tuple[str, dict, Path]] = []
    for p in sorted(verdicts_dir.rglob("*.json")):
        if p.name == "_summary.json":
            continue
        try:
            data =ujson.loads(p.read_text(encoding="utf-8"))
        except ujson.JSONDecodeError as e:
            print(f"  ⚠ Skipping {p.name}: invalid JSON ({e})",
                  file=sys.stderr)
            continue
        if not isinstance(data, dict):
            print(f"  ⚠ Skipping {p.name}: top-level is not an object",
                  file=sys.stderr)
            continue
        case_id = derive_case_id(data, p)
        out.append((case_id, data, p))
    return out


# ============================================================
#  Main
# ============================================================

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a full HTML evaluation report from a folder of "
                    "verdict JSON files."
    )
    ap.add_argument("--verdicts-dir", required=True, type=Path,
                    help="Folder containing per-test verdict *.json files.")
    ap.add_argument("--output", required=True, type=Path,
                    help="Path for the generated HTML report.")
    ap.add_argument("--title", default="Mobile Security Assessment Report",
                    help="Report title (also used in <title> and the hero "
                         "section).")
    ap.add_argument("--apk-name", default=None,
                    help="Optional APK identifier shown in the hero subtitle.")
    ap.add_argument("--generated-at", default=None,
                    help="Override the generation timestamp shown in the "
                         "report. Defaults to current UTC.")
    args = ap.parse_args()

    if not args.verdicts_dir.is_dir():
        sys.exit(f"Verdicts directory not found: {args.verdicts_dir}")

    verdicts = load_verdicts(args.verdicts_dir)
    if not verdicts:
        sys.exit(f"No usable verdict files found in {args.verdicts_dir}")

    # Sort and number the cases. Numbering is what powers #case-N anchors.
    verdicts.sort(key=lambda t: sort_key(t[0]))
    cases = [(i + 1, case_id, vd) for i, (case_id, vd, _)
             in enumerate(verdicts)]

    generated_at = (
        args.generated_at
        or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    html = build_full_html(
        cases,
        title=args.title,
        apk_name=args.apk_name,
        generated_at=generated_at,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html, encoding="utf-8")

    print(f"✓ Report written to {args.output} "
          f"({len(cases)} cases, "
          f"{sum(1 for _, _, vd in cases if normalise_verdict(vd.get('verdict')) == 'fail')} failing)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())