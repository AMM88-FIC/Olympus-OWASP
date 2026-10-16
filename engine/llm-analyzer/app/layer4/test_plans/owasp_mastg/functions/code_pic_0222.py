"""MASTG-TEST-0222: Position Independent Code (PIC) Not Enabled.

Deterministic check over the Layer 3 ``native_binaries.json`` evidence -
no model reasoning needed, so this is a programmatic handler rather than
an LLM prompt.

Background: since Android 5.0 (API 21) all dynamically linked executables
must be position independent (PIE). Shared objects (``.so``) are compiled
position-independently by definition - the ELF type is ``ET_DYN``, which
the Layer 3 native-binary builder records as
``security_features.pie = true``. A native library whose ``pie`` flag is
false was linked non-position-independent (e.g. ``ET_EXEC``) and fails
this control.

Verdict:
  * ``n/a``  - the app ships no native libraries (nothing to evaluate).
  * ``pass`` - every native library is position independent (pie=true).
  * ``fail`` - at least one native library has pie=false.

Records are de-duplicated by library name because the same library built
for several ABIs (arm64-v8a, armeabi-v7a, ...) appears once per ABI.
"""
import json
from pathlib import Path

TEST_ID = "MASTG-TEST-0222"


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for MASTG-TEST-0222 (PIC/PIE in native libs)."""
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / "native_binaries.json"

    base = {
        "test_id": TEST_ID,
        "certainty_percent": "No-LLM",
        "needs_dynamic_testing": False,
        "false_positive_risks": [],
    }

    if not path.is_file():
        return {
            **base,
            "verdict": "n/a",
            "evidence_table": [{
                "id": "pic-000",
                "description": (
                    "No native_binaries.json evidence found; the app appears "
                    "to ship no native libraries, so PIC/PIE does not apply."
                ),
                "reference": "native_binaries.json",
                "level": 1,
            }],
            "rationale": (
                "No native_binaries.json was produced for this job, indicating "
                "the APK contains no native libraries. MASTG-TEST-0222 (PIC) "
                "is not applicable."
            ),
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - surface as inconclusive, never crash the batch
        return {
            **base,
            "verdict": "inconclusive",
            "evidence_table": [{
                "id": "pic-err",
                "description": f"Could not parse native_binaries.json: {exc}.",
                "reference": "native_binaries.json",
                "level": 1,
            }],
            "rationale": (
                f"native_binaries.json could not be read/parsed ({exc}); "
                "PIC status is undetermined."
            ),
        }

    records = data.get("records") or []
    if not records:
        return {
            **base,
            "verdict": "n/a",
            "evidence_table": [{
                "id": "pic-000",
                "description": (
                    "native_binaries.json contains zero native-library "
                    "records; the app ships no native code."
                ),
                "reference": "native_binaries.json#records",
                "level": 1,
            }],
            "rationale": (
                "No native libraries are present (0 records). "
                "MASTG-TEST-0222 (PIC) is not applicable."
            ),
        }

    # De-duplicate by library name; keep the first record per name.
    seen: dict[str, dict] = {}
    for rec in records:
        name = rec.get("name") or (rec.get("paths") or ["<unknown>"])[0]
        if name not in seen:
            seen[name] = rec

    findings: list[tuple[str, dict]] = []   # (name, record) with pie=false
    compliant: list[str] = []
    for name, rec in seen.items():
        sf = rec.get("security_features") or {}
        if sf.get("pie", False):
            compliant.append(name)
        else:
            findings.append((name, rec))

    evidence_table: list[dict] = []
    for i, (name, rec) in enumerate(findings, 1):
        paths = rec.get("paths") or []
        abis = rec.get("abis") or []
        evidence_table.append({
            "id": f"pic-{i:03d}",
            "description": (
                f"Finding: native library '{name}' is NOT position "
                f"independent (security_features.pie = false), so PIC/PIE is "
                f"not enabled. ABIs: {abis or 'n/a'}."
            ),
            "reference": (
                f"native_binaries.json#records[{name}] "
                f"({paths[0] if paths else 'unknown path'})"
            ),
            "level": 1,
        })

    if compliant:
        evidence_table.append({
            "id": "pic-ok",
            "description": (
                f"{len(compliant)} native library/libraries are position "
                f"independent (pie=true): "
                f"{', '.join(sorted(compliant)[:20])}"
                f"{' ...' if len(compliant) > 20 else ''}."
            ),
            "reference": "native_binaries.json#records",
            "level": 1,
        })

    if findings:
        verdict = "fail"
        rationale = (
            f"{len(findings)} of {len(seen)} native library/libraries are not "
            f"position independent (pie=false): "
            f"{', '.join(n for n, _ in findings)}. Android requires PIE since "
            f"API 21; a non-PIC/PIE native binary fails MASTG-TEST-0222."
        )
    else:
        verdict = "pass"
        rationale = (
            f"All {len(seen)} native library/libraries are position "
            f"independent (security_features.pie = true). MASTG-TEST-0222 "
            f"(PIC) passes."
        )

    return {**base, "verdict": verdict, "evidence_table": evidence_table,
            "rationale": rationale}
