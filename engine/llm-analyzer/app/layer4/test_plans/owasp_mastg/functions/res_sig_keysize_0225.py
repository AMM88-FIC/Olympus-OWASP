"""MASTG-TEST-0225: Usage of Insecure APK Signature Key Size.

Deterministic check over app_metadata.json (Layer 3 / apksigner), so this is
a programmatic handler rather than an LLM prompt.

OWASP evaluation: the test fails if any signer key size is below 2048 bits for
RSA (e.g. 1024-bit RSA). A short signing key weakens the integrity/authenticity
of the APK and could let an attacker forge signatures.

The Layer 3 app_metadata builder records each signer under ``certificates`` as
``{key_algorithm, key_size_bits, ...}`` (from apksigner).

Verdict:
  * ``fail``         - at least one RSA (or DSA) signer key is < 2048 bits.
  * ``pass``         - every signer key meets its minimum (RSA/DSA >= 2048;
                       EC curves >= 224 bits are adequate).
  * ``inconclusive`` - no certificates / key sizes available (unsigned APK or
                       apksigner did not run).
"""
import json
from pathlib import Path

TEST_ID = "MASTG-TEST-0225"

# Minimum acceptable signing-key size by algorithm family (bits).
_MIN_BITS = {"RSA": 2048, "DSA": 2048, "EC": 224, "ECDSA": 224}


def _algo_family(algo: str) -> str:
    a = (algo or "").upper()
    if "RSA" in a:
        return "RSA"
    if "EC" in a or "ECDSA" in a:
        return "EC"
    if "DSA" in a:
        return "DSA"
    return a or "UNKNOWN"


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for MASTG-TEST-0225 (insecure APK signature key size)."""
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / "app_metadata.json"

    base = {
        "test_id": TEST_ID,
        "certainty_percent": "No-LLM",
        "needs_dynamic_testing": False,
        "false_positive_risks": [],
    }

    if not path.is_file():
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "sigk-err",
                    "description": "app_metadata.json not found; signer key "
                                   "sizes could not be determined.",
                    "reference": "app_metadata.json", "level": 1}],
                "rationale": "No app_metadata.json was produced; signer key "
                             "size is undetermined."}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "sigk-err",
                    "description": f"Could not parse app_metadata.json: {exc}.",
                    "reference": "app_metadata.json", "level": 1}],
                "rationale": f"app_metadata.json could not be parsed ({exc})."}

    certs = data.get("certificates") or []
    if not certs:
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "sigk-000",
                    "description": "No signer certificates reported; the APK "
                                   "appears unsigned or apksigner did not run.",
                    "reference": "app_metadata.json#certificates", "level": 1}],
                "rationale": "No signer certificate / key size is available, so "
                             "the signature key size cannot be evaluated "
                             "(unsigned APK or apksigner unavailable)."}

    evidence_table = []
    findings = []      # (idx, algo, bits, minimum)
    evaluated = 0
    for i, cert in enumerate(certs, 1):
        algo = cert.get("key_algorithm")
        bits = cert.get("key_size_bits")
        idx = cert.get("signer_index", i)
        if not isinstance(bits, int):
            evidence_table.append({
                "id": f"sigk-u{i}",
                "description": (f"Signer #{idx}: key size not reported "
                                f"(algorithm={algo}); cannot evaluate."),
                "reference": "app_metadata.json#certificates", "level": 1})
            continue
        evaluated += 1
        fam = _algo_family(algo)
        minimum = _MIN_BITS.get(fam, 2048)
        ok = bits >= minimum
        evidence_table.append({
            "id": f"sigk-{i:03d}",
            "description": (f"Signer #{idx} key: {algo} {bits}-bit "
                            f"(minimum {minimum}). "
                            f"{'OK' if ok else 'INSUFFICIENT'}."),
            "reference": "app_metadata.json#certificates", "level": 1})
        if not ok:
            findings.append((idx, algo, bits, minimum))

    if evaluated == 0:
        return {**base, "verdict": "inconclusive",
                "evidence_table": evidence_table,
                "rationale": "Signer certificates are present but none report a "
                             "key size; signature key size is undetermined."}

    if findings:
        verdict = "fail"
        names = "; ".join(f"Signer #{idx} {algo} {bits}-bit (< {m})"
                          for idx, algo, bits, m in findings)
        rationale = (f"{len(findings)} signer key(s) below the minimum size: "
                     f"{names}. A signing key shorter than 2048 bits (RSA/DSA) "
                     f"weakens the APK's integrity/authenticity; "
                     f"MASTG-TEST-0225 fails.")
    else:
        verdict = "pass"
        rationale = (f"All {evaluated} signer key(s) meet the minimum size "
                     f"(RSA/DSA >= 2048, EC >= 224). MASTG-TEST-0225 passes.")

    return {**base, "verdict": verdict, "evidence_table": evidence_table,
            "rationale": rationale}
