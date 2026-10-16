"""MASTG-TEST-0224: Usage of Insecure APK Signature Version.

Deterministic check over app_metadata.json (Layer 3 / apksigner), so this is
a programmatic handler rather than an LLM prompt.

OWASP evaluation: the test fails if the app has minSdkVersion >= 24 AND only
the v1 (JAR) signature scheme is enabled. v1-only signing is vulnerable to
CVE-2017-13156 (Janus). v2+ schemes cover the whole APK.

Verdict:
  * ``fail``         - min_sdk >= 24 and the only verified scheme is v1.
  * ``pass``         - a v2-or-higher scheme is verified, OR min_sdk < 24
                       (the test's failing condition does not apply).
  * ``inconclusive`` - apksigner did not run / the APK is unsigned / no
                       scheme data is available.

signing_schemes records look like:
    [{"version": "1", "verified": true}, {"version": "2", "verified": false}]
(SourceStamp is an auxiliary stamp, not a primary scheme - excluded.)
"""
import json
from pathlib import Path

TEST_ID = "MASTG-TEST-0224"


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for MASTG-TEST-0224 (insecure APK signature version)."""
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
                "evidence_table": [{
                    "id": "sigv-err",
                    "description": "app_metadata.json not found; signing scheme "
                                   "and minSdkVersion could not be determined.",
                    "reference": "app_metadata.json", "level": 1}],
                "rationale": "No app_metadata.json was produced; the APK signing "
                             "version is undetermined."}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "sigv-err",
                    "description": f"Could not parse app_metadata.json: {exc}.",
                    "reference": "app_metadata.json", "level": 1}],
                "rationale": f"app_metadata.json could not be parsed ({exc})."}

    min_sdk = data.get("min_sdk")
    schemes = data.get("signing_schemes") or []

    verified_versions: list[str] = []
    has_v2_or_higher = False
    for s in schemes:
        if not s.get("verified", False):
            continue
        v = s.get("version")
        verified_versions.append(str(v))
        if v == "SourceStamp":
            continue
        try:
            if float(v) >= 2.0:
                has_v2_or_higher = True
        except (TypeError, ValueError):
            continue

    numeric_verified = [v for v in verified_versions if v != "SourceStamp"]

    # No scheme data at all -> apksigner unavailable / unsigned.
    if not numeric_verified:
        return {**base, "verdict": "inconclusive",
                "evidence_table": [{"id": "sigv-000",
                    "description": (f"No verified signature scheme reported "
                                    f"(minSdkVersion={min_sdk}); the APK appears "
                                    f"unsigned or apksigner did not run."),
                    "reference": "app_metadata.json#signing_schemes", "level": 1}],
                "rationale": ("No verified signing scheme is available, so the "
                              "signature-version requirement cannot be evaluated "
                              "(unsigned APK or apksigner unavailable).")}

    v1_only = ("1" in numeric_verified) and not has_v2_or_higher
    min_sdk_ge_24 = isinstance(min_sdk, int) and min_sdk >= 24

    evidence_table = [{
        "id": "sigv-001",
        "description": (f"Verified signature schemes: {numeric_verified}. "
                        f"minSdkVersion={min_sdk}."),
        "reference": "app_metadata.json#signing_schemes",
        "level": 1,
    }]

    if v1_only and min_sdk_ge_24:
        verdict = "fail"
        rationale = (f"The APK is signed only with the v1 (JAR) scheme "
                     f"(verified schemes: {numeric_verified}) and minSdkVersion "
                     f"is {min_sdk} (>= 24). v1-only signing is vulnerable to "
                     f"CVE-2017-13156 (Janus); MASTG-TEST-0224 fails.")
    elif v1_only and not min_sdk_ge_24:
        verdict = "pass"
        rationale = (f"The APK is v1-only (verified: {numeric_verified}) but "
                     f"minSdkVersion is {min_sdk} (< 24), so the test's failing "
                     f"condition (minSdk>=24 AND v1-only) does not apply. "
                     f"MASTG-TEST-0224 passes (note: v2+ is still recommended).")
    else:
        verdict = "pass"
        rationale = (f"The APK is signed with a v2-or-higher scheme (verified: "
                     f"{numeric_verified}), which covers the whole APK. "
                     f"MASTG-TEST-0224 passes.")

    return {**base, "verdict": verdict, "evidence_table": evidence_table,
            "rationale": rationale}
