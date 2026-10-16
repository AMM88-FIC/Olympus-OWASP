"""
RESILIENCE-1-1: Verify the APK is signed with APK Signature Scheme v2 or
higher.

v1-only (JAR) signing is vulnerable to the Janus exploit (CVE-2017-13156)
which allowed arbitrary DEX prepending on Android < 7.0. Modern apps
should use v2 or higher; v3+ adds key rotation and v4 adds streamed
verification for incremental updates.

This is a deterministic check against the data apksigner produced during
L2 extraction (now stored in app_metadata.signing_schemes). No model
reasoning needed.
"""
import json
from pathlib import Path


def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for RESILIENCE-1-1."""

    with open(evidence_dir / "app_metadata.json") as f:
        app_metadata = json.load(f)

    # signing_schemes is a list of records like:
    #   [{"version": "1", "verified": true},
    #    {"version": "2", "verified": false}, ...]
    schemes = app_metadata.get("signing_schemes") or []

    # Collect every scheme that verified, separating numeric versions
    # from SourceStamp (which is an auxiliary stamping mechanism, not a
    # primary signing scheme — exclude from the v1-only check).
    verified_versions: list[str] = []
    has_v2_or_higher = False
    for scheme in schemes:
        version = scheme.get("version")
        verified = scheme.get("verified", False)
        if not verified:
            continue
        verified_versions.append(version)
        if version == "SourceStamp":
            continue
        # version is a string like "1", "2", "3", "3.1", "4". Compare as
        # float to handle the "3.1" case correctly. Strings like
        # "SourceStamp" already excluded above.
        try:
            if float(version) >= 2.0:
                has_v2_or_higher = True
        except (TypeError, ValueError):
            # Unknown version label — skip rather than crash. This is
            # defensive; current apksigner versions only produce the
            # values listed above.
            continue

    verdict = "pass" if has_v2_or_higher else "fail"

    # Build the rationale text. The three branches cover: unsigned,
    # v1-only, and the pass case.
    if not verified_versions:
        rationale = (
            "The APK is not signed under any signature scheme. apksigner "
            "reported zero verified schemes, indicating the APK is "
            "unsigned or its signatures could not be validated. "
            "RESILIENCE-1-1 requires v2 or higher; this APK fails."
        )
    elif not has_v2_or_higher:
        rationale = (
            f"The APK is signed only under v1 (JAR signing). Verified "
            f"schemes: {verified_versions}. v1-only signing is vulnerable "
            f"to CVE-2017-13156 (Janus) on Android versions below 7.0 and "
            f"does not satisfy modern signing requirements. RESILIENCE-1-1 "
            f"requires v2 or higher; this APK fails."
        )
    else:
        rationale = (
            f"The APK is signed under one or more modern signature "
            f"schemes. Verified schemes: {verified_versions}. This "
            f"satisfies RESILIENCE-1-1's requirement of v2 or higher."
        )

    result = {
        "test_id": "RESILIENCE-1-1",
        "verdict": verdict,
        "certainty_percent": "No-LLM",
        "evidence_table": [
            {
                "id": "app-001",
                "description": (
                    f"Verified signing schemes for this APK: "
                    f"{verified_versions if verified_versions else 'none'}."
                ),
                "reference": "app_metadata.json#signing_schemes",
                "level": 1,
            },
        ],
        "rationale": rationale,
    }

    print(result)

    return result 