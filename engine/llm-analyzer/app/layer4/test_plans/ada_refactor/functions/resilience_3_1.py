from pathlib import Path
import ujson

def run(job_id: str, evidence_dir: Path) -> dict:
    """Return a verdict for CODE-1-1.

    The dict shape mirrors the LLM-test output: every field the verdict
    engine writes to disk for an LLM run must also appear here, so
    downstream consumers (the report generator, etc.) can treat
    programmatic and LLM verdicts uniformly.
    """

    result = {
        "test_id": "CODE-1-1", 
        "verdict": "", 
        "certainty_percent": "Non-LLM",
        "evidence_table": [],
        "rationale": "",
        }

    # Latest stable Android API level.
    # Last reviewed: 2026-05 (Android 16 = API 36).
    # Source: https://apilevels.com/
    # Refresh by: comparing the current latest to this value
    #             every 6 months; update if it advanced.

    latest_sdk = 36

    print(str(evidence_dir) + "/manifest_findings.json")

    with open(str(evidence_dir) + "/manifest_findings.json") as json_data:
        manifest_findings = ujson.load(json_data)
    
    debuggable_flag = bool(manifest_findings['flags']['debuggable'])

    if (debuggable_flag): 
        verdict = "FAIL" 
    else: 
        verdict = "PASS" 

    result['verdict'] = verdict

    test_case_description = f"The debuggable flag in the AndroidManifest is {debuggable_flag}, while the expected value for this particular test case is false. "
    if (verdict == "FAIL"):
        test_case_description = test_case_description + f"This particular application seems to be released with debuggable flag enabled, which goes against this particular provision. Therefore, the verdict is set to FAIL."
    else:
        test_case_description = test_case_description + f"This particular application seems to be released with debuggable flag disabled, which is the expected result for this particular provision. Therefore, the verdict is set to PASS."

    result['evidence_table'].append(
        {
                "id": "man-001",
                "description": (
                    f"The debuggable flag of this APK is set to {debuggable_flag}"
                ),
                "reference": "manifest_findings#flags.debuggable",
                "level": 1,
            },
    )

    result['rationale'] = test_case_description

    print(result)
    
    return result