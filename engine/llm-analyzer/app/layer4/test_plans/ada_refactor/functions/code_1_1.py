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

    print(str(evidence_dir) + "/app_metadata.json")

    with open(str(evidence_dir) + "/app_metadata.json") as json_data:
        app_metadata = ujson.load(json_data)
    
    apk_sdk = int(app_metadata['app']['target_sdk'])
    print(apk_sdk)

    if (apk_sdk <= latest_sdk - 3): 
        verdict = "FAIL" 
    else: 
        verdict = "PASS" 

    result['verdict'] = verdict

    test_case_description = f"The targetSdkVersion in the AndroidManifest is {apk_sdk}, while the latest SDK version is {latest_sdk}. "
    if (verdict == "FAIL"):
        test_case_description = test_case_description + f"This particular target SDK version is {latest_sdk - apk_sdk} less than the latest SDK version, which goes against this particular provision. The minimum required as per this particular evaluation case is {latest_sdk - 2}. Therefore, the verdict is set to FAIL."
    else:
        test_case_description = test_case_description + f"This particular target SDK is more than {latest_sdk - 2}, which is the minimum required as per this particular evaluation case. Therefore, its verdit is set to PASS."

    result['evidence_table'].append(
        {
                "id": "app-001",
                "description": (
                    f"The targetSdkVersion of this APK is {apk_sdk}"
                ),
                "reference": "app_metadata#app.target_sdk",
                "level": 1,
            },
    )

    result['rationale'] = test_case_description

    print(result)
    
    return result