#!/usr/bin/env python3
"""
Review an Olympus control result with the LLM.

    olympus run | python3 olympus_review.py

Reads Olympus output on stdin, prints the review verdict JSON on stdout.
Logs go to stderr. Exit code 0 on a verdict, 1 otherwise.
"""

import contextlib
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

# ============================================================
#  CONFIG
# ============================================================

BACKEND  = "gemini"
MODEL    = "gemini-2.5-pro"
API_KEY  = os.environ.get("GEMINI_API_KEY", "")

APK_ROOT  = REPO / "storage/artifacts/xiaomi-explorer"
TEST_PLAN = REPO / "app/layer4/test_plans/owasp_mastg"
SYSTEM_PROMPT = REPO / "app/layer4/prompts/system/1.system_prompt-validation-v1.md"
SCHEMA        = REPO / "app/layer4/prompts/system/2.layer3_schema-validation-v1.md"

# Olympus control id -> MASTG test id. Add controls here as they are mapped.
CONTROL_TO_TEST = {
    "1.1.2.1": "MASTG-TEST-0258",   # Keyboard Cache Audit
    "1.5.1.1": "MASTG-TEST-0355",   # Content Provider Exposure
}

# ============================================================


def main() -> int:
    olympus_output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", sys.stdin.read())

    m = re.search(r"Control\s+(\d+(?:\.\d+)+)", olympus_output)
    if not m:
        print("error: no 'Control <id>' found in input", file=sys.stderr)
        return 1
    test_id = CONTROL_TO_TEST.get(m.group(1))
    if not test_id:
        print(f"error: control {m.group(1)} is not mapped in CONTROL_TO_TEST",
              file=sys.stderr)
        return 1

    # Everything the engine or an SDK prints goes to stderr, so stdout carries
    # only the verdict and stays pipeable.
    with contextlib.redirect_stdout(sys.stderr):
        from app.engine_api import EngineSettings
        engine = EngineSettings.from_dict({
            "backend": BACKEND,
            "model": MODEL,
            "api_key": API_KEY,
            "system_prompt": SYSTEM_PROMPT,
            "schema": SCHEMA,
        }).for_apk(APK_ROOT, test_plan_dir=TEST_PLAN)
        result = engine.validate(test_id, olympus_output)

    if not result.full_verdict:
        print(f"error: no verdict ({result.status}: {result.error})",
              file=sys.stderr)
        return 1

    print(json.dumps(result.full_verdict, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
