# Intentionally empty.
#
# This package previously did:
#     from app.layer2.coordinator import run_extraction_sync
#     from . import androguard_runner
#
# which meant importing ANYTHING under app.layer2 — even just the JadxResult
# dataclass — pulled in androguard_runner and therefore `androguard` itself.
# That made dataclass-only consumers pay for a heavy optional dependency:
# build_evidence.py could not reconstruct a JadxResult from an existing
# artifact directory on a machine without androguard installed, even though
# rebuilding crypto_usage.json needs no extraction tool at all.
#
# Nothing imported the re-exports (every caller uses the submodule path,
# `from app.layer2.coordinator import run_extraction_sync`), and the file also
# held a dead `if __name__ == "__init__":` demo block — that condition is never
# true, since a package's __name__ is its dotted name.
#
# Same reasoning as app/__init__.py and app/layer4/__init__.py, both emptied
# for the same reason. See TODO F8 for the one remaining instance,
# app/layer4/backends/__init__.py, which still forces google-genai on
# OpenAI-only users.
