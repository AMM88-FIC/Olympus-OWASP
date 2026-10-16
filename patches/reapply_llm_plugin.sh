#!/bin/sh
# Re-apply the LLM analyzer integration after an Olympus update or re-extraction.
#
# Shipped files are overwritten and must be re-patched:
#     tooling/toolsurface.py     registers the tool family
#     olympus_owasp_app.py       exports the AI panel's Gemini key
# Not shipped, so they survive:
#     gui_shared/llm_plugin.py   the plugin itself
#     ~/.config/olympus-owasp/llm_plugin.json
#     .venv/ and its packages
#
# Run from the app directory. Safe to run when nothing needs doing.
set -e
cd "$(dirname "$0")"
PY=.venv/bin/python3
[ -x "$PY" ] || PY=python3

"$PY" patch_toolsurface_llm.py tooling/toolsurface.py || true
"$PY" patch_llm_key.py olympus_owasp_app.py || true

"$PY" -c "
import sys; sys.path.insert(0, '.')
from tooling import toolsurface as T
names = sorted(n for n in T.TOOLS if n.startswith('llm_'))
print('llm tools registered:', names or 'NONE')
raise SystemExit(0 if names else 1)
"
