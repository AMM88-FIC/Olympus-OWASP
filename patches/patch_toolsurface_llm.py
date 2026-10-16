#!/usr/bin/env python3
"""Register the LLM analyzer plugin in Olympus's tool surface.

Idempotent, anchored, and backs up first. Re-run after the AppImage
re-extracts: toolsurface.py is a shipped file and is overwritten, while
gui_shared/llm_plugin.py is not.
"""
import pathlib, shutil, sys

p = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "tooling/toolsurface.py")
s = p.read_text(encoding="utf-8")
if "llm_plugin" in s:
    sys.exit("already patched: %s" % p)

BOOTSTRAP = '''
# ── the LLM analyzer plugin (optional) ───────────────────────────────────────
# Registered here rather than declared above so that an absent or misconfigured
# plugin costs the tool surface nothing: every existing tool behaves as before.
# The failure is REPORTED, though - a tool family that vanishes without a word
# is the hardest kind of bug to chase, and stderr from the tool server lands in
# the desktop's developer log.
try:
    from gui_shared import llm_plugin as _llm_plugin
    LLM, _LLM_SCHEMA, _LLM_COST, _LLM_SLOW = _llm_plugin.register(_S)
    SCHEMA.update(_LLM_SCHEMA)
    COST.update(_LLM_COST)
    SLOW.update(_LLM_SLOW)
    TOOLS.update(LLM)
except Exception as _llm_exc:                        # noqa: BLE001
    import sys as _sys, traceback as _tb
    print("llm_plugin NOT loaded: %s: %s" % (type(_llm_exc).__name__, _llm_exc),
          file=_sys.stderr)
    _tb.print_exc(file=_sys.stderr)
    LLM = {}


def schema(name):'''

ANCHOR = "\ndef schema(name):"
if s.count(ANCHOR) != 1:
    sys.exit("anchor 'def schema(name):' matched %d times - not patching" % s.count(ANCHOR))
s = s.replace(ANCHOR, BOOTSTRAP, 1)

ORDER_OLD = "    order = list(ORCHESTRATOR) + list(NAVIGATOR)"
if s.count(ORDER_OLD) != 1:
    sys.exit("anchor 'order = ...' matched %d times - not patching" % s.count(ORDER_OLD))
s = s.replace(ORDER_OLD, ORDER_OLD + " + list(LLM)", 1)

backup = p.with_suffix(p.suffix + ".pre-llm")
if not backup.exists():
    shutil.copy2(p, backup)
p.write_text(s, encoding="utf-8")
print("patched %s (backup: %s)" % (p, backup.name))
