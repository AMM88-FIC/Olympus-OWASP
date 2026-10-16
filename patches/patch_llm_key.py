#!/usr/bin/env python3
"""Export the AI panel's Gemini key to this process, so the LLM plugin's child
processes inherit it. Idempotent; refuses rather than guesses. Backs up first."""
import pathlib, shutil, sys

p = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "olympus_owasp_app.py")
s = p.read_text(encoding="utf-8")
if "_ai_key_exported" in s:
    sys.exit("already patched: %s" % p)

CONNECT_OLD = """                backend.verify()
                GLib.idle_add(self._ai_connected, backend, name, None)"""
CONNECT_NEW = """                backend.verify()
                # The LLM analyzer plugin runs as a child process and needs this same
                # credential. The environment is the only channel that keeps the rule
                # stated above: memory only, inherited by children, never on disk.
                if name == "gemini":
                    os.environ["GEMINI_API_KEY"] = key
                    self._ai_key_exported = True
                GLib.idle_add(self._ai_connected, backend, name, None)"""

FORGET_OLD = """        self._ai_backend = None
        self._ai_loop = None
        self._ai_key.set_text("")"""
FORGET_NEW = """        self._ai_backend = None
        self._ai_loop = None
        # Only unset what we set: the operator may have exported the key themselves
        # before launching, and forgetting the session must not take that with it.
        if getattr(self, "_ai_key_exported", False):
            os.environ.pop("GEMINI_API_KEY", None)
            self._ai_key_exported = False
        self._ai_key.set_text("")"""

for old, new, label in ((CONNECT_OLD, CONNECT_NEW, "connect"),
                        (FORGET_OLD, FORGET_NEW, "forget")):
    n = s.count(old)
    if n != 1:
        sys.exit("anchor %r matched %d times, expected 1 - not patching" % (label, n))
    s = s.replace(old, new, 1)

backup = p.with_suffix(p.suffix + ".pre-llm-key")
if not backup.exists():
    shutil.copy2(p, backup)
p.write_text(s, encoding="utf-8")
print("patched %s (backup: %s)" % (p, backup.name))
