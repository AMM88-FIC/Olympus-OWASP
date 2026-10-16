"""
gui_shared/llm_plugin.py — the LLM Android Analyzer, as an Olympus tool family.

Everything Olympus knows about the analyzer lives here. Two tools reach the
wire, both through the ordinary tool surface, so the MCP server, the desktop's
orchestrator panel and a model's function-call loop all get them for free:

    llm_run_test(target, test_id)   the engine answers the test itself
    llm_review(target, test_id)     the engine checks what Olympus answered

They are alternatives, not a sequence. Reviewing the engine's own output would
be the engine grading itself.

HOW THE ENGINE RUNS. Verdicts run IN THIS PROCESS, evidence building runs as a
subprocess, and the split is not arbitrary.

One process is required for rate limiting: a `SharedRateLimiter` paces the
process it lives in, so an engine spawned per call gets a fresh limiter every
time and N concurrent calls can collectively overshoot. One 429 from Gemini
locks the key out for hours — across a batch of applications that is the
difference between slow and stopped. Importing the engine puts every call
behind one limiter.

It is affordable because `app.engine_api` and all of layer 4 import only the
standard library. `google-genai`, `ujson` and `openai` are pulled lazily when a
backend is built, so Olympus's venv needs exactly those three.

Evidence building stays a subprocess in the analyzer's own venv, because that
path needs androguard, and Olympus pins `androguard==4.1.3` precisely because
the pin sits in its own evidence path. Nothing from that tree is imported here.

If the engine cannot be imported, both tools fall back to the subprocess bridge
and `llm_status` says which mode is in force and why.

WHAT THIS DOES NOT DO. There is no `set_verdict` here, and these tools do not
write one. `llm_review` returns what the engine concluded beside what Olympus
delivered; reconciling the two is the report's job, not a model's. The absence
is the same guardrail `mcp_server` describes, kept deliberately.

CONFIGURATION lives in `~/.config/olympus-owasp/llm_plugin.json` — the plugin's
own file, NOT the desktop's `app.json`. The desktop reads app.json once at
startup and `_save_cfg` later writes that whole in-memory dict back, so keys
added to it while Olympus is running are silently overwritten (a window resize
is enough to trigger the save). `app.json` is still read when the file below is
absent, so an existing setup keeps working, but settings there are not durable.

    "llm_enabled":      false                     master switch
    "llm_home":         "/path/to/llm-android-analyzer"
    "llm_python":       ""                        default: <home>/.venv/bin/python3
    "llm_model":        "gemini-2.5-pro"
    "llm_artifacts":    ""                        default: ~/olympus-evidence
    "llm_api_key_file": ""                        headless only, see below
    "llm_in_process":   true                      false forces the subprocess
    "llm_tpm":          0                         0 = the engine's own tpm_limit
    "llm_rpm":          150                       run_parallel's default

`llm_status` reports which of these is missing, so a tool that will not run can
say why without anyone reading this file.

THE KEY, and why it is not a setting. The desktop's own comment on the AI panel
is explicit: the key lives in memory and nowhere else — not in app.json, not in
a file, not in the keyring — because that is what lets the product tell a client
"this tool stores no key". Nothing here changes that.

So the key arrives through this process's environment. The AI panel puts it
there when a Gemini backend connects, and the tool server inherits it at spawn;
launching Olympus from a shell that exported `GEMINI_API_KEY` does the same.
Either way it reaches the analyzer through the child's environment and never
through argv, which is world-readable in /proc.

`llm_api_key_file` exists only for headless use — a scheduled sweep with no
operator and no panel — and it is the operator's file to place and protect, not
one this tool writes. Leave it unset on a workstation.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import threading

APP_ID = "olympus-owasp"
_CONFIG_DIR = pathlib.Path(
    os.environ.get("XDG_CONFIG_HOME", pathlib.Path.home() / ".config")) / APP_ID

#: The plugin's own file, and the reason it is not `app.json`: the desktop reads
#: app.json ONCE at startup into `self._cfg` and `_save_cfg` later dumps that whole
#: dict back. Anything added to the file while the app is running is overwritten by
#: the copy it loaded before those keys existed — and a window resize is enough to
#: trigger the save. A separate file is never rewritten by the desktop, so it can be
#: edited at any time and survives.
CONFIG_PATH = _CONFIG_DIR / "llm_plugin.json"

#: Read only if the file above is absent, so an existing setup keeps working. Keys
#: placed here are NOT durable, for the reason given above.
LEGACY_CONFIG_PATH = _CONFIG_DIR / "app.json"

BRIDGE = "olympus_bridge.py"
EVIDENCE = "olympus_evidence.py"
DEFAULT_MODEL = "gemini-2.5-pro"
DEFAULT_ARTIFACTS = pathlib.Path.home() / "olympus-evidence"

_LOCK = threading.Lock()


# ── configuration ────────────────────────────────────────────────────────────

def _config() -> tuple[dict, pathlib.Path]:
    """(settings, the file they came from)."""
    for path in (CONFIG_PATH, LEGACY_CONFIG_PATH):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and any(k.startswith("llm_") for k in data):
            return data, path
    return {}, CONFIG_PATH


def _settings() -> dict:
    cfg, source = _config()
    home = str(cfg.get("llm_home") or "").strip()
    python = str(cfg.get("llm_python") or "").strip()
    tried = ""
    if home and not python:
        # A venv inside the analyzer's own directory is only the common case.
        # On a VirtualBox share it belongs outside it, so `llm_python` is the
        # setting that matters and this default is a convenience, not a rule.
        candidate = pathlib.Path(home) / ".venv" / "bin" / "python3"
        tried = str(candidate)
        python = str(candidate) if candidate.is_file() else ""
    return {
        "enabled": bool(cfg.get("llm_enabled", False)),
        "home": pathlib.Path(home) if home else None,
        "python": pathlib.Path(python) if python else None,
        "python_tried": tried,
        "model": str(cfg.get("llm_model") or DEFAULT_MODEL),
        "artifacts": pathlib.Path(str(cfg.get("llm_artifacts") or DEFAULT_ARTIFACTS)),
        "api_key_file": str(cfg.get("llm_api_key_file") or "").strip(),
        "in_process": bool(cfg.get("llm_in_process", True)),
        "tpm": int(cfg.get("llm_tpm") or 0),
        "rpm": int(cfg.get("llm_rpm") or 150),
        "source": source,
    }


def _api_key(s: dict | None = None) -> str:
    """The Gemini key: the environment first, then a file named in settings.

    A desktop launched from a menu inherits no shell exports, so `GEMINI_API_KEY`
    being set in the terminal where the CLI was tested says nothing about the
    GUI's environment. `llm_api_key_file` covers that without putting the key in
    a config file, a repository, or argv.
    """
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if key:
        return key
    path = (s or _settings())["api_key_file"]
    if path:
        try:
            return pathlib.Path(path).expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


#: Variables that must not reach a foreign interpreter. Olympus runs from an
#: AppImage whose AppRun exports PYTHONHOME (and usually LD_LIBRARY_PATH) so its
#: OWN bundled Python can start. Inherited by a different Python, PYTHONHOME
#: sends it looking for its standard library inside Olympus's bundle and it dies
#: with "Fatal Python error: Failed to import encodings module" before running a
#: line. LD_LIBRARY_PATH is the same hazard one layer down: the bundle ships its
#: own glibc and libpython.
_FOREIGN_UNSAFE = (
    "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE",
    "PYTHONUSERBASE", "PYTHONOPTIMIZE", "PYTHONDEBUG", "PYTHONNOUSERSITE",
    "VIRTUAL_ENV", "LD_LIBRARY_PATH", "LD_PRELOAD",
)


#: Keys the emit path itself binds. A payload carrying one of these does not
#: overwrite a field — it raises TypeError, because both ends pass them by name.
_EMIT_RESERVED = ("ev", "phase")


def _emit(ctx, phase: str, /, **kw) -> None:
    """One shape for every progress event this plugin sends.

    Olympus's `_RunContext.emit(ev, **kw)` builds `dict(ev=ev, **kw)`, so a
    payload key that collides with a parameter on the way in is a TypeError,
    not a dropped field — and the analyzer's NDJSON always carries "ev". Two
    defences, because the payload is data from another process and neither one
    covers the other:

      * `phase` is positional-only (`/`), so a payload's own "phase" lands in
        **kw instead of binding to the parameter twice;
      * every reserved key is then stripped from **kw, so neither can collide
        with the keywords this function passes on.

    The inner event name travels as `phase`. Progress must never fail a call,
    so the whole body is guarded.
    """
    try:
        for key in _EMIT_RESERVED:
            kw.pop(key, None)
        ctx.emit("llm_progress", phase=phase, **kw)
    except Exception:                                    # noqa: BLE001
        pass                                             # progress must never fail a call


def _child_env(python: pathlib.Path | None = None) -> dict:
    """The analyzer's environment: Olympus's, minus everything that would make
    another Python load Olympus's runtime. The key travels here, never in argv.
    """
    env = {k: v for k, v in os.environ.items() if k not in _FOREIGN_UNSAFE}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    key = _api_key()
    if key:
        env["GEMINI_API_KEY"] = key
    if python is not None:
        # Activate the analyzer's venv the way a shell would, so anything it
        # spawns finds its own interpreter first.
        venv = python.resolve().parent.parent
        env["VIRTUAL_ENV"] = str(venv)
        env["PATH"] = "%s:%s" % (python.resolve().parent, env.get("PATH", ""))
    return env


def available() -> tuple[bool, str]:
    """(usable, why not). Used by `llm_status`, the readiness panel and the tools."""
    s = _settings()
    if not s["enabled"]:
        return False, ('"llm_enabled" is false or absent in %s' % s["source"])
    if not s["home"]:
        return False, ('"llm_home" is not set in %s' % s["source"])
    if not s["home"].is_dir():
        return False, ('"llm_home" is not a directory: %s' % s["home"])
    if not (s["home"] / BRIDGE).is_file():
        return False, ("%s is not in %s — is llm_home the analyzer's root?"
                       % (BRIDGE, s["home"]))
    if not s["python"]:
        return False, ('"llm_python" is not set and there is no interpreter at %s — '
                       "set it to the analyzer's venv python"
                       % (s["python_tried"] or "<llm_home>/.venv/bin/python3"))
    if not s["python"].is_file():
        return False, ('"llm_python" does not exist: %s' % s["python"])
    if not _api_key(s):
        return False, ("no Gemini key in this process's environment. Connect a Gemini "
                       "backend in the AI panel — the desktop exports the key for its "
                       "children. If you connected it AFTER the tool server started, "
                       "the server did not inherit it: disconnect and reconnect so the "
                       "session restarts. (Headless: export GEMINI_API_KEY before "
                       "launching, or set \"llm_api_key_file\".)")
    return True, ""


# ── Olympus-side helpers ─────────────────────────────────────────────────────

def _repo() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _target_dir(target: str) -> pathlib.Path:
    """A target by name or path, the way every other tool accepts one."""
    from tooling.toolsurface import ToolError
    candidate = pathlib.Path(target).expanduser()
    if not candidate.is_dir():
        candidate = _repo() / "targets" / target
    if not candidate.is_dir():
        raise ToolError("no_target", "no such target: %s" % target, {"target": target})
    if not (candidate / "rsc_base" / "AndroidManifest.xml").is_file():
        raise ToolError("no_recon", "%s has not been prepared (no rsc_base/)" % target,
                        {"target": target})
    if not any(p.is_dir() for p in (candidate / "rsc_base").glob("smali*")):
        raise ToolError("no_recon",
                        "%s decoded to resources but no smali — re-prepare it with a "
                        "current apktool before any code-backed analysis" % target,
                        {"target": target})
    return candidate.resolve()


def olympus_row(target_dir: pathlib.Path, test_id: str) -> dict:
    """Olympus's own resolved row for one MASTG test.

    Read in-process: we are inside Olympus, and `assess` resolves what the
    engines already wrote rather than re-running them.
    """
    from tooling.toolsurface import ToolError
    from olympus_owasp import assess as _assess
    rep = _assess.assess(str(target_dir))
    rows = rep["tests"] if isinstance(rep, dict) and "tests" in rep else rep
    rows = rows if isinstance(rows, list) else list(rows.values())
    for row in rows:
        if str(row.get("test") or "") == test_id:
            return row
    raise ToolError("unknown_test",
                    "Olympus has no result for %s on this target — run it first" % test_id,
                    {"test_id": test_id, "known": len(rows)})


# ── the analyzer, as a subprocess ────────────────────────────────────────────

def _run(argv: list[str], *, stdin_text: str | None, cwd: pathlib.Path,
         timeout: int, python: pathlib.Path) -> dict:
    """Run one analyzer command, streaming its NDJSON progress into the call.

    The analyzer writes progress on `--events-fd`, the same convention Olympus's
    own CLIs use, so this reader is the one Olympus already has in another form.
    Results come back on stdout; logs go to stderr and into the developer log.
    """
    from tooling.toolsurface import ToolError, _ctx

    ctx = _ctx()
    read_fd, write_fd = os.pipe()
    argv = list(argv) + ["--events-fd", str(write_fd)]

    try:
        proc = subprocess.Popen(
            argv, cwd=str(cwd), stdin=subprocess.PIPE if stdin_text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            bufsize=1, pass_fds=(write_fd,), start_new_session=True,
            env=_child_env(python),
        )
    except OSError as e:
        os.close(read_fd), os.close(write_fd)
        raise ToolError("engine_missing", "could not start the analyzer: %s" % e,
                        {"argv": argv[:2]})
    os.close(write_fd)                          # the child holds the only write end

    def pump():
        try:
            with os.fdopen(read_fd, "r") as events:
                for line in events:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except ValueError:
                        continue
                    # A bare scalar or list on this channel is not an event;
                    # **payload would raise on it.
                    if not isinstance(payload, dict):
                        continue
                    _emit(ctx, str(payload.pop("ev", "") or "progress"), **payload)
        except OSError:
            pass

    pumper = threading.Thread(target=pump, daemon=True)
    pumper.start()

    def watch():
        # The operator's Stop reaches us as ctx.cancelled(); the child is its own
        # session leader, so one killpg takes the engine down with it.
        while proc.poll() is None:
            if ctx.cancelled():
                try:
                    os.killpg(os.getpgid(proc.pid), 15)
                except OSError:
                    pass
                return
            if _stop.wait(0.25):
                return

    _stop = threading.Event()
    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()

    try:
        out, err = proc.communicate(input=stdin_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except OSError:
            pass
        raise ToolError("timeout", "the analyzer exceeded %ds" % timeout, {})
    finally:
        _stop.set()
        pumper.join(timeout=2)

    if ctx.cancelled():
        raise ToolError("refused", "cancelled by the operator", {})

    tail = "\n".join((err or "").strip().splitlines()[-6:])
    if not (out or "").strip():
        raise ToolError("refused", "the analyzer produced no result:\n%s" % tail,
                        {"returncode": proc.returncode})
    try:
        return json.loads(out)
    except ValueError:
        raise ToolError("refused", "the analyzer's output was not JSON:\n%s"
                        % (out or "")[:400], {"returncode": proc.returncode})


def _ensure_evidence(target_dir: pathlib.Path, s: dict) -> pathlib.Path:
    """Build the engine's evidence tree for this target if it is not current.

    Idempotent and keyed on the APK's sha256, so a second call is a no-op.
    Serialised: two tools building the same job would race on the same files.
    """
    from tooling.toolsurface import ToolError, _ctx
    job = s["artifacts"] / target_dir.name
    with _LOCK:
        if (job / "evidence").is_dir() and (job / ".olympus_evidence.json").is_file():
            return job
        _emit(_ctx(), "evidence_start", target=target_dir.name)
        proc = subprocess.run(
            [str(s["python"]), str(s["home"] / EVIDENCE),
             "--olympus-target", str(target_dir),
             "--artifacts-root", str(s["artifacts"])],
            cwd=str(s["home"]), capture_output=True, text=True, env=_child_env(s["python"]),
        )
        if proc.returncode != 0:
            tail = "\n".join((proc.stderr or "").strip().splitlines()[-8:])
            raise ToolError("engine_missing", "evidence build failed:\n%s" % tail, {})
        _emit(_ctx(), "evidence_done", target=target_dir.name)
        return job


def _guard() -> dict:
    from tooling.toolsurface import ToolError
    ok, why = available()
    if not ok:
        raise ToolError("engine_missing", why,
                        {"config": str(_settings()["source"])})
    return _settings()


# ── in-process engine ────────────────────────────────────────────────────────
# WHY THIS EXISTS. A rate limiter paces the process it lives in. With the
# analyzer spawned per call, every tool call got its own limiter and N calls
# could collectively overshoot — and one 429 from Gemini locks the key out for
# hours, which on a batch of applications is the difference between slow and
# stopped. Importing the engine here puts every call in ONE process behind ONE
# limiter.
#
# It is affordable because `app.engine_api` and all of layer 4 import only the
# standard library; `google-genai`, `ujson` and `openai` are pulled lazily when
# a backend is built. So Olympus's venv needs those three and nothing else —
# not androguard, not the evidence stack. Evidence building stays a subprocess
# in the analyzer's own venv, where its pins belong.
#
# THE TRADE-OFF, stated plainly: a subprocess could be killed, so Stop was
# immediate. An in-process call cannot be interrupted — cancelling stops this
# tool waiting, and the model conversation finishes in the background. It still
# passes through the limiter, so it cannot cause a 429; it does spend tokens.

_ENGINES: dict = {}
_LIMITER = None


def _engine_home_on_path(home: pathlib.Path) -> None:
    # Appended, never prepended: Olympus's own modules must keep winning if the
    # two trees ever share a name.
    path = str(home)
    if path not in sys.path:
        sys.path.append(path)


def _shared_limiter(engine, s):
    """One SharedRateLimiter for every engine in this process."""
    global _LIMITER
    if _LIMITER is None:
        from app.layer4.shared_rate_limiter import SharedRateLimiter
        tpm = s["tpm"] or int(engine.settings.get("tpm_limit") or 0)
        rpm = s["rpm"]
        if tpm <= 0 and rpm <= 0:
            return None
        _LIMITER = SharedRateLimiter(tpm_limit=tpm, rpm_limit=rpm, log_fn=lambda *a, **k: None)
    return _LIMITER


def _engine(job_root: pathlib.Path, s: dict):
    """The EngineAPI for one job, built once and reused.

    Cached because the APK index and the loaded test plan are the expensive
    part, and because every engine must share the one limiter.
    """
    key = "%s|%s" % (job_root, s["model"])
    with _LOCK:
        got = _ENGINES.get(key)
        if got is not None:
            return got
        _engine_home_on_path(s["home"])
        from app.engine_api import EngineMode, EngineSettings
        from olympus_bridge import discover_modes

        found = discover_modes()
        if "analysis" not in found:
            from tooling.toolsurface import ToolError
            raise ToolError("engine_missing",
                            "no analysis prompt/schema pair under "
                            "app/layer4/prompts/system/", {})
        analysis_prompt, analysis_schema = found["analysis"]
        settings = EngineSettings.from_dict({
            "backend": "gemini",
            "model": s["model"],
            "api_key": _api_key(s),
            "system_prompt": str(analysis_prompt),
            "schema": str(analysis_schema),
        }, log_fn=lambda *a, **k: None)

        modes = {name: EngineMode(name, system_prompt=pr, schema=sc)
                 for name, (pr, sc) in found.items()}
        engine = settings.for_apk(job_root, log_fn=lambda *a, **k: None, **modes)
        limiter = _shared_limiter(engine, s)
        if limiter is not None:
            engine.set_rate_limiter(limiter)
        _ENGINES[key] = engine
        return engine


def _call_in_process(mode: str, job_root: pathlib.Path, test_id: str,
                     row, s: dict) -> dict:
    from tooling.toolsurface import ToolError, _ctx
    from olympus_bridge import envelope          # identical result shape

    ctx = _ctx()
    engine = _engine(job_root, s)
    out: dict = {}

    def work():
        try:
            # One backend per in-flight call: a backend holds conversation
            # state and must never be shared. They share the limiter, not
            # the conversation.
            backend = engine.make_backend()
            if mode == "review":
                result = engine.validate(test_id, row, backend=backend)
            else:
                result = engine.run_test(test_id, backend=backend)
            out["env"] = envelope(mode, test_id, result)
        except Exception as exc:                         # noqa: BLE001
            out["error"] = exc

    _emit(ctx, "%s_start" % mode, cid=test_id)
    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    while worker.is_alive():
        worker.join(timeout=0.5)
        if ctx.cancelled() and worker.is_alive():
            raise ToolError("refused",
                            "cancelled by the operator. The call cannot be "
                            "interrupted in-process, so it finishes in the "
                            "background and its verdict is still written.", {})
    if "error" in out:
        exc = out["error"]
        raise ToolError("refused", "%s: %s" % (type(exc).__name__, exc), {})
    _emit(ctx, "%s_done" % mode, cid=test_id, status=out["env"].get("status"))
    return out["env"]


def in_process_ready(s: dict) -> tuple[bool, str]:
    """Can this process import and run the engine itself?"""
    if not s["in_process"]:
        return False, '"llm_in_process" is false'
    if not s["home"]:
        return False, "no llm_home"
    try:
        _engine_home_on_path(s["home"])
        import app.engine_api                            # noqa: F401
    except Exception as exc:                             # noqa: BLE001
        return False, "cannot import the engine: %s: %s" % (type(exc).__name__, exc)
    for module, package in (("google.genai", "google-genai"),
                            ("ujson", "ujson"), ("openai", "openai")):
        try:
            __import__(module)
        except Exception:                                # noqa: BLE001
            return False, ("%s is not installed in Olympus's venv (pip install %s)"
                           % (module, package))
    return True, ""


# ── the two tools ────────────────────────────────────────────────────────────

def llm_run_test(target, test_id, timeout=3600):
    """The engine answers the test itself. Olympus is not asked."""
    s = _guard()
    tdir = _target_dir(target)
    job = _ensure_evidence(tdir, s)
    ok, _ = in_process_ready(s)
    if ok:
        return _call_in_process("run", job, str(test_id), None, s)
    return _run([str(s["python"]), str(s["home"] / BRIDGE), "run",
                 "--apk-root", str(job), "--test", str(test_id),
                 "--backend", "gemini", "--model", s["model"]],
                stdin_text=None, cwd=s["home"], timeout=int(timeout),
                python=s["python"])


def llm_review(target, test_id, timeout=3600):
    """The engine checks Olympus's own answer for this test against the evidence."""
    s = _guard()
    tdir = _target_dir(target)
    row = olympus_row(tdir, str(test_id))
    job = _ensure_evidence(tdir, s)
    ok, _ = in_process_ready(s)
    if ok:
        return _call_in_process("review", job, str(test_id), row, s)
    return _run([str(s["python"]), str(s["home"] / BRIDGE), "review",
                 "--apk-root", str(job), "--test", str(test_id),
                 "--backend", "gemini", "--model", s["model"]],
                stdin_text=json.dumps(row, default=str), cwd=s["home"],
                timeout=int(timeout), python=s["python"])


# ── registration ─────────────────────────────────────────────────────────────

def llm_status():
    """Why the plugin is or is not usable, without running anything."""
    s = _settings()
    ok, why = available()
    return {
        "available": ok,
        "reason": why or "ready",
        "config_file": str(s["source"]),
        "config_exists": s["source"].is_file(),
        "config_is_durable": s["source"] == CONFIG_PATH,
        "enabled": s["enabled"],
        "home": str(s["home"]) if s["home"] else "",
        "python": str(s["python"]) if s["python"] else "",
        "model": s["model"],
        "artifacts_root": str(s["artifacts"]),
        "execution": ("in-process (one shared rate limiter)"
                      if in_process_ready(s)[0]
                      else "subprocess per call — %s" % in_process_ready(s)[1]),
        "rate_limit": "TPM<=%s RPM<=%s" % (s["tpm"] or "from settings", s["rpm"]),
        "api_key": ("from this process's environment (the AI panel, or the shell "
                    "Olympus was launched from)"
                    if os.environ.get("GEMINI_API_KEY", "").strip()
                    else ("from llm_api_key_file" if _api_key(s) else "missing")),
    }


def register(_S):
    """(tools, schema, cost, slow) for `toolsurface` to merge in.

    Returned rather than imported the other way so this module stays a leaf:
    `toolsurface` knows the plugin exists, the plugin knows nothing until a call
    is in flight.
    """
    tools = {"llm_status": llm_status,
             "llm_run_test": llm_run_test, "llm_review": llm_review}

    schema = {
        "llm_status": (
            "Whether the LLM analysis engine is configured and reachable, and "
            "if not, exactly which setting is missing. Runs nothing and costs "
            "nothing. Ask this first when an LLM tool reports it is unavailable.",
            {}, []),
        "llm_run_test": (
            "Answer one MASTG test with the LLM analysis engine instead of "
            "Olympus's own rule. Reads the engine's evidence layer for this "
            "target, building it first if it is missing. Returns the engine's "
            "verdict and its cited evidence. Does NOT set Olympus's delivered "
            "verdict.",
            {"target": _S["str"], "test_id": _S["str"], "timeout": _S["int"]},
            ["target", "test_id"]),
        "llm_review": (
            "Check what Olympus already answered for one MASTG test. The engine "
            "is given Olympus's own resolved row plus the evidence layer and "
            "looks for checks that were never performed. Returns the engine's "
            "verdict beside Olympus's, and whether they disagree. Does NOT set "
            "Olympus's delivered verdict. Requires that Olympus has run the "
            "test first.",
            {"target": _S["str"], "test_id": _S["str"], "timeout": _S["int"]},
            ["target", "test_id"]),
    }

    cost = {"llm_status": "instant",
            "llm_run_test": "minutes", "llm_review": "minutes"}

    slow = {
        "llm_run_test": "a multi-turn model conversation over the evidence layer, up to "
                        "50 tool rounds, and builds the evidence tree on first use",
        "llm_review": "a multi-turn model conversation over the evidence layer, up to "
                      "50 tool rounds, and builds the evidence tree on first use",
    }
    return tools, schema, cost, slow
