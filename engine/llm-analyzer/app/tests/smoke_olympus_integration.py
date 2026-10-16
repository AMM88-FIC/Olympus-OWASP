"""End-to-end smoke test for the Olympus integration surface.

Stubs the third-party SDKs (absent on this Windows box) and the LLM backend, so
nothing touches the network. Exercises the real facade, the real test plan, the
real validator and the real Olympus adapter.
"""
import json, sys, types, tempfile, shutil
from pathlib import Path

sys.path.insert(0, ".")

# --- stub third-party deps not installed here (target env is Kali) ---
uj = types.ModuleType("ujson"); uj.dumps = json.dumps; uj.loads = json.loads
uj.JSONDecodeError = ValueError; sys.modules["ujson"] = uj
g = types.ModuleType("google"); gg = types.ModuleType("google.genai")
gg.types = types.ModuleType("google.genai.types"); g.genai = gg
sys.modules["google"] = g; sys.modules["google.genai"] = gg
sys.modules["google.genai.types"] = gg.types
oa = types.ModuleType("openai"); oa.OpenAI = object; sys.modules["openai"] = oa

from app.engine_api import (EngineAPI, EngineSettings, EngineConfigError,
                            TestNotFoundError, EngineError)
from app.layer4.backends.base import TurnResult, Usage
from app.olympus import MockOlympusClient, normalize_olympus_output, OlympusError

PASS, FAIL = [], []
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{'  — ' + detail if detail and not cond else ''}")

tmp = Path(tempfile.mkdtemp())
ev = tmp / "evidence"; ev.mkdir()
(ev / "crypto_usage.json").write_text(json.dumps(
    {"records": [{"id": "CR-1", "algorithm": "AES/ECB/PKCS5Padding"}]}))
apk = tmp / "apk"; (apk / "jadx" / "sources").mkdir(parents=True)
(apk / "jadx" / "sources" / "Main.java").write_text("package a;\nclass Main {}\n")

SETTINGS = dict(
    backend="openai", model="stub", base_url="http://stub",
    apk_root=apk, evidence_dir=ev, output_dir=tmp / "out",
    schema=Path("app/layer4/prompts/system/2.layer3_schema_v1.2.5_full_spec.md"),
    system_prompt=Path("app/layer4/prompts/system/1.system_prompt-v1.3.10.md"),
    test_plan_dir=Path("app/layer4/test_plans/owasp_mastg"),
)

print("\n[1] Facade construction and config errors")
api = EngineAPI.from_dict(SETTINGS)
check("from_dict builds", api is not None)
try:
    EngineAPI.from_dict({**SETTINGS, "apk_root": None}); check("missing path raises", False)
except EngineConfigError as e:
    check("missing path raises EngineConfigError (not SystemExit)", True)
try:
    EngineAPI.from_dict({**SETTINGS, "nonsense_key": 1}); check("unknown key raises", False)
except EngineConfigError:
    check("unknown setting rejected", True)

print("\n[2] Test catalogue (G1) — filters match the CLI")
allt = api.list_tests()
crypto = api.list_tests("crypto")
check("107 tests loaded", len(allt) == 107, f"got {len(allt)}")
check("category filter 'crypto' -> 12", len(crypto) == 12, f"got {len(crypto)}")
check("TestInfo carries source", all(t.source == "engine" for t in allt))
check("TestInfo is serialisable", isinstance(crypto[0].to_dict(), dict))

print("\n[3] read_test / read_results")
t = api.read_test("MASTG-TEST-0204")
check("read_test returns prompt text", isinstance(t["prompt"], str) and len(t["prompt"]) > 100)
check("read_test carries category", t["category"] == "CRYPTO", t.get("category"))
check("read_results is None before a run", api.read_results("MASTG-TEST-0204") is None)
rp = api.result_path("MASTG-TEST-0204")
check("result path is category-nested", rp.parent.name == "CRYPTO", str(rp))
try:
    api.read_test("NOPE"); check("unknown test raises", False)
except TestNotFoundError:
    check("unknown test raises TestNotFoundError", True)

print("\n[4] APK read surface")
check("13 tools exposed", len(api.tool_names()) == 13, str(len(api.tool_names())))
check("list_dir works", "jadx/" in [str(x) for x in api.call_tool("list_dir", {})] or
                        any("jadx" in str(x) for x in api.call_tool("list_dir", {})))
check("evidence tool works", api.call_tool("list_evidence_files") is not None)
try:
    api.call_tool("rm_rf", {}); check("unknown tool rejected", False)
except EngineError:
    check("unknown tool rejected", True)
try:
    esc = api.call_tool("read_file", {"path": "../../../etc/passwd"})
    check("path escape blocked", False, repr(esc)[:60])
except Exception as e:
    check(f"path escape blocked ({type(e).__name__})", True)

print("\n[5] Olympus adapter (G2)")
fix = tmp / "olympus"; fix.mkdir()
(fix / "MASTG-TEST-0204.json").write_text(json.dumps(
    {"test_id": "MASTG-TEST-0204", "verdict": "pass",
     "rationale": "AES used.", "checks": ["cipher-scan"]}))
(fix / "MASTG-TEST-0205.txt").write_text("PASS - no weak crypto found\n")
cli = MockOlympusClient(fix)
check("lists available", cli.list_available() == ["MASTG-TEST-0204", "MASTG-TEST-0205"])
check("is_finished true", cli.is_finished("MASTG-TEST-0204"))
check("is_finished false for unknown", not cli.is_finished("MASTG-TEST-9999"))
o = cli.get_test_output("MASTG-TEST-0204")
check("JSON normalised: verdict", o.verdict == "pass", str(o.verdict))
check("JSON normalised: raw preserved", o.raw["checks"] == ["cipher-scan"])
o2 = cli.get_test_output("MASTG-TEST-0205")
check("plain text carried through", "PASS" in o2.as_text())
check("plain text warns", any("plain text" in w for w in o2.warnings), str(o2.warnings))
try:
    cli.get_test_output("../../etc/passwd"); check("id traversal blocked", False)
except OlympusError:
    check("id traversal blocked", True)
try:
    cli.get_test_output("MASTG-TEST-9999"); check("missing output raises", False)
except OlympusError:
    check("missing output raises OlympusError", True)
bad = normalize_olympus_output('{"broken": ')
check("malformed JSON kept as text + warned", bool(bad.warnings) and isinstance(bad.raw, str))

print("\n[6] Validation flow (G3) with a stub backend")
sent = []
class StubBackend:
    """Answers the first prompt with a verdict; records what it was sent."""
    def send_user_message(self, content, *, label=""):
        sent.append(content)
        return TurnResult(text=json.dumps({
            "verdict": "fail", "certainty_percent": 80,
            "evidence_table": [{"id": "CR-1"}],
            "rationale": "Olympus missed the ECB mode in CR-1.",
        }), tool_calls=[], usage=Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15))
    def send_tool_responses(self, responses, *, label=""): raise AssertionError("unused")
    def ack_protocol_tool_calls(self, calls): pass
    def configure_tools(self, navigator): pass

# Olympus PUSHES its output in - no client object, no callback.
run = api.validate("MASTG-TEST-0204", cli.get_test_output("MASTG-TEST-0204").raw,
                   backend=StubBackend(), bootstrap=False)
check("validation ran", run.ok, run.status)
check("verdict captured", run.verdict == "fail", str(run.verdict))
check("olympus output retained", run.olympus.verdict == "pass")
check("gaps_found true when verdicts differ", run.gaps_found)
check("result serialises", isinstance(run.to_dict(), dict))
prompt = sent[0]
check("Olympus output injected into prompt", '"verdict": "pass"' in prompt)
check("prompt scoped to verification", "Verify it." in prompt)
check("prompt asks for omissions", "MISSING" in prompt)
check("test prompt still present after prefix", "# Test case" in prompt)
check("verdict written to category subfolder", api.result_path("MASTG-TEST-0204").is_file())
check("read_results now returns it", (api.read_results("MASTG-TEST-0204") or {}).get("verdict") == "fail")

print("\n[7] Validation skips rather than fails")
# Raw CLI text is accepted just as readily as JSON.
run2 = api.validate("MASTG-TEST-0212", "PASS - nothing found",
                    backend=StubBackend(), bootstrap=False)
check("plain-text olympus output accepted", run2.ok, run2.status)
check("no gap flagged when olympus verdict unparseable", not run2.gaps_found)
empty = tmp / "empty_ev"; empty.mkdir()
api_noev = EngineAPI.from_dict({**SETTINGS, "evidence_dir": empty})
try:
    api_noev.validate("MASTG-TEST-0204", {"verdict": "pass"},
                      backend=StubBackend(), bootstrap=False)
    check("empty evidence dir refused", False)
except EngineError as e:
    check("empty evidence dir refused loudly", "no evidence" in str(e).lower() or "no *.json" in str(e))

print("\n[8] source marker (G4) round-trip")
plan_dir = tmp / "plan"; (plan_dir / "prompts").mkdir(parents=True)
(plan_dir / "prompts" / "t.md").write_text("# t\n")
(plan_dir / "tests.toml").write_text(
    'name = "src"\n'
    '[tests.A]\ntype="llm"\nprompt="t.md"\n'
    '[tests.B]\ntype="llm"\nprompt="t.md"\nsource="olympus"\ncategory="CRYPTO"\n')
api2 = EngineAPI.from_dict({**SETTINGS, "test_plan_dir": plan_dir})
srcs = {t.test_id: t.source for t in api2.list_tests()}
check("default source is engine", srcs["A"] == "engine", srcs.get("A"))
check("explicit source honoured", srcs["B"] == "olympus", srcs.get("B"))
check("olympus_sourced_tests filters", [t.test_id for t in api2.olympus_sourced_tests()] == ["B"])

print("\n[9] EngineSettings — configure once, one engine per APK")
def _mkapk(name):
    r = tmp / name
    (r / "evidence").mkdir(parents=True); (r / "jadx" / "sources").mkdir(parents=True)
    (r / "evidence" / "crypto_usage.json").write_text('{"records":[]}')
    return r
a1, a2 = _mkapk("app-one"), _mkapk("app-two")
# Every value a plain string, the way a JSON/dict config would supply it.
fixed = EngineSettings.from_dict({
    "backend": "openai", "model": "qwen3.6:27b", "base_url": "http://stub",
    "test_plan_dir": "app/layer4/test_plans/owasp_mastg",
    "schema": "app/layer4/prompts/system/2.layer3_schema_v1.2.5_full_spec.md",
    "system_prompt": "app/layer4/prompts/system/1.system_prompt-v1.3.10.md",
    "max_tool_iterations": "40",
})
e1 = fixed.for_apk(str(a1)); e2 = fixed.for_apk(a2)
check("builds with no apk paths and no INI file", e1 is not None)
check("str and Path apk_root both accepted", e2 is not None)
check("evidence_dir defaults to <apk_root>/evidence", e1.config.evidence_dir == a1 / "evidence")
check("output_dir defaults to <apk_root>/verdicts", e1.config.output_dir == a1 / "verdicts")
check("string int coerced to int", e1.config.max_tool_iterations == 40)
check("fixed settings reused across APKs", e1.settings["model"] == e2.settings["model"])
check("both engines load the plan", len(e1.list_tests()) == len(e2.list_tests()) == 107)
e3 = fixed.for_apk(a1, output_dir=tmp / "custom", evidence_dir=str(a2 / "evidence"))
check("explicit dir overrides honoured",
      e3.config.output_dir.name == "custom" and e3.config.evidence_dir.parent.name == "app-two")
e4 = fixed.with_(model="other").for_apk(a1)
check("with_() does not mutate shared settings",
      e4.settings["model"] == "other" and fixed.base["model"] == "qwen3.6:27b")
try:
    EngineSettings.from_dict({"backend": "openai", "model": "m"}).for_apk(a1)
    check("incomplete fixed settings raise", False)
except EngineConfigError:
    check("incomplete fixed settings raise EngineConfigError", True)
try:
    fixed.for_apk(a1, max_tool_iterations="not-a-number")
    check("uncoercible value raises", False)
except EngineConfigError:
    check("uncoercible value raises EngineConfigError", True)

print("\n[10] Protocol handshake — a stub that follows the real protocol")
# The earlier StubBackend answers with a verdict no matter what it is sent, so
# it would pass even if the session never negotiated the schema. This one
# behaves like the system prompt says a model must: ask for the schema first,
# then for a prompt, and only then produce a verdict.
class ProtocolBackend:
    def __init__(self):
        self.turns = []
    def send_user_message(self, content, *, label=""):
        self.turns.append(content)
        n = len(self.turns)
        if n == 1:
            body = json.dumps({"status": "prompted", "operation": "getSchema",
                               "args": "None"})
        elif n == 2:
            body = json.dumps({"status": "prompted", "operation": "getPrompt",
                               "args": "None"})
        else:
            body = json.dumps({"verdict": "fail", "certainty_percent": 70,
                               "evidence_table": [{"id": "CR-1"}],
                               "rationale": "ECB mode reached via CR-1."})
        return TurnResult(text=body, tool_calls=[],
                          usage=Usage(prompt_tokens=1, completion_tokens=1,
                                      total_tokens=2))
    def send_tool_responses(self, responses, *, label=""):
        raise AssertionError("unused")
    def ack_protocol_tool_calls(self, calls):
        pass
    def configure_tools(self, navigator):
        self.tools_registered = list(navigator.TOOL_NAMES)

pb = ProtocolBackend()
run3 = api.run_test("MASTG-TEST-0205", backend=pb)
check("run_test completes against a protocol-following model", run3.ok, run3.status)
check("handshake ran: 3 turns (Begin, schema, prompt)", len(pb.turns) == 3,
      f"{len(pb.turns)} turns")
check("turn 1 is the kickoff", pb.turns[0].strip() == "Begin.", pb.turns[0][:40])
check("turn 2 delivers the schema", "=== schema.md ===" in pb.turns[1])
check("turn 3 is the test prompt", "MASTG-TEST" in pb.turns[2] or len(pb.turns[2]) > 200)
check("all 13 navigator tools registered with the backend",
      getattr(pb, "tools_registered", None) is not None
      and len(pb.tools_registered) == 13,
      str(getattr(pb, "tools_registered", None)))

pb2 = ProtocolBackend()
run4 = api.validate("MASTG-TEST-0208", {"verdict": "pass"}, backend=pb2)
check("validate also runs the handshake", len(pb2.turns) == 3, f"{len(pb2.turns)} turns")
check("validate injects Olympus output after the handshake",
      '"verdict": "pass"' in pb2.turns[2])
check("validate reached a verdict", run4.ok, run4.status)

# A model that refuses the handshake must fail loudly, not silently proceed.
class NoHandshakeBackend(ProtocolBackend):
    def send_user_message(self, content, *, label=""):
        self.turns.append(content)
        return TurnResult(text="I will not negotiate.", tool_calls=[],
                          usage=Usage(1, 1, 2))
try:
    api.run_test("MASTG-TEST-0212", backend=NoHandshakeBackend())
    check("failed handshake raises", False)
except EngineError:
    check("failed handshake raises EngineError instead of running blind", True)

print("\n[11] Report generation")
try:
    out = api.generate_report(tmp / "report.html", apk_name="Demo")
    html = out.read_text(encoding="utf-8")
    check("report written", out.is_file() and len(html) > 1000)
    check("report includes the nested verdict", "MASTG-TEST-0204" in html)
except Exception as e:
    check("report generation", False, f"{type(e).__name__}: {e}")

shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{'='*58}\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  FAILED: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
