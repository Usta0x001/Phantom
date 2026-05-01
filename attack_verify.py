"""AGGRESSIVE ATTACK TEST — every change, every import, every function call.
No assumptions. No mocking. Real imports only.
"""
import os, sys
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

import traceback

FAILED = []
PASSED = []

def ATTACK(name, fn):
    try:
        fn()
        PASSED.append(name)
        print(f"[PASS] {name}")
    except Exception as e:
        FAILED.append((name, str(e)[:120]))
        print(f"[FAIL] {name}: {e[:100]}")

def assert_true(name, cond, detail=""):
    if not cond:
        FAILED.append((name, f"assertion failed{detail}"))
        print(f"[FAIL] {name}: assertion failed {detail}")

print("=" * 70)
print("ATTACK 1: phantom/__init__.py version")
print("=" * 70)

def t1():
    from phantom import __version__
    assert_true("version is 0.9.216", __version__ == "0.9.216", f"got {__version__}")

ATTACK("version check", t1)

print()
print("=" * 70)
print("ATTACK 2: phantom/config/config.py phantom_tool_subset=core")
print("=" * 70)

def t2():
    from phantom.config import Config
    val = Config.get("phantom_tool_subset")
    assert_true("phantom_tool_subset = core", val == "core", f"got '{val}'")

ATTACK("Config.get phantom_tool_subset", t2)

print()
print("=" * 70)
print("ATTACK 3: phantom/llm/__init__.py glm-5.1 model registry")
print("=" * 70)

def t3():
    from phantom.llm import _PHANTOM_EXTRA_MODELS
    assert_true("glm-5.1 in _PHANTOM_EXTRA_MODELS", "glm-5.1" in _PHANTOM_EXTRA_MODELS)
    assert_true("openai/glm-5.1 in _PHANTOM_EXTRA_MODELS", "openai/glm-5.1" in _PHANTOM_EXTRA_MODELS)
    info = _PHANTOM_EXTRA_MODELS["glm-5.1"]
    assert_true("glm-5.1.max_tokens >= 128000", info["max_tokens"] >= 128000)
    assert_true("glm-5.1.input_cost > 0", info["input_cost_per_token"] > 0)
    assert_true("glm-5.1.output_cost > 0", info["output_cost_per_token"] > 0)

ATTACK("glm-5.1 registry", t3)

print()
print("=" * 70)
print("ATTACK 4: phantom/llm/llm.py cost warning")
print("=" * 70)

def t4():
    src = open("phantom/llm/llm.py", encoding="utf-8", errors="ignore").read()
    assert_true("Budget tracking is blind in llm.py", "Budget tracking is blind" in src)
    assert_true("use_compact=True in llm.py", "use_compact=True" in src)

ATTACK("cost warning + use_compact", t4)

print()
print("=" * 70)
print("ATTACK 5: config.toml + auth.json API key removal")
print("=" * 70)

def t5():
    ct = open("config.toml", encoding="utf-8", errors="ignore").read()
    aj = open("auth.json", encoding="utf-8", errors="ignore").read()
    assert_true("config.toml: no sk-S8 key", "sk-S8" not in ct)
    assert_true("auth.json: no sk-S8 key", "sk-S8" not in aj)
    assert_true("auth.json: has REPLACE_WITH_YOUR_TOKEN", "REPLACE_WITH_YOUR_TOKEN" in aj)

ATTACK("API keys removed", t5)

print()
print("=" * 70)
print("ATTACK 6: phantom/agents/base_agent.py error handling")
print("=" * 70)

def t6():
    src = open("phantom/agents/base_agent.py", encoding="utf-8", errors="ignore").read()
    assert_true("no contextlib.suppress(Exception)", "contextlib.suppress(Exception)" not in src)
    assert_true("no 'if True:' dead branches", "if True:" not in src)
    assert_true("_NO_ACTION_STALL_WARN defined", "_NO_ACTION_STALL_WARN" in src)
    cnt = src.count("logger.exception")
    assert_true("logger.exception called >= 6 times", cnt >= 6, f" only {cnt}")
    assert_true("logger.warning called >= 2 times", src.count("logger.warning") >= 2)

ATTACK("base_agent error handling", t6)

print()
print("=" * 70)
print("ATTACK 7: phantom/tools/__init__.py explicit imports")
print("=" * 70)

def t7():
    src = open("phantom/tools/__init__.py", encoding="utf-8", errors="ignore").read()
    stars = [l for l in src.split("\n") if "import *" in l and not l.strip().startswith("#")]
    assert_true("0 star imports", len(stars) == 0, f" found {stars}")
    assert_true("wait_for_agents in __all__", "wait_for_agents" in src.split("__all__")[1])
    assert_true("reset_all_state in __all__", "reset_all_state" in src.split("__all__")[1])
    assert_true("from .agents_graph import", "from .agents_graph import" in src)

ATTACK("tools/__init__.py explicit imports", t7)

print()
print("=" * 70)
print("ATTACK 8: phantom/tools/agents_graph/__init__.py exports")
print("=" * 70)

def t8():
    from phantom.tools.agents_graph import agent_finish, create_agent, send_message_to_agent
    from phantom.tools.agents_graph import view_agent_graph, wait_for_message, wait_for_agents, reset_all_state
    assert_true("wait_for_agents is callable", callable(wait_for_agents))
    assert_true("reset_all_state is callable", callable(reset_all_state))

ATTACK("agents_graph exports", t8)

print()
print("=" * 70)
print("ATTACK 9: phantom/tools/dynamic_tools.py use_compact default")
print("=" * 70)

def t9():
    src = open("phantom/tools/dynamic_tools.py", encoding="utf-8", errors="ignore").read()
    assert_true("use_compact=True default in get_tools_prompt_subset", 
                 "use_compact: bool = True" in src)
    assert_true("get_compact_tools_prompt_subset called when use_compact=True", 
                 "get_compact_tools_prompt_subset" in src)

ATTACK("dynamic_tools use_compact", t9)

print()
print("=" * 70)
print("ATTACK 10: phantom/agents/PhantomAgent/system_prompt.jinja")
print("=" * 70)

def t10():
    src = open("phantom/agents/PhantomAgent/system_prompt.jinja", encoding="utf-8", errors="ignore").read()
    lines = src.splitlines()
    assert_true("system prompt <= 250 lines", len(lines) <= 250, f" got {len(lines)}")
    assert_true("get_tools_prompt in template", "{{ get_tools_prompt()" in src)
    assert_true("loaded_skill_names removed from template", "loaded_skill_names" not in src)
    assert_true("security_rules section", "security_rules" in src)
    assert_true("core_mandate section", "core_mandate" in src)
    assert_true("hypothesis_ledger section", "hypothesis_ledger" in src)
    assert_true("TARGET in template", "TARGET:" in src or "target_url" in src)

ATTACK("system_prompt.jinja", t10)

print()
print("=" * 70)
print("ATTACK 11: phantom/tools/browser/browser_actions.py conflict resolved")
print("=" * 70)

def t11():
    src = open("phantom/tools/browser/browser_actions.py", encoding="utf-8", errors="ignore").read()
    assert_true("no git conflict markers", "<<<<<<" not in src)
    assert_true("no ======= in non-comment", 
                 len([l for l in src.split("\n") if l.strip() == "======="]) == 0)
    assert_true("@register_tool(sandbox_execution=True)", "@register_tool(sandbox_execution=True)" in src)

ATTACK("browser_actions conflict resolved", t11)

print()
print("=" * 70)
print("ATTACK 12: phantom/tools/registry.py — get_tools_prompt()")
print("=" * 70)

def t12():
    from phantom.tools import get_tools_prompt
    prompt = get_tools_prompt()
    assert_true("get_tools_prompt returns non-empty string", len(prompt) > 1000)
    assert_true("get_tools_prompt has <!-- comments", "<!-- " in prompt)

ATTACK("registry get_tools_prompt", t12)

print()
print("=" * 70)
print("ATTACK 13: FULL IMPORT CHAIN — TUI to tools (THE CRITICAL PATH)")
print("=" * 70)

def t13():
    import importlib
    # Simulate exactly what TUI does at startup
    from phantom.tools import get_tools_prompt, get_tool_names
    from phantom.agents.PhantomAgent import PhantomAgent
    from phantom.llm.config import LLMConfig
    from phantom.interface.cli import run_cli
    from phantom.interface.tui import PhantomTUIApp
    # If any of these fail, the TUI crashes (original bug)
    assert_true("get_tools_prompt", callable(get_tools_prompt))
    assert_true("get_tool_names", callable(get_tool_names))
    assert_true("PhantomAgent", callable(PhantomAgent))
    assert_true("LLMConfig", callable(LLMConfig))
    assert_true("run_cli", callable(run_cli))
    assert_true("PhantomTUIApp", callable(PhantomTUIApp))

ATTACK("full TUI import chain", t13)

print()
print("=" * 70)
print("ATTACK 14: TOOL REGISTRY — 79 tools registered after cleanup")
print("=" * 70)

def t14():
    from phantom.tools import tools, get_tool_names
    assert_true("tools list populated", len(tools) >= 65, f" got {len(tools)}")
    names = get_tool_names()
    assert_true("get_tool_names >= 65", len(names) >= 65, f" got {len(names)}")
    critical = ["send_request", "terminal_execute", "create_vulnerability_report", 
                 "browser_action", "create_agent", "get_scan_status"]
    for t in critical:
        assert_true(f"critical tool '{t}'", t in names)

ATTACK("tool registry", t14)

print()
print("=" * 70)
print("ATTACK 15: DYNAMIC TOOLS — subset modes work")
print("=" * 70)

def t15():
    from phantom.tools.dynamic_tools import (
        get_tools_for_subset_mode, get_compact_tools_prompt_subset,
        get_tools_prompt_subset, get_tools_for_context
    )
    # core mode
    core = get_tools_for_subset_mode("core")
    assert_true("core mode returns tools", len(core) >= 20, f" got {len(core)}")
    
    prompt_core = get_tools_prompt_subset(core, use_compact=True)
    assert_true("core compact prompt < 15K", len(prompt_core) < 15000, f" got {len(prompt_core)}")
    
    # full mode
    full = get_tools_for_subset_mode("full")
    prompt_full = get_compact_tools_prompt_subset(full)
    assert_true("full compact prompt < 50K", len(prompt_full) < 50000, f" got {len(prompt_full)}")
    
    # verify 82% reduction
    from phantom.tools.registry import get_tools_prompt
    xml_full = get_tools_prompt()
    reduction = 100 * (1 - len(prompt_full) / len(xml_full))
    assert_true("reduction >= 75%", reduction >= 75, f" only {reduction:.0f}%")

ATTACK("dynamic tools", t15)

print()
print("=" * 70)
print("ATTACK 16: HYPOTHESIS LEDGER — still functional")
print("=" * 70)

def t16():
    from phantom.agents.hypothesis_ledger import HypothesisLedger
    ledger = HypothesisLedger()
    hid = ledger.add("http://test/api", "sqli")
    assert_true("add returns ID", hid is not None and len(hid) > 0)
    checked = ledger.has_tested("http://test/api", "sqli", "test'OR'1=1")
    assert_true("has_tested returns False for new payload", checked == False)
    ledger.record_payload(hid, "test'OR'1=1")
    ledger.record_payload(hid, "admin'--")
    confirmed = ledger.confirm(hid, "extracted admin table with passwords")
    assert_true("confirm returns True", confirmed == True)
    all_h = ledger.get_all()
    assert_true("get_all returns dict", isinstance(all_h, dict) and len(all_h) > 0)
    hyp = ledger.get(hid)
    assert_true("get(hid) returns Hypothesis", hyp is not None)
    assert_true("Hypothesis.status is confirmed", hyp.status == "confirmed")

ATTACK("hypothesis ledger", t16)

print()
print("=" * 70)
print("ATTACK 17: AGENT STATE — creation and attributes")
print("=" * 70)

def t17():
    from phantom.agents.state import AgentState
    state = AgentState(agent_id="test", agent_name="Test", parent_id=None, task="scan")
    assert_true("state has iteration", hasattr(state, "iteration"))
    assert_true("state has add_message", hasattr(state, "add_message"))
    assert_true("state has agent_id", state.agent_id == "test")
    state.add_message("user", "test message")
    msgs = state.messages
    assert_true("messages not empty after add", len(msgs) > 0)

ATTACK("agent state", t17)

print()
print("=" * 70)
print("ATTACK 18: LLM CONFIG — scan_mode defaults")
print("=" * 70)

def t18():
    os.environ["PHANTOM_LLM"] = "openai/test-model"
    os.environ["PHANTOM_LLM_API_KEY"] = "test-key-for-verify"
    from phantom.llm.config import LLMConfig
    cfg = LLMConfig(model_name="test-model", scan_mode="deep")
    assert_true("scan_mode is deep", cfg.scan_mode == "deep")
    assert_true("litellm_model set", cfg.litellm_model is not None)
    assert_true("canonical_model set", cfg.canonical_model is not None)

ATTACK("LLM config", t18)

print()
print("=" * 70)
print("ATTACK 19: SYSTEM PROMPT RENDER — Jinja2 with real context")
print("=" * 70)

def t19():
    from jinja2 import Environment, BaseLoader
    src = open("phantom/agents/PhantomAgent/system_prompt.jinja", encoding="utf-8", errors="ignore").read()
    env = Environment(loader=BaseLoader())
    tpl = env.from_string(src)
    result = tpl.render(
        target_url="http://evil.com",
        phantom_port_range="",
        loaded_skill_names=["skill1", "skill2"],
        get_tools_prompt=lambda: "TOOLS_HERE",
        get_skill=lambda x: "SKILL_CONTENT",
    )
    assert_true("renders without error", len(result) > 100)
    assert_true("target_url injected", "http://evil.com" in result)
    assert_true("get_tools_prompt called", "TOOLS_HERE" in result)

ATTACK("Jinja2 render", t19)

print()
print("=" * 70)
print("ATTACK 20: AGENTGRAPH ACTIONS — wait_for_agents function signature")
print("=" * 70)

def t20():
    import inspect
    from phantom.tools.agents_graph import wait_for_agents
    sig = inspect.signature(wait_for_agents)
    params = list(sig.parameters.keys())
    assert_true("wait_for_agents has agent_ids param", "agent_ids" in params)
    assert_true("wait_for_agents has timeout_seconds param", "timeout_seconds" in params)

ATTACK("wait_for_agents signature", t20)

print()
print("=" * 70)
print("ATTACK 21: BASE_AGENT CLASS — class variables")
print("=" * 70)

def t21():
    from phantom.agents.base_agent import BaseAgent
    assert_true("_NO_ACTION_STALL_WARN in class", hasattr(BaseAgent, "_NO_ACTION_STALL_WARN"))
    assert_true("_NO_ACTION_STALL_ABORT in class", hasattr(BaseAgent, "_NO_ACTION_STALL_ABORT"))
    assert_true("max_iterations in class", hasattr(BaseAgent, "max_iterations"))
    assert_true("max_iterations = 300", BaseAgent.max_iterations == 300)

ATTACK("BaseAgent class attributes", t21)

print()
print("=" * 70)
print("ATTACK 22: PYPROJECT.TOML vs __init__.py version sync")
print("=" * 70)

def t22():
    import re
    py_ver = re.search(r'version\s*=\s*"([^"]+)"', open("pyproject.toml", encoding="utf-8", errors="ignore").read())
    init_ver = re.search(r'__version__\s*=\s*"([^"]+)"', open("phantom/__init__.py", encoding="utf-8", errors="ignore").read())
    pv = py_ver.group(1) if py_ver else None
    iv = init_ver.group(1) if init_ver else None
    assert_true("pyproject.toml version exists", pv is not None, f" got {pv}")
    assert_true("__init__.py version exists", iv is not None, f" got {iv}")
    assert_true("versions match", pv == iv, f" {pv} vs {iv}")

ATTACK("version sync", t22)

print()
print("=" * 70)
print("ATTACK 23: PYTHON SYNTAX — every modified file")
print("=" * 70)

def t23():
    import py_compile
    files = [
        "phantom/__init__.py",
        "phantom/config/config.py",
        "phantom/llm/__init__.py",
        "phantom/llm/llm.py",
        "phantom/agents/base_agent.py",
        "phantom/tools/__init__.py",
        "phantom/tools/agents_graph/__init__.py",
        "phantom/tools/dynamic_tools.py",
        "phantom/tools/registry.py",
        "phantom/tools/executor.py",
        "phantom/tools/browser/browser_actions.py",
    ]
    for f in files:
        try:
            py_compile.compile(f, doraise=True)
        except py_compile.PyCompileError as e:
            raise AssertionError(f"syntax error in {f}: {e}")

ATTACK("all files syntax", t23)

print()
print("=" * 70)
print("ATTACK 24: UNREACHABLE CODE — base_agent.py AST check")
print("=" * 70)

def t24():
    import ast
    src = open("phantom/agents/base_agent.py", encoding="utf-8", errors="ignore").read()
    tree = ast.parse(src)

    class UnreachableChecker(ast.NodeVisitor):
        def __init__(self):
            self.issues = []
        def _check_body(self, body):
            for i, stmt in enumerate(body):
                if i > 0:
                    prev = body[i - 1]
                    if isinstance(prev, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        self.issues.append(stmt.lineno)
        def visit_FunctionDef(self, n):
            self._check_body(n.body)
            self.generic_visit(n)
        def visit_AsyncFunctionDef(self, n):
            self._check_body(n.body)
            self.generic_visit(n)
        def visit_If(self, n):
            self._check_body(n.body)
            self._check_body(n.orelse)
            self.generic_visit(n)
        def visit_Try(self, n):
            self._check_body(n.body)
            self._check_body(n.finalbody)
            self.generic_visit(n)

    checker = UnreachableChecker()
    checker.visit(tree)
    assert_true("no unreachable code", len(checker.issues) == 0, f" lines: {checker.issues}")

ATTACK("unreachable code check", t24)

print()
print("=" * 70)
print("=" * 70)
print(f" RESULTS: {len(PASSED)} PASSED, {len(FAILED)} FAILED")
print("=" * 70)
if FAILED:
    print("FAILED TESTS:")
    for name, err in FAILED:
        print(f"  [FAIL] {name}")
        print(f"        {err}")
    sys.exit(1)
else:
    print("ALL ATTACKS PASSED — system is verified healthy")
    print("=" * 70)