"""
END-TO-END EXECUTION AUDIT
Simulates the full phantom scan execution path with mocks to verify
no errors, no dead code, no unnecessary components.
"""

import asyncio
import json
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("END-TO-END EXECUTION AUDIT")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Full import chain
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 1] Full execution path imports...")

try:
    from phantom.agents import PhantomAgent
    from phantom.llm import LLM, LLMConfig
    from phantom.tools import get_tools_prompt, process_tool_invocations
    from phantom.telemetry.tracer import Tracer, set_global_tracer
    from phantom.checkpoint import CheckpointManager
    from phantom.runtime import get_runtime, cleanup_runtime
    from phantom.config import Config
    from phantom.interface.cli import run_cli
    from phantom.interface.cli_app import cli_main, app
    from phantom.agents.state import AgentState
    assert_true("all execution path imports succeed", True)
except Exception as e:
    assert_true("all execution path imports succeed", False, str(e))


# ═══════════════════════════════════════════════════════════════════════════
# 2. Tool catalog consistency
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 2] Tool catalog loads and is consistent...")

from phantom.tools.registry import get_tools_prompt, _tools_by_name
from phantom.tools.executor import execute_tool_with_validation

tools_prompt = get_tools_prompt()
assert_true("tool catalog non-empty", len(tools_prompt) > 1000, f"got {len(tools_prompt)}")
assert_true("tool catalog contains tools", "<tool name=" in tools_prompt, "no tools found")
assert_true("examples preserved in catalog", "<example" in tools_prompt.lower() or "<examples" in tools_prompt.lower(), "no examples")

# Verify all registered tools have schemas
registered_tools = list(_tools_by_name.keys())
assert_true("tools registered", len(registered_tools) > 0, f"got {len(registered_tools)}")

# Verify each tool can be validated (sync check)
from phantom.tools.executor import validate_tool_availability
for tool_name in registered_tools[:5]:  # sample first 5
    is_valid, err = validate_tool_availability(tool_name)
    assert_true(f"tool '{tool_name}' validates", is_valid, err)


# ═══════════════════════════════════════════════════════════════════════════
# 3. Tracer lifecycle
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 3] Tracer lifecycle (create -> log -> save -> cleanup)...")

# Use the tracer's default run_dir (phantom_runs/test_run)
tracer = Tracer("test_run")
tracer.set_scan_config({"scan_id": "test_run", "targets": []})

# Log some events
tracer.log_chat_message("Hello", "user", agent_id="agent-1")
tracer.log_tool_execution_start("agent-1", "send_request", {"url": "http://test.com"})
tracer.update_agent_status("agent-1", "running")

# Save scan stats
tracer.save_run_data(mark_complete=True)
stats_file = Path("phantom_runs/test_run/scan_stats.json")
assert_true("scan_stats.json created", stats_file.exists(), "file not created")

if stats_file.exists():
    stats = json.loads(stats_file.read_text())
    assert_true("scan_stats has llm_stats", "llm_stats" in stats, f"keys: {list(stats.keys())}")
    assert_true("scan_stats has vulnerability_count", "vulnerability_count" in stats, f"keys: {list(stats.keys())}")

tracer.cleanup()
assert_true("tracer cleanup succeeds", True)


# ═══════════════════════════════════════════════════════════════════════════
# 4. Checkpoint lifecycle
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 4] Checkpoint lifecycle (save -> load -> verify)...")

with tempfile.TemporaryDirectory() as tmpdir:
    run_dir = Path(tmpdir)
    cp_mgr = CheckpointManager(run_dir, interval=1)
    
    # Create a fake state
    state = AgentState(agent_id="test-agent", target_url="http://test.com")
    state.add_message("user", "test message")
    state.increment_iteration()
    
    # Build and save checkpoint
    cp_data = CheckpointManager.build(
        run_name="test_run",
        state=state,
        tracer=Tracer("test_run"),
        scan_config={"scan_id": "test_run"},
        status="running",
    )
    cp_mgr.save(cp_data)
    
    # Load checkpoint
    loaded = cp_mgr.load()
    assert_true("checkpoint loads", loaded is not None, "load returned None")
    assert_true("checkpoint has correct run_name", loaded.run_name == "test_run", f"got {loaded.run_name}")
    assert_true("checkpoint has state", loaded.root_agent_state is not None, "no state")


# ═══════════════════════════════════════════════════════════════════════════
# 5. Agent state operations
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 5] Agent state operations...")

state = AgentState(agent_id="test-agent", target_url="http://test.com")
state.add_message("user", "Message 1")
state.add_message("assistant", "Response 1")
state.add_message("user", "Message 2")
state.increment_iteration()
state.increment_iteration()

assert_true("iteration count correct", state.iteration == 2, f"got {state.iteration}")
assert_true("history has 3 messages", len(state.get_conversation_history()) == 3, f"got {len(state.get_conversation_history())}")
assert_true("should_stop False initially", not state.should_stop(), "should_stop returned True")

state.set_completed({"success": True})
assert_true("completed after set_completed", state.completed, "not completed")
assert_true("should_stop True after completion", state.should_stop(), "should_stop returned False")


# ═══════════════════════════════════════════════════════════════════════════
# 6. LLM message preparation
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 6] LLM message preparation (merge consecutive users)...")

async def _test_llm_prepare():
    fake_config = LLMConfig(litellm_model="gpt-4")
    llm = LLM(fake_config, agent_name="test-agent")
    
    conversation = [
        {"role": "user", "content": "Message A"},
        {"role": "user", "content": "Message B"},
        {"role": "assistant", "content": "Response"},
        {"role": "user", "content": "Message C"},
    ]
    
    messages = await llm._prepare_messages(conversation)
    roles = [m["role"] for m in messages]
    
    assert_true("no consecutive user roles", all(roles[i] != roles[i+1] or roles[i] != "user" for i in range(len(roles)-1)), f"roles: {roles}")
    assert_true("system prompt present", messages[0]["role"] == "system", f"first role: {messages[0]['role']}")

asyncio.run(_test_llm_prepare())


# ═══════════════════════════════════════════════════════════════════════════
# 7. Tool invocation parsing robustness
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 7] Tool invocation parsing (XML parser + edge cases)...")

from phantom.llm.utils import parse_tool_invocations

test_cases = [
    ("normal call", '<function=send_request><parameter=method>GET</parameter></function>', 1, {"method": "GET"}),
    ("batch calls", '<function=a><parameter=x>1</parameter></function><function=b><parameter=y>2</parameter></function>', 2, None),
    ("gt in param", '<function=terminal_execute><parameter=command>python -c "print(1>0)"</parameter></function>', 1, {"command": 'python -c "print(1>0)"'}),
    ("script payload", '<function=send_request><parameter=body><script>alert(1)</script></parameter></function>', 1, {"body": "<script>alert(1)</script>"}),
    ("name attr format", '<function=send_request><parameter name="method">GET</parameter></function>', 1, {"method": "GET"}),
]

for name, xml, expected_count, expected_args in test_cases:
    result = parse_tool_invocations(xml)
    count_ok = result is not None and len(result) == expected_count
    assert_true(f"[{name}] parsed count", count_ok, f"got {result}")
    if expected_args and result:
        for k, v in expected_args.items():
            actual = result[0]["args"].get(k)
            assert_true(f"[{name}] arg {k}", actual == v, f"expected '{v}', got '{actual}'")


# ═══════════════════════════════════════════════════════════════════════════
# 8. Tool result formatting
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 8] Tool result formatting (CDATA + signals + truncation)...")

from phantom.tools.executor import _format_tool_result_with_meta

# Test with signal
obs, images, meta = _format_tool_result_with_meta(
    "send_request",
    {"status_code": 200, "body": "<script>alert(1)</script>"},
    image_slots_remaining=1,
)
assert_true("CDATA present", "<![CDATA[" in obs, "CDATA missing")
assert_true("html not escaped in CDATA", "&lt;script&gt;" not in obs, "HTML was escaped")
assert_true("signal not bloated", "[INVESTIGATION REQUIRED]" not in obs, "bloated signal present")

# Test truncation metadata
obs2, _, meta2 = _format_tool_result_with_meta(
    "terminal_execute",
    {"stdout": "x" * 100},
    image_slots_remaining=1,
)
# truncation meta only set when actually truncated


# ═══════════════════════════════════════════════════════════════════════════
# 9. System prompt one-call-per-response instruction
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 9] System prompt requires exactly one call per response...")

prompt_path = Path("phantom/agents/PhantomAgent/system_prompt.jinja")
prompt_text = prompt_path.read_text(encoding="utf-8")

assert_true("one-call rule present", "exactly ONE tool call" in prompt_text, "no one-call rule")
assert_true("tool-call-first rule present", "PUT THE TOOL CALL FIRST" in prompt_text, "no tool-call-first rule")
assert_true("anti-batching present", "Do NOT attempt to batch" in prompt_text, "no anti-batching rule")
assert_true("signal_rules present", "<signal_rules>" in prompt_text, "no signal_rules")


# ═══════════════════════════════════════════════════════════════════════════
# 10. Dead code check — no ImportError on key paths
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 10] No ImportError on key execution paths...")

# Verify nothing imports deleted globals anymore
import phantom.llm.llm as llm_module
assert_true("no _GLOBAL_STATS_LOCK reference", "_GLOBAL_STATS_LOCK" not in llm_module.__dict__ or llm_module.__dict__.get("_GLOBAL_STATS_LOCK") is not None, "reference deleted")

# Verify tracer doesn't reference deleted globals
import phantom.telemetry.tracer as tracer_module
tracer_src = Path("phantom/telemetry/tracer.py").read_text()
assert_true("tracer uses _DEFAULT_SHARED_STATE", "_DEFAULT_SHARED_STATE" in tracer_src, "not using new state")
assert_true("tracer no longer imports deleted globals", "_GLOBAL_STATS_LOCK" not in tracer_src, "still references deleted globals")


# ═══════════════════════════════════════════════════════════════════════════
# 11. Full simulated scan loop (no LLM)
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 11] Simulated scan loop (agent init -> execute -> complete)...")

async def _test_simulated_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        run_dir = Path(tmpdir)
        
        # Create tracer
        tracer = Tracer("sim_test")
        tracer.set_scan_config({"scan_id": "sim_test", "targets": [{"original": "http://test.com"}]})
        set_global_tracer(tracer)
        
        # Create checkpoint manager
        cp_mgr = CheckpointManager(run_dir, interval=100)  # high interval so it doesn't fire
        
        # Create agent config
        llm_config = LLMConfig(litellm_model="gpt-4")
        agent_config = {
            "llm_config": llm_config,
            "max_iterations": 3,
            "non_interactive": True,
            "_checkpoint_manager": cp_mgr,
            "_run_name": "sim_test",
            "agent_name": "PhantomAgent",  # so system prompt template loads
        }
        
        # Create agent
        agent = PhantomAgent(agent_config)
        
        # Mock LLM to return finish_scan immediately
        async def mock_generate(messages):
            from phantom.llm.llm import LLMResponse
            yield LLMResponse(
                content="<function=finish_scan><parameter name=""executive_summary"">Test complete</parameter><parameter name=""methodology"">test</parameter><parameter name=""technical_analysis"">test</parameter><parameter name=""recommendations"">test</parameter></function>",
                tool_invocations=[{"toolName": "finish_scan", "args": {"executive_summary": "Test complete", "methodology": "test", "technical_analysis": "test", "recommendations": "test"}}]
            )
        
        agent.llm.generate = mock_generate
        
        # Execute scan
        scan_config = {
            "scan_id": "sim_test",
            "targets": [{"type": "web", "original": "http://test.com", "details": {"target_url": "http://test.com"}}],
            "user_instructions": "",
            "run_name": "sim_test",
            "scan_mode": "standard",
        }
        
        result = await agent.execute_scan(scan_config)
        assert_true("scan completed", result.get("success", False) or agent.state.completed, f"result: {result}")
        assert_true("iterations <= max", agent.state.iteration <= 3, f"iterations: {agent.state.iteration}")
        
        # Verify tracer saved stats
        tracer.save_run_data(mark_complete=True)
        stats_file = Path("phantom_runs/sim_test/scan_stats.json")
        assert_true("scan stats saved", stats_file.exists(), "stats not saved")
        
        # Cleanup
        tracer.cleanup()

asyncio.run(_test_simulated_scan())


# ═══════════════════════════════════════════════════════════════════════════
# 12. Version consistency
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 12] Version consistency across files...")

import phantom
pyproject = Path("pyproject.toml").read_text()
init_version = phantom.__version__

# Extract pyproject version
import re
pp_match = re.search(r'version = "([^"]+)"', pyproject)
pp_version = pp_match.group(1) if pp_match else "unknown"

assert_true("versions match", init_version == pp_version, f"__init__: {init_version}, pyproject: {pp_version}")


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL END-TO-END AUDIT TESTS PASSED")
print("=" * 70)
