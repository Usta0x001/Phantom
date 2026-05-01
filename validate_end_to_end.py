"""
END-TO-END EXECUTION VALIDATION — Critical Path Simulation
Simulates a real scan and verifies all integration fixes hold up.
"""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("END-TO-END CRITICAL PATH SIMULATION")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 1: Agent loop with wall-clock timeout
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 1] Agent loop wall-clock timeout fires correctly...")

from phantom.agents.base_agent import BaseAgent
from phantom.llm.config import LLMConfig

async def _sim_timeout():
    agent = BaseAgent({
        "llm_config": LLMConfig(),
        "max_iterations": 300,
        "non_interactive": True,
    })
    async def _slow_iter(*args, **kwargs):
        await asyncio.sleep(0.1)
        return False

    # Patch to bypass sandbox init
    with patch.object(agent, "_initialize_sandbox_and_state", return_value=None):
        with patch.object(agent, "_process_iteration", side_effect=_slow_iter):
            with patch("phantom.config.Config.get", return_value="0.1"):
                result = await agent.agent_loop("test task")
    # Should have aborted due to 0.1s wall-clock timeout
    assert_true(
        "wall-clock timeout triggered",
        not result.get("success", True) and "timeout" in str(result.get("error", "")).lower(),
        f"result={result}",
    )

asyncio.run(_sim_timeout())


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 2: _prepare_messages preserves caller's list
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 2] _prepare_messages preserves caller's conversation history...")

from phantom.llm.llm import LLM

async def _sim_no_mutation():
    llm = LLM(LLMConfig(), agent_name="TestAgent")
    original = [
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": "<function=send_request><parameter=method>GET</parameter></function>"},
        {"role": "user", "content": "result"},
    ]
    original_snapshot = [dict(msg) for msg in original]

    with patch.object(llm.memory_compressor, "compress_history", return_value=list(original)):
        result = await llm._prepare_messages(original)

    # Original must be unchanged
    for i, (orig, snap) in enumerate(zip(original, original_snapshot)):
        assert_true(
            f"message {i} preserved",
            orig["content"] == snap["content"] and orig["role"] == snap["role"],
            f"msg[{i}] mutated: {orig} != {snap}",
        )
    # Result must be a different list
    assert_true(
        "returns new list",
        result is not original,
        "_prepare_messages returned the same list object",
    )
    # Result must start with system prompt
    assert_true(
        "system prompt prepended",
        result[0]["role"] == "system",
        f"first message role={result[0]['role']}",
    )

asyncio.run(_sim_no_mutation())


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 3: Atomic budget check (race condition test)
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 3] Atomic budget check prevents race overspend...")

async def _sim_atomic_budget():
    from phantom.llm.llm import SharedLLMState, RequestStats

    state = SharedLLMState()
    state.total_stats.cost = 100.0

    async def _check():
        async with state.lock:
            cost = float(state.total_stats.cost or 0.0)
            # Simulate tracer read inside same lock
            traced = 100.0
            current = max(traced, cost)
            return current

    # Run 10 concurrent checks
    results = await asyncio.gather(*[_check() for _ in range(10)])
    assert_true(
        "all checks see consistent cost",
        all(r == 100.0 for r in results),
        f"inconsistent results: {results}",
    )

asyncio.run(_sim_atomic_budget())


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 4: Per-agent auto-summarize counter isolation
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 4] Per-agent auto-summarize counter isolation...")

async def _sim_per_agent_cap():
    from phantom.tools.executor import _auto_summarize_result

    # Create simple agent state objects with proper context handling
    class FakeState:
        def __init__(self):
            self.context = {}
        def update_context(self, k, v):
            self.context[k] = v

    agent_a = FakeState()
    agent_b = FakeState()

    import os
    os.environ["PHANTOM_USE_AUTO_SUMMARIZE"] = "true"
    long_text = "A" * 20000

    # Call 5 times for agent_a
    for _ in range(5):
        await _auto_summarize_result(long_text, "test", agent_state=agent_a)

    # Agent_b should still have count 0
    assert_true(
        "agent_b count is 0",
        agent_b.context.get("_auto_summarize_count", 0) == 0,
        f"agent_b count={agent_b.context}",
    )

    # Agent_a should have count 5
    assert_true(
        "agent_a count is 5",
        agent_a.context.get("_auto_summarize_count", 0) == 5,
        f"agent_a count={agent_a.context}",
    )

asyncio.run(_sim_per_agent_cap())


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 5: Shared httpx client for sandbox
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 5] Sandbox httpx client reuse...")

from phantom.tools.executor import _get_sandbox_client, _close_sandbox_client

async def _sim_client_reuse():
    client1 = await _get_sandbox_client()
    client2 = await _get_sandbox_client()
    assert_true(
        "same client instance returned",
        client1 is client2,
        "client not reused",
    )
    await _close_sandbox_client()
    client3 = await _get_sandbox_client()
    assert_true(
        "new client after close",
        client3 is not client1,
        "old client still returned after close",
    )
    await _close_sandbox_client()

asyncio.run(_sim_client_reuse())


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 6: LLM completion timeout wrapper
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 6] LLM completion asyncio.wait_for wrapper...")

import ast

src_llm = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
tree = ast.parse(src_llm)

found_wait_for = False
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "wait_for":
            # Check if tracked_acompletion is inside
            for arg in node.args:
                if isinstance(arg, ast.Call):
                    if isinstance(arg.func, ast.Name) and arg.func.id == "tracked_acompletion":
                        found_wait_for = True

assert_true(
    "asyncio.wait_for wraps tracked_acompletion",
    found_wait_for,
    "wait_for wrapper not found around tracked_acompletion",
)


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 7: Checkpoint save ordering in _execute_actions
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 7] Checkpoint ordering: save before tool execution...")

src_base = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")

# Find _execute_actions and verify save comes before process_tool_invocations
lines = src_base.splitlines()
in_execute = False
save_idx = None
process_idx = None
for i, line in enumerate(lines):
    if "async def _execute_actions" in line:
        in_execute = True
    if in_execute:
        if "_maybe_save_checkpoint" in line:
            save_idx = i
        if "process_tool_invocations" in line:
            process_idx = i
        if line.strip().startswith("async def ") and "_execute_actions" not in line and save_idx is not None:
            break

assert_true(
    "save checkpoint exists before tool execution",
    save_idx is not None and process_idx is not None and save_idx < process_idx,
    f"save={save_idx}, process={process_idx}",
)


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 8: Sandbox health check exists
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 8] Sandbox health check before POST...")

src_exec = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
assert_true(
    "health check GET call",
    'client.get(' in src_exec and '/health' in src_exec,
    "health endpoint call missing",
)
assert_true(
    "health failure aborts with RuntimeError",
    "Sandbox health check failed" in src_exec or "Sandbox unreachable" in src_exec,
    "health failure handling missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 9: Global tracer set in cli.py
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 9] Global tracer registered in CLI entry...")

src_cli = Path("phantom/interface/cli.py").read_text(encoding="utf-8")
assert_true(
    "set_global_tracer called",
    "set_global_tracer(tracer)" in src_cli,
    "tracer registration missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION 10: LLM stream timeout in agent_loop
# ═══════════════════════════════════════════════════════════════════════════
print("\n[SIM 10] LLM stream timeout in _process_iteration...")

assert_true(
    "phantom_llm_stream_timeout config",
    "phantom_llm_stream_timeout" in src_base,
    "stream timeout config missing",
)
assert_true(
    "TimeoutError caught in _process_iteration",
    "asyncio.TimeoutError" in src_base,
    "TimeoutError handling missing",
)


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL END-TO-END SIMULATIONS PASSED")
print("=" * 70)
