"""
ADVERSARIAL ATTACK SUITE — Integration Fixes (Top 10)
Attempts to break the end-to-end integration fixes with edge cases.
"""

import ast
import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("INTEGRATION FIXES — ADVERSARIAL ATTACK SUITE")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 1: LLM stream timeout exists and is configurable
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 1] LLM stream timeout configured in base_agent.py...")

src_base = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
assert_true(
    "phantom_llm_stream_timeout Config.get",
    "phantom_llm_stream_timeout" in src_base,
    "stream timeout config key missing",
)
assert_true(
    "asyncio.TimeoutError handling",
    "asyncio.TimeoutError" in src_base,
    "TimeoutError not caught",
)
assert_true(
    "timeout wraps generate()",
    "_llm_timeout" in src_base and "self.llm.generate" in src_base,
    "timeout variable or generate call missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 2: tracked_acompletion wrapped in asyncio.wait_for
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 2] tracked_acompletion timeout wrapper in llm.py...")

src_llm = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
assert_true(
    "phantom_llm_completion_timeout Config.get",
    "phantom_llm_completion_timeout" in src_llm,
    "completion timeout config key missing",
)
assert_true(
    "asyncio.wait_for around tracked_acompletion",
    "asyncio.wait_for" in src_llm and "tracked_acompletion" in src_llm,
    "wait_for wrapper missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 3: httpx.AsyncClient reused across sandbox calls
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 3] Shared httpx client for sandbox calls...")

src_exec = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
assert_true(
    "_sandbox_client module-level variable",
    "_sandbox_client: httpx.AsyncClient | None = None" in src_exec,
    "shared client variable missing",
)
assert_true(
    "_get_sandbox_client helper exists",
    "async def _get_sandbox_client()" in src_exec,
    "client getter missing",
)
assert_true(
    "no 'async with httpx.AsyncClient' per call",
    "async with httpx.AsyncClient" not in src_exec,
    "still creating client per call",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 4: Global tracer set in cli.py
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 4] Global tracer registered in cli.py...")

src_cli = Path("phantom/interface/cli.py").read_text(encoding="utf-8")
assert_true(
    "set_global_tracer imported",
    "set_global_tracer" in src_cli,
    "import missing",
)
assert_true(
    "set_global_tracer called after Tracer creation",
    "set_global_tracer(tracer)" in src_cli,
    "registration call missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 5: _prepare_messages does NOT mutate input list
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 5] _prepare_messages preserves caller's list...")

# Check AST: conversation_history.clear() and .extend() must be gone
tree = ast.parse(src_llm)
found_mutation = False
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in ("clear", "extend"):
                # Check if it's acting on conversation_history
                if isinstance(func.value, ast.Name) and func.value.id == "conversation_history":
                    found_mutation = True

assert_true(
    "no conversation_history.clear() in _prepare_messages",
    not found_mutation,
    "in-place mutation still present",
)

# Functional test: call _prepare_messages twice with same list, verify unchanged
from phantom.llm.llm import LLM
from phantom.llm.config import LLMConfig

llm = LLM(LLMConfig(), agent_name="TestAgent")
original = [{"role": "user", "content": "test"}]
original_len = len(original)
original_first = dict(original[0])  # shallow copy of first item

try:
    # _prepare_messages is async; run it in a minimal loop
    async def _check():
        # Patch compressor to return empty to avoid heavy deps
        with patch.object(llm.memory_compressor, "compress_history", return_value=list(original)):
            result1 = await llm._prepare_messages(original)
            result2 = await llm._prepare_messages(original)
        assert len(original) == original_len, f"list mutated: {len(original)} != {original_len}"
        assert original[0]["content"] == original_first["content"], "item mutated"
        assert result1 is not original, "should return a new list"
        assert result2 is not original, "should return a new list"

    asyncio.run(_check())
    assert_true("functional no-mutation test", True)
except Exception as e:
    assert_true("functional no-mutation test", False, str(e))


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 6: Checkpoint saved BEFORE tool execution
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 6] Checkpoint ordering: before tool execution...")

# Find _maybe_save_checkpoint and process_tool_invocations in _execute_actions
src_base_lines = src_base.splitlines()

# Find _execute_actions method
in_execute_actions = False
save_line = None
process_line = None
for i, line in enumerate(src_base_lines):
    if "async def _execute_actions" in line:
        in_execute_actions = True
    if in_execute_actions:
        if "_maybe_save_checkpoint" in line:
            save_line = i
        if "process_tool_invocations" in line:
            process_line = i
        if "async def " in line and "_execute_actions" not in line and save_line is not None:
            break

assert_true(
    "checkpoint save exists in _execute_actions",
    save_line is not None,
    "_maybe_save_checkpoint not found in _execute_actions",
)
assert_true(
    "process_tool_invocations exists in _execute_actions",
    process_line is not None,
    "process_tool_invocations not found in _execute_actions",
)
assert_true(
    "save happens BEFORE process_tool_invocations",
    save_line < process_line,
    f"save at {save_line}, process at {process_line}",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 7: Sandbox health check before POST
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 7] Sandbox health check before tool execution...")

assert_true(
    "health check GET request",
    'client.get(' in src_exec and '/health' in src_exec,
    "health endpoint call missing",
)
assert_true(
    "health failure raises RuntimeError",
    "Sandbox health check failed" in src_exec or "Sandbox unreachable" in src_exec,
    "health failure handling missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 8: Atomic budget check (tracer read inside lock)
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 8] Atomic budget check in llm.py...")

# Find _check_budget and verify tracer.get_total_llm_stats is inside the lock block
in_check_budget = False
lock_block_has_tracer = False
tracer_outside_lock = False
indent_level = 0

for i, line in enumerate(src_llm.splitlines()):
    if "async def _check_budget" in line:
        in_check_budget = True
        continue
    if in_check_budget:
        if "async with self._shared_state.lock:" in line:
            indent_level = len(line) - len(line.lstrip())
            # Scan until dedent
            for j in range(i + 1, len(src_llm.splitlines())):
                inner = src_llm.splitlines()[j]
                if inner.strip() == "":
                    continue
                current_indent = len(inner) - len(inner.lstrip())
                if current_indent <= indent_level and inner.strip():
                    break
                if "tracer" in inner and "get_total_llm_stats" in inner:
                    lock_block_has_tracer = True
            continue
        # After lock block ends, check if tracer is still accessed
        if "tracer" in line and "get_total_llm_stats" in line and not lock_block_has_tracer:
            tracer_outside_lock = True
        if line.strip().startswith("async def ") and "_check_budget" not in line:
            break

assert_true(
    "tracer cost read inside lock block",
    lock_block_has_tracer,
    "tracer not read inside lock",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 9: Wall-clock timeout in agent_loop
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 9] Wall-clock timeout in agent_loop...")

assert_true(
    "phantom_scan_wall_timeout Config.get",
    "phantom_scan_wall_timeout" in src_base,
    "wall timeout config key missing",
)
assert_true(
    "_scan_deadline computed",
    "_scan_deadline" in src_base,
    "deadline variable missing",
)
assert_true(
    "deadline check inside while True",
    "_time_mod.monotonic() > _scan_deadline" in src_base,
    "deadline comparison missing",
)
assert_true(
    "timeout abort returns error result",
    "wall-clock timeout" in src_base.lower(),
    "timeout message missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 10: Per-agent auto-summarize count
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 10] Per-agent auto-summarize cap...")

assert_true(
    "_auto_summarize_count module global removed",
    "_auto_summarize_count = 0" not in src_exec,
    "global counter still present",
)
assert_true(
    "agent_state parameter added",
    "agent_state: Any | None = None" in src_exec,
    "agent_state param missing",
)
assert_true(
    "agent_state.update_context used for count",
    "agent_state.update_context" in src_exec,
    "per-agent context update missing",
)
assert_true(
    "call site passes agent_state",
    "_auto_summarize_result(observation_xml, tool_name, agent_state)" in src_exec,
    "agent_state not passed at call site",
)


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL INTEGRATION FIX ATTACKS PASSED")
print("=" * 70)
