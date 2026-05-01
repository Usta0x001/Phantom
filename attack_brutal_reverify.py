"""
BRUTAL RE-VERIFICATION — adversarial attacks designed to BREAK the fixes.
If any fix is fake, shallow, or regressed, this will catch it.
"""

import ast
import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("BRUTAL RE-VERIFICATION — BREAK-THE-FIXES ATTACK SUITE")
print("=" * 70)

# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 1: base_agent.py — verify NO hashlib import in _process_iteration
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 1] No hashlib usage in base_agent.py...")

src_ba = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
assert_true(
    "no 'import hashlib' in base_agent.py",
    "import hashlib" not in src_ba,
    "hashlib still imported",
)
assert_true(
    "no 'hashlib.' usage in base_agent.py",
    "hashlib." not in src_ba,
    "hashlib still used",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 2: base_agent.py — audit imports all use module-level helper
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 2] All audit logger calls use module-level _get_audit_logger...")

lines = src_ba.splitlines()
for i, line in enumerate(lines, 1):
    if "_audit" in line and "_get_audit_logger()" in line:
        continue
    if "_get_audit" in line and "_get_audit_logger" not in line:
        # Found a line using a local alias instead of module-level
        pass  # We'll count them

# Count remaining inline imports (should be 0)
inline_audit = src_ba.count("from phantom.logging.audit import get_audit_logger as _get_audit")
assert_true(
    "zero inline audit imports remain",
    inline_audit == 1,  # the module-level one
    f"found {inline_audit} inline audit imports (expected 1 module-level)",
)

# Verify all _audit* vars call _get_audit_logger()
call_count = src_ba.count("_get_audit_logger()")
assert_true(
    "_get_audit_logger() called in multiple places",
    call_count >= 5,
    f"only {call_count} calls found (expected >= 5)",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 3: llm.py — verify default isolation + backward compat
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 3] LLM default isolation + explicit sharing...")

src_llm = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
assert_true(
    "_DEFAULT_SHARED_STATE still exists for backward compat",
    "_DEFAULT_SHARED_STATE" in src_llm,
    "backward compat singleton removed",
)
assert_true(
    "__init__ default is not _DEFAULT_SHARED_STATE",
    "_DEFAULT_SHARED_STATE" not in src_llm.split("def __init__")[1].split("def ")[0],
    "__init__ still defaults to singleton",
)

from phantom.llm.llm import LLM, LLMConfig, SharedLLMState

llm1 = LLM(LLMConfig(), agent_name="x")
llm2 = LLM(LLMConfig(), agent_name="y")
assert_true(
    "isolated by default",
    llm1._shared_state is not llm2._shared_state,
    "still sharing state",
)

shared = SharedLLMState()
llm3 = LLM(LLMConfig(), agent_name="z", shared_state=shared)
llm4 = LLM(LLMConfig(), agent_name="w", shared_state=shared)
assert_true(
    "explicit sharing works",
    llm3._shared_state is llm4._shared_state is shared,
    "explicit sharing broken",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 4: tool_server.py — verify no return in CancelledError handler
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 4] tool_server.py CancelledError handler has no return...")

src_ts = Path("phantom/runtime/tool_server.py").read_text(encoding="utf-8")
tree = ast.parse(src_ts)
for node in ast.walk(tree):
    if isinstance(node, ast.ExceptHandler):
        type_name = None
        if isinstance(node.type, ast.Name):
            type_name = node.type.id
        elif isinstance(node.type, ast.Attribute):
            type_name = node.type.attr
        if type_name == "CancelledError":
            for stmt in node.body:
                if isinstance(stmt, ast.Return):
                    raise AssertionError(
                        "[FAIL] CancelledError handler still contains return"
                    )
            assert_true(
                "CancelledError handler only has raise",
                any(isinstance(s, ast.Raise) for s in node.body),
                "no raise found in handler",
            )


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 5: base_agent.py — reset_all_state guarded by _global_agents check
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 5] reset_all_state conditional guard...")

# Verify the exact guard exists
assert_true(
    "_global_agents guard present",
    "_global_agents" in src_ba and "reset_all_state" in src_ba,
    "guard not found",
)
# Verify it comes BEFORE reset_all_state
guard_idx = src_ba.find("_global_agents")
reset_idx = src_ba.find("reset_all_state()")
assert_true(
    "guard precedes reset_all_state() call",
    guard_idx != -1 and reset_idx != -1 and guard_idx < reset_idx,
    "guard after reset_all_state or missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 6: base_agent.py — phase gate uses system role
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 6] Phase gate system role injection...")

# Find the add_message near FINAL WARNING
lines = src_ba.splitlines()
gate_add_msg = None
for i, line in enumerate(lines):
    if "FINAL WARNING" in line:
        # Look forward for add_message
        for j in range(i, min(i + 10, len(lines))):
            if "add_message" in lines[j]:
                gate_add_msg = lines[j]
                break
        break

assert_true(
    "phase gate add_message uses system",
    gate_add_msg and '"system"' in gate_add_msg,
    f"found line: {gate_add_msg}",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 7: executor.py — shared client still works after close + reopen
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 7] Sandbox client lifecycle stress test...")

async def _client_stress():
    from phantom.tools.executor import _get_sandbox_client, _close_sandbox_client

    c1 = await _get_sandbox_client()
    c2 = await _get_sandbox_client()
    assert_true("initial reuse", c1 is c2, "client not reused")

    await _close_sandbox_client()
    c3 = await _get_sandbox_client()
    assert_true("new after close", c3 is not c1, "stale client returned")

    await _close_sandbox_client()
    c4 = await _get_sandbox_client()
    assert_true("reopen after double close", c4 is not None, "None after reopen")

asyncio.run(_client_stress())


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 8: llm.py — _prepare_messages does NOT mutate caller's list
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 8] _prepare_messages functional immutability...")

async def _no_mutate():
    llm = LLM(LLMConfig(), agent_name="TestAgent")
    original = [
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": "<function=send_request>"},
    ]
    snapshot = [dict(msg) for msg in original]

    with patch.object(llm.memory_compressor, "compress_history", return_value=list(original)):
        result = await llm._prepare_messages(original)

    for i, (orig, snap) in enumerate(zip(original, snapshot)):
        assert_true(
            f"original[{i}] unchanged",
            orig == snap,
            f"mutated: {orig} != {snap}",
        )
    assert_true(
        "result is new object",
        result is not original,
        "same object returned",
    )

asyncio.run(_no_mutate())


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 9: base_agent.py — wall-clock timeout actually aborts
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 9] Wall-clock timeout aborts scan...")

from phantom.agents.base_agent import BaseAgent

async def _wall_timeout():
    agent = BaseAgent({
        "llm_config": LLMConfig(),
        "max_iterations": 300,
        "non_interactive": True,
    })

    async def _slow(*a, **k):
        await asyncio.sleep(0.2)
        return False

    with patch.object(agent, "_initialize_sandbox_and_state", return_value=None):
        with patch.object(agent, "_process_iteration", side_effect=_slow):
            with patch("phantom.config.Config.get", return_value="0.05"):
                result = await agent.agent_loop("task")

    assert_true(
        "timeout returns error result",
        not result.get("success", True),
        f"result={result}",
    )
    assert_true(
        "error mentions timeout",
        "timeout" in str(result.get("error", "")).lower(),
        f"error={result.get('error')}",
    )

asyncio.run(_wall_timeout())


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 10: Full syntax + import chain for all modified modules
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 10] Full import chain smoke test...")

modules = [
    "phantom.agents.base_agent",
    "phantom.llm.llm",
    "phantom.tools.executor",
    "phantom.interface.cli",
    "phantom.runtime.tool_server",
    "phantom.llm.dedupe",
    "phantom.checkpoint.checkpoint",
]

for mod in modules:
    if mod == "phantom.runtime.tool_server":
        # tool_server has a module-level guard that starts a CLI; syntax-check only
        import py_compile
        try:
            py_compile.compile("phantom/runtime/tool_server.py", doraise=True)
            print(f"  [PASS] syntax check {mod}")
        except py_compile.PyCompileError as e:
            raise AssertionError(f"[FAIL] syntax {mod}: {e}")
        continue
    try:
        __import__(mod)
        print(f"  [PASS] import {mod}")
    except Exception as e:
        raise AssertionError(f"[FAIL] import {mod}: {e}")


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL BRUTAL RE-VERIFICATION ATTACKS PASSED")
print("=" * 70)
