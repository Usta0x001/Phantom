"""
END-TO-END FINDINGS — ADVERSARIAL ATTACK SUITE
Tests for remaining CRITICAL/HIGH issues from END_TO_END_EXECUTION.md
"""

import ast
import asyncio
from pathlib import Path


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("END-TO-END FINDINGS — ADVERSARIAL ATTACK SUITE")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 1: tool_server.py must re-raise asyncio.CancelledError
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 1] tool_server.py re-raises asyncio.CancelledError...")

src_ts = Path("phantom/runtime/tool_server.py").read_text(encoding="utf-8")
# Find the except block
tree = ast.parse(src_ts)
found_re_raise = False
for node in ast.walk(tree):
    if isinstance(node, ast.ExceptHandler):
        type_name = None
        if isinstance(node.type, ast.Name):
            type_name = node.type.id
        elif isinstance(node.type, ast.Attribute):
            type_name = node.type.attr
        if type_name == "CancelledError":
            # Check body for 'raise' statement (not 'return')
            for stmt in node.body:
                if isinstance(stmt, ast.Raise):
                    found_re_raise = True
                    break
                elif isinstance(stmt, ast.Return):
                    found_re_raise = False
                    break

assert_true(
    "CancelledError is re-raised",
    found_re_raise,
    "tool_server.py swallows CancelledError instead of re-raising",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 2: reset_all_state() only runs when no agents active
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 2] reset_all_state() conditional on empty agent graph...")

src_ba = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
assert_true(
    "reset_all_state wrapped in conditional",
    "if not getattr(agents_graph_actions, \"_global_agents\", None):" in src_ba,
    "reset_all_state still unconditional",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 3: SHA-256 replaced with string comparison
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 3] SHA-256 scan status check removed...")

assert_true(
    "no hashlib.sha256 in _process_iteration",
    "hashlib.sha256" not in src_ba,
    "expensive SHA-256 still present",
)
assert_true(
    "string comparison used instead",
    "_last_status_msg" in src_ba and "_last_status_msg_hash" not in src_ba,
    "string comparison not found or old hash attr still present",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 4: Phase gate injected as system message
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 4] Phase gate message injected as system, not user...")

# Find the phase gate block
lines = src_ba.splitlines()
in_gate = False
gate_line = None
for i, line in enumerate(lines):
    if "FINAL WARNING" in line:
        in_gate = True
    if in_gate and "add_message" in line:
        gate_line = line
        break

assert_true(
    "phase gate uses system role",
    gate_line and '"system"' in gate_line,
    f"phase gate line: {gate_line}",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 5: Inline audit imports removed from hot loop
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 5] Inline audit imports eliminated from base_agent.py...")

inline_count = src_ba.count("from phantom.logging.audit import get_audit_logger as _get_audit")
assert_true(
    "only module-level audit import remains",
    inline_count == 1,
    f"found {inline_count} inline audit imports (expected 1 module-level)",
)
assert_true(
    "module-level _get_audit_logger imported",
    "from phantom.logging.audit import get_audit_logger as _get_audit_logger" in src_ba,
    "module-level import missing",
)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK 6: LLM instances get isolated SharedLLMState by default
# ═══════════════════════════════════════════════════════════════════════════
print("\n[ATTACK 6] LLM instances isolated by default...")

src_llm = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
assert_true(
    "__init__ accepts shared_state parameter",
    "shared_state: SharedLLMState | None = None" in src_llm,
    "shared_state parameter missing",
)
assert_true(
    "default creates fresh SharedLLMState",
    "shared_state or SharedLLMState()" in src_llm,
    "default still uses singleton",
)

# Functional test
from phantom.llm.llm import LLM, LLMConfig, SharedLLMState

llm_a = LLM(LLMConfig(), agent_name="A")
llm_b = LLM(LLMConfig(), agent_name="B")
assert_true(
    "two LLMs have different _shared_state",
    llm_a._shared_state is not llm_b._shared_state,
    "LLM instances still share state",
)

# Explicit sharing still works
shared = SharedLLMState()
llm_c = LLM(LLMConfig(), agent_name="C", shared_state=shared)
llm_d = LLM(LLMConfig(), agent_name="D", shared_state=shared)
assert_true(
    "explicit shared_state still works",
    llm_c._shared_state is llm_d._shared_state is shared,
    "explicit sharing broken",
)


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL END-TO-END ATTACKS PASSED")
print("=" * 70)
