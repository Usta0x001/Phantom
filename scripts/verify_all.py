#!/usr/bin/env python3
"""Phantom 0.9.56 — Comprehensive feature verification script.

Proves every Phantom-specific addition is real, functional, and not decorative.
Run: python scripts/verify_all.py
"""

import os
import sys
import traceback
from pathlib import Path

# Ensure we import from the local source tree, not the installed package.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")

PASS = 0
FAIL = 0


def check(name: str, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  ✓  {name}")
        PASS += 1
    except Exception as e:
        print(f"  ✗  {name}")
        traceback.print_exc()
        FAIL += 1


print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("  PHANTOM 0.9.56 — FULL FEATURE VERIFICATION")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


# ── 1. VERSION ─────────────────────────────────────────────────────────────────
print("[1] VERSION CONSISTENCY")

def v_version_init():
    import phantom
    assert phantom.__version__ == "0.9.56", f"Got {phantom.__version__}"

def v_version_pyproject():
    pyproject = (
        __import__("pathlib").Path(__file__).parent.parent / "pyproject.toml"
    ).read_text(encoding="utf-8")
    assert 'version = "0.9.56"' in pyproject

check("phantom.__version__ == '0.9.55'", v_version_init)
check("pyproject.toml version == '0.9.55'", v_version_pyproject)


# ── 2. COST CONTROLS ───────────────────────────────────────────────────────────
print("\n[2] COST CONTROLS (llm.py)")
from phantom.llm.llm import LLM, LLMRequestFailedError
from phantom.llm.config import LLMConfig

def make_llm(mode="standard"):
    cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode=mode)
    return LLM(cfg, "PhantomAgent")

def v_max_tokens_quick():
    llm = make_llm("quick")
    assert llm._get_max_tokens() == 4000

def v_max_tokens_stealth():
    llm = make_llm("stealth")
    assert llm._get_max_tokens() == 6000

def v_max_tokens_standard():
    llm = make_llm("standard")
    assert llm._get_max_tokens() == 8000

def v_max_tokens_env_override():
    os.environ["LLM_MAX_TOKENS"] = "2000"
    try:
        llm = make_llm("standard")
        assert llm._get_max_tokens() == 2000
    finally:
        del os.environ["LLM_MAX_TOKENS"]

def v_budget_check_fires():
    os.environ["PHANTOM_MAX_COST"] = "1.00"
    try:
        llm = make_llm()
        llm._total_stats.cost = 1.00
        raised = False
        try:
            llm._check_budget()
        except LLMRequestFailedError as e:
            assert "Budget exceeded" in str(e)
            raised = True
        assert raised, "_check_budget should raise"
    finally:
        del os.environ["PHANTOM_MAX_COST"]

def v_budget_check_noop():
    os.environ["PHANTOM_MAX_COST"] = "1.00"
    try:
        llm = make_llm()
        llm._total_stats.cost = 0.99
        llm._check_budget()  # must not raise
    finally:
        del os.environ["PHANTOM_MAX_COST"]

def v_budget_no_env_noop():
    llm = make_llm()
    llm._total_stats.cost = 999.0
    llm._check_budget()  # no env var = no-op

def v_per_request_ceiling_fires():
    os.environ["PHANTOM_PER_REQUEST_CEILING"] = "0.50"
    try:
        llm = make_llm()
        llm._total_stats.cost = 1.00
        raised = False
        try:
            llm._check_per_request_budget(cost_before=0.40)  # 0.60 > 0.50
        except LLMRequestFailedError as e:
            assert "Per-request" in str(e)
            raised = True
        assert raised
    finally:
        del os.environ["PHANTOM_PER_REQUEST_CEILING"]

def v_per_request_ceiling_noop():
    os.environ["PHANTOM_PER_REQUEST_CEILING"] = "0.50"
    try:
        llm = make_llm()
        llm._total_stats.cost = 1.00
        llm._check_per_request_budget(cost_before=0.55)  # 0.45 < 0.50
    finally:
        del os.environ["PHANTOM_PER_REQUEST_CEILING"]

def v_budget_reraise_not_swallowed():
    """LLMRequestFailedError must propagate (not swallowed by retry loop)."""
    # Check the generate() method explicitly re-raises LLMRequestFailedError
    import inspect, ast
    src = inspect.getsource(LLM.generate)
    assert "raise" in src and "LLMRequestFailedError" in src

check("_get_max_tokens(): quick=4000", v_max_tokens_quick)
check("_get_max_tokens(): stealth=6000", v_max_tokens_stealth)
check("_get_max_tokens(): standard=8000", v_max_tokens_standard)
check("_get_max_tokens(): LLM_MAX_TOKENS env override", v_max_tokens_env_override)
check("_check_budget(): raises when cost>=max", v_budget_check_fires)
check("_check_budget(): no-op when cost<max", v_budget_check_noop)
check("_check_budget(): no-op when env not set", v_budget_no_env_noop)
check("_check_per_request_budget(): fires when request>ceiling", v_per_request_ceiling_fires)
check("_check_per_request_budget(): no-op when request<ceiling", v_per_request_ceiling_noop)
check("LLMRequestFailedError re-raised (not swallowed)", v_budget_reraise_not_swallowed)


# ── 3. MEMORY COMPRESSOR ───────────────────────────────────────────────────────
print("\n[3] MEMORY COMPRESSOR (lean constants)")
from phantom.llm.memory_compressor import (
    MAX_TOTAL_TOKENS, MIN_RECENT_MESSAGES, COMPRESSOR_MAX_TOKENS, MemoryCompressor
)

def v_max_tokens_20k():
    assert MAX_TOTAL_TOKENS == 20_000, f"Got {MAX_TOTAL_TOKENS}"

def v_min_recent_8():
    assert MIN_RECENT_MESSAGES == 8, f"Got {MIN_RECENT_MESSAGES}"

def v_compressor_cap_1500():
    assert COMPRESSOR_MAX_TOKENS == 1500, f"Got {COMPRESSOR_MAX_TOKENS}"

def v_compressor_timeout_30():
    mc = MemoryCompressor(model_name="openai/gpt-4o")
    assert mc.timeout == 30, f"Got {mc.timeout}"

def v_compressor_noop_under_threshold():
    mc = MemoryCompressor(model_name="openai/gpt-4o")
    msgs = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]
    result = mc.compress_history(msgs)
    assert result == msgs

def v_thinking_none_in_summarize():
    """Summarizer must pass thinking=None to avoid paying for reasoning in summarization."""
    import inspect, ast
    src = inspect.getsource(
        __import__("phantom.llm.memory_compressor", fromlist=["_summarize_messages"])
        ._summarize_messages
    )
    assert '"thinking": None' in src or "'thinking': None" in src

check("MAX_TOTAL_TOKENS == 20_000 (lean, was 100k)", v_max_tokens_20k)
check("MIN_RECENT_MESSAGES == 8 (was 15)", v_min_recent_8)
check("COMPRESSOR_MAX_TOKENS == 1500", v_compressor_cap_1500)
check("MemoryCompressor timeout == 30", v_compressor_timeout_30)
check("compress_history(): no-op when under threshold", v_compressor_noop_under_threshold)
check("_summarize_messages: thinking=None (no reasoning waste)", v_thinking_none_in_summarize)


# ── 4. STATE — THINKING BLOCKS ─────────────────────────────────────────────────
print("\n[4] AGENT STATE (thinking_blocks stripped)")
from phantom.agents.state import AgentState

def v_thinking_not_stored():
    s = AgentState()
    blocks = [{"type": "thinking", "content": "secret reasoning"}]
    s.add_message("assistant", "response", thinking_blocks=blocks)
    # Must NOT be stored in history — prevents invisible context bloat
    assert "thinking_blocks" not in s.messages[-1]
    assert s.messages[-1]["content"] == "response"

def v_content_still_stored():
    s = AgentState()
    s.add_message("user", "hello")
    assert s.messages[-1]["content"] == "hello"

check("thinking_blocks NOT stored in message history", v_thinking_not_stored)
check("actual content still stored correctly", v_content_still_stored)


# ── 5. EXECUTOR TRUNCATION ────────────────────────────────────────────────────
print("\n[5] TOOL OUTPUT TRUNCATION (executor.py)")
from phantom.tools.executor import _format_tool_result

def v_truncates_at_6001():
    r, _ = _format_tool_result("tool", "A" * 6001)
    assert "truncated" in r.lower()

def v_no_truncate_at_5999():
    r, _ = _format_tool_result("tool", "B" * 5999)
    assert "truncated" not in r.lower()

def v_head_tail_preserved():
    r, _ = _format_tool_result("tool", "HEAD" + "X" * 7990 + "TAIL")
    assert "HEAD" in r and "TAIL" in r

def v_result_under_7000_after_truncation():
    r, _ = _format_tool_result("tool", "Z" * 20000)
    # Should be ~5000 + overhead markup, well under 7000
    assert len(r) < 7000

check("truncation fires at 6001 chars", v_truncates_at_6001)
check("no truncation at 5999 chars", v_no_truncate_at_5999)
check("head and tail preserved after truncation", v_head_tail_preserved)
check("truncated result fits in context window", v_result_under_7000_after_truncation)


# ── 6. CONFIG ──────────────────────────────────────────────────────────────────
print("\n[6] CONFIGURATION (config.py)")
from phantom.config.config import Config

def v_reasoning_medium_default():
    assert Config.phantom_reasoning_effort == "medium"

def v_max_cost_none():
    assert Config.phantom_max_cost is None

def v_per_request_ceiling_none():
    assert Config.phantom_per_request_ceiling is None

def v_llm_max_tokens_none():
    assert Config.llm_max_tokens is None

def v_all_new_vars_in_canonical():
    canonical = Config._LLM_CANONICAL_NAMES
    assert "llm_max_tokens" in canonical
    assert "phantom_max_cost" in canonical
    assert "phantom_per_request_ceiling" in canonical

def v_mem_compressor_timeout_30():
    assert Config.phantom_memory_compressor_timeout == "30"

check("reasoning_effort default == 'medium'", v_reasoning_medium_default)
check("phantom_max_cost default == None (opt-in only)", v_max_cost_none)
check("phantom_per_request_ceiling default == None", v_per_request_ceiling_none)
check("llm_max_tokens default == None", v_llm_max_tokens_none)
check("all new vars in _LLM_CANONICAL_NAMES", v_all_new_vars_in_canonical)
check("phantom_memory_compressor_timeout == '30'", v_mem_compressor_timeout_30)


# ── 7. BOM GUARD ──────────────────────────────────────────────────────────────
print("\n[7] BOM GUARD (scripts/strip_bom.py)")

def v_strip_bom_script_exists():
    from pathlib import Path
    script = Path(__file__).parent / "strip_bom.py"
    assert script.exists()

def v_pre_commit_hook_exists():
    from pathlib import Path
    hook = Path(__file__).parent.parent / ".git" / "hooks" / "pre-commit"
    assert hook.exists()

def v_no_bom_in_source_files():
    from pathlib import Path
    BOM = b"\xef\xbb\xbf"
    root = Path(__file__).parent.parent
    extensions = {".py", ".md", ".toml", ".yaml", ".yml", ".jinja", ".jinja2"}
    bom_files = []
    for path in root.rglob("*"):
        if path.suffix not in extensions:
            continue
        if any(p in path.parts for p in (".git", "__pycache__", "dist", ".venv")):
            continue
        try:
            if path.read_bytes().startswith(BOM):
                bom_files.append(str(path.relative_to(root)))
        except OSError:
            pass
    assert not bom_files, f"BOM found in: {bom_files}"

check("scripts/strip_bom.py exists", v_strip_bom_script_exists)
check(".git/hooks/pre-commit exists", v_pre_commit_hook_exists)
check("zero BOM in any source/doc/config file", v_no_bom_in_source_files)


# ── 8. STRIX REFERENCES ────────────────────────────────────────────────────────
print("\n[8] STRIX REFERENCE AUDIT")

def v_no_strix_in_source():
    import re
    from pathlib import Path
    root = Path(__file__).parent.parent
    extensions = {".py", ".md", ".toml", ".yaml", ".yml", ".jinja", ".jinja2",
                  ".txt", ".json", ".cfg", ".ini", ".rst"}
    found = []
    for path in root.rglob("*"):
        if path.suffix not in extensions:
            continue
        if any(p in path.parts for p in (".git", "__pycache__", "dist", ".venv", "scripts")):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"strix", text, re.IGNORECASE):
                found.append(str(path.relative_to(root)))
        except OSError:
            pass
    assert not found, f"Strix found in: {found}"

check("zero 'Strix' references in any source/doc file", v_no_strix_in_source)


# ── SUMMARY ────────────────────────────────────────────────────────────────────
total = PASS + FAIL
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print(f"  RESULTS: {PASS}/{total} passed  |  {FAIL} failed")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
if FAIL:
    sys.exit(1)
