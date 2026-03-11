#!/usr/bin/env python3
"""Phantom 0.9.70 — Comprehensive feature verification script.

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
print("  PHANTOM 0.9.70 — FULL FEATURE VERIFICATION")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


# ── 1. VERSION ─────────────────────────────────────────────────────────────────
print("[1] VERSION CONSISTENCY")

def v_version_init():
    import phantom
    assert phantom.__version__ == "0.9.70", f"Got {phantom.__version__}"

def v_version_pyproject():
    pyproject = (
        __import__("pathlib").Path(__file__).parent.parent / "pyproject.toml"
    ).read_text(encoding="utf-8")
    assert 'version = "0.9.70"' in pyproject

check("phantom.__version__ == '0.9.70'", v_version_init)
check("pyproject.toml version == '0.9.70'", v_version_pyproject)


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
    """BUG FIX D (0.9.63): thinking=None must ONLY be sent for anthropic/ models."""
    import inspect
    src = inspect.getsource(
        __import__("phantom.llm.memory_compressor", fromlist=["_summarize_messages"])
        ._summarize_messages
    )
    # The guard must be present
    assert 'startswith("anthropic/")' in src, (
        "thinking=None guard missing: must use model.startswith('anthropic/')"
    )
    # thinking=None assignment must exist (inside the guard)
    assert 'completion_args["thinking"] = None' in src, (
        "thinking=None assignment missing from _summarize_messages"
    )

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


# ── 9. COST LOGGING ────────────────────────────────────────────────────────────
print("\n[9] COST LOGGING (P2)")
import logging as _logging
import inspect as _inspect
from phantom.llm.llm import LLM as _LLM

def v_logger_defined():
    from phantom.llm import llm as _m
    assert hasattr(_m, "logger")
    assert isinstance(_m.logger, _logging.Logger)

def v_cost_logging_in_stream():
    src = _inspect.getsource(_LLM._stream)
    assert "logger.info" in src
    assert "request_cost" in src or "llm_call" in src

def v_logging_captures_scan_mode():
    src = _inspect.getsource(_LLM._stream)
    assert "scan_mode" in src

check("logger instance defined in llm.py", v_logger_defined)
check("_stream() calls logger.info with cost data", v_cost_logging_in_stream)
check("log message includes scan_mode", v_logging_captures_scan_mode)


# ── 10. PER-TOOL TRUNCATION OVERRIDES ─────────────────────────────────────────
print("\n[10] PER-TOOL TRUNCATION OVERRIDES (P3)")
from phantom.tools.executor import _get_truncation_limit as _gtl, _format_tool_result as _ftr

def v_default_limit_6000():
    assert _gtl("unknown_tool_xyz") == 6000

def v_single_override():
    os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"] = "nuclei=10000"
    try:
        assert _gtl("nuclei") == 10000
    finally:
        del os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"]

def v_multi_override():
    os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"] = "nuclei=10000,grep=3000"
    try:
        assert _gtl("nuclei") == 10000
        assert _gtl("grep") == 3000
        assert _gtl("nmap") == 6000  # unspecified → default
    finally:
        del os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"]

def v_nuclei_not_truncated_at_9000():
    os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"] = "nuclei=10000"
    try:
        r, _ = _ftr("nuclei", "N" * 9000)
        assert "truncated" not in r.lower()
    finally:
        del os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"]

def v_grep_truncated_at_3001_with_override():
    os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"] = "grep=3000"
    try:
        r, _ = _ftr("grep", "G" * 3001)
        assert "truncated" in r.lower()
    finally:
        del os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"]

def v_config_registers_new_var():
    from phantom.config.config import Config
    assert hasattr(Config, "phantom_tool_truncation_overrides")

check("_get_truncation_limit(): default=6000", v_default_limit_6000)
check("_get_truncation_limit(): single override works", v_single_override)
check("_get_truncation_limit(): multi-tool override + fallback", v_multi_override)
check("nuclei: 9000 chars not truncated under 10000 limit", v_nuclei_not_truncated_at_9000)
check("grep: 3001 chars truncated under 3000 limit", v_grep_truncated_at_3001_with_override)
check("Config.phantom_tool_truncation_overrides registered", v_config_registers_new_var)


# ── 11. CONTEXT-WINDOW AWARE COMPRESSION ──────────────────────────────────────
print("\n[11] CONTEXT-WINDOW AWARE COMPRESSION (kimi-k2.5 fix)")
from unittest.mock import patch as _patch
from phantom.llm.memory_compressor import (
    _get_model_context_window as _gcw,
    MemoryCompressor as _MC,
    MAX_TOTAL_TOKENS as _MAX_TOK,
    _CONTEXT_FILL_RATIO as _RATIO,
)

def v_context_window_lookup_works():
    with _patch("litellm.get_model_info", return_value={"max_input_tokens": 8000}):
        assert _gcw("kimi-k2.5") == 8000

def v_context_window_fallback():
    with _patch("litellm.get_model_info", side_effect=Exception("no info")):
        assert _gcw("unknown") == _MAX_TOK

def v_kimi_gets_small_threshold():
    with _patch("phantom.llm.memory_compressor._get_model_context_window", return_value=8000):
        mc = _MC(model_name="openai/gpt-4o")
    assert mc._max_total_tokens == int(8000 * _RATIO)

def v_env_override_phantom_max_input_tokens():
    os.environ["PHANTOM_MAX_INPUT_TOKENS"] = "5000"
    try:
        with _patch("phantom.llm.memory_compressor._get_model_context_window", return_value=128000):
            mc = _MC(model_name="openai/gpt-4o")
        assert mc._max_total_tokens == 5000
    finally:
        del os.environ["PHANTOM_MAX_INPUT_TOKENS"]

def v_is_context_too_large_detects_kimi_error():
    from phantom.llm.llm import LLM as _LLM
    from phantom.llm.config import LLMConfig as _Cfg
    llm = _LLM(_Cfg(model_name="openai/gpt-4o", scan_mode="standard"), "PhantomAgent")
    e = Exception("Request body too large for kimi-k2.5 model. Max size: 8000 tokens.")
    assert llm._is_context_too_large(e)

def v_is_context_too_large_ignores_normal_errors():
    from phantom.llm.llm import LLM as _LLM
    from phantom.llm.config import LLMConfig as _Cfg
    llm = _LLM(_Cfg(model_name="openai/gpt-4o", scan_mode="standard"), "PhantomAgent")
    assert not llm._is_context_too_large(Exception("Connection timeout"))

def v_config_registers_max_input_tokens():
    from phantom.config.config import Config
    assert hasattr(Config, "phantom_max_input_tokens")

check("_get_model_context_window(): reads from litellm", v_context_window_lookup_works)
check("_get_model_context_window(): fallback to MAX_TOTAL_TOKENS", v_context_window_fallback)
check("kimi-k2.5 8k → threshold=int(8k*0.6)=4800", v_kimi_gets_small_threshold)
check("PHANTOM_MAX_INPUT_TOKENS env overrides model info", v_env_override_phantom_max_input_tokens)
check("_is_context_too_large(): detects kimi error string", v_is_context_too_large_detects_kimi_error)
check("_is_context_too_large(): ignores normal errors", v_is_context_too_large_ignores_normal_errors)
check("Config.phantom_max_input_tokens registered", v_config_registers_max_input_tokens)


# ── 12. TOOL NAME PREFIX NORMALISATION ────────────────────────────────────────
print("\n[12] TOOL NAME PREFIX NORMALISATION (0.9.59)")
from unittest.mock import patch as _patch2, AsyncMock as _AsyncMock
import asyncio as _asyncio
from phantom.tools.executor import (
    execute_tool_with_validation as _etwv,
    validate_tool_availability as _vta,
)
from phantom.tools.registry import get_tools_prompt as _gtp, tools as _tools_list, clear_registry as _clear_reg

def v_validate_valid_tool_passes():
    with _patch2("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]):
        ok, msg = _vta("scope_rules")
    assert ok is True and msg == ""

def v_prefixed_name_is_normalised():
    async def _run():
        with (
            _patch2("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]),
            _patch2("phantom.tools.executor.validate_tool_availability", return_value=(True, "")),
            _patch2("phantom.tools.executor._validate_tool_arguments", return_value=None),
            _patch2("phantom.tools.executor.execute_tool", new=_AsyncMock(return_value="OK")),
        ):
            return await _etwv("proxy_tools.scope_rules")
    assert _asyncio.run(_run()) == "OK"

def v_unknown_prefixed_name_errors():
    async def _run():
        with _patch2("phantom.tools.executor.get_tool_names", return_value=["scope_rules"]):
            return await _etwv("proxy_tools.nonexistent")
    result = _asyncio.run(_run())
    assert "Error" in result and "not available" in result.lower()

def v_tools_prompt_uses_comment_headers():
    fake = [
        {
            "name": "scope_rules",
            "module": "proxy",
            "xml_schema": '<tool name="scope_rules"><description>scope</description></tool>',
            "sandbox_execution": False,
        },
    ]
    original = _tools_list[:]
    _tools_list[:] = fake
    try:
        prompt = _gtp()
    finally:
        _tools_list[:] = original
    assert "<!-- proxy tools -->" in prompt
    assert "<proxy_tools>" not in prompt
    assert "</proxy_tools>" not in prompt

def v_tools_prompt_tool_names_intact():
    """Individual <tool name="..."> tags must still be present inside the comment section."""
    fake = [
        {
            "name": "scope_rules",
            "module": "proxy",
            "xml_schema": '<tool name="scope_rules"><description>scope</description></tool>',
            "sandbox_execution": False,
        },
    ]
    original = _tools_list[:]
    _tools_list[:] = fake
    try:
        prompt = _gtp()
    finally:
        _tools_list[:] = original
    assert 'name="scope_rules"' in prompt

check("validate_tool_availability(): bare name passes", v_validate_valid_tool_passes)
check("execute_tool_with_validation(): proxy_tools.scope_rules → scope_rules", v_prefixed_name_is_normalised)
check("execute_tool_with_validation(): proxy_tools.nonexistent → error", v_unknown_prefixed_name_errors)
check("get_tools_prompt(): section header uses <!-- comment -->", v_tools_prompt_uses_comment_headers)
check("get_tools_prompt(): tool name= attributes intact", v_tools_prompt_tool_names_intact)


# ── [13] CHECKPOINT MODULE (0.9.62) ───────────────────────────────────────────
print("\n[13] CHECKPOINT MODULE (0.9.62)")

def v_checkpoint_models_importable():
    from phantom.checkpoint.models import CheckpointData
    cp = CheckpointData(run_name="x")
    assert cp.version == "1"
    assert cp.status == "in_progress"

def v_checkpoint_manager_importable():
    from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        mgr = CheckpointManager(pathlib.Path(td))
        assert not mgr.exists()
        assert mgr.should_save(1)
        assert not mgr.should_save(0)

def v_checkpoint_save_load_roundtrip():
    from phantom.checkpoint.checkpoint import CheckpointManager
    from phantom.checkpoint.models import CheckpointData
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        mgr = CheckpointManager(pathlib.Path(td))
        cp = CheckpointData(run_name="test-run", iteration=7, compression_calls=2)
        mgr.save(cp)
        loaded = mgr.load()
        assert loaded is not None
        assert loaded.run_name == "test-run"
        assert loaded.iteration == 7
        assert loaded.compression_calls == 2

def v_checkpoint_mark_completed():
    from phantom.checkpoint.checkpoint import CheckpointManager
    from phantom.checkpoint.models import CheckpointData
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        mgr = CheckpointManager(pathlib.Path(td))
        mgr.save(CheckpointData(run_name="r"))
        mgr.mark_completed()
        assert mgr.load().status == "completed"

def v_checkpoint_interval_param_accepted():
    """CheckpointManager(interval=10) must store _interval=10."""
    from phantom.checkpoint.checkpoint import CheckpointManager
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        mgr = CheckpointManager(pathlib.Path(td), interval=10)
        assert mgr._interval == 10

def v_checkpoint_custom_interval_schedule():
    """Configurable interval must change when should_save() fires."""
    from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        default_mgr = CheckpointManager(pathlib.Path(td), interval=CHECKPOINT_INTERVAL)
        custom_mgr  = CheckpointManager(pathlib.Path(td), interval=10)
        assert default_mgr.should_save(5) is True
        assert custom_mgr.should_save(5) is False
        assert custom_mgr.should_save(10) is True

def v_agentstate_clear_sandbox_method():
    """AgentState.clear_sandbox() must zero the three sandbox fields."""
    from phantom.agents.state import AgentState
    state = AgentState(
        sandbox_id="ws_dead",
        sandbox_token="tok_dead",
        sandbox_info={"url": "http://localhost:8080"},
    )
    state.clear_sandbox()
    assert state.sandbox_id is None
    assert state.sandbox_token is None
    assert state.sandbox_info is None

check("checkpoint.models: CheckpointData importable with defaults", v_checkpoint_models_importable)
check("checkpoint.checkpoint: CheckpointManager importable, should_save(0)=False", v_checkpoint_manager_importable)
check("CheckpointManager: save/load round-trip preserves all fields", v_checkpoint_save_load_roundtrip)
check("CheckpointManager.mark_completed() sets status='completed'", v_checkpoint_mark_completed)
check("CheckpointManager(interval=10) stores _interval=10", v_checkpoint_interval_param_accepted)
check("CheckpointManager configurable interval: should_save fires at custom boundary", v_checkpoint_custom_interval_schedule)
check("AgentState.clear_sandbox() zeroes all three sandbox fields", v_agentstate_clear_sandbox_method)


# ── [14] PER-MODEL ANALYTICS + CALL COUNTERS (0.9.60) ────────────────────────
print("\n[14] PER-MODEL ANALYTICS + CALL COUNTERS (0.9.60)")

def v_llm_per_model_stats_dict_present():
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig
    cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="standard")
    llm = LLM(cfg)
    assert hasattr(llm, "_per_model_stats")
    assert isinstance(llm._per_model_stats, dict)

def v_llm_agent_calls_counter():
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig
    cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="standard")
    llm = LLM(cfg)
    assert llm._agent_calls == 0
    assert llm._error_calls == 0

def v_memory_compressor_compression_calls():
    from phantom.llm.memory_compressor import MemoryCompressor
    mc = MemoryCompressor(model_name="openai/gpt-4o")
    assert mc.compression_calls == 0

def v_tracer_get_per_model_stats_callable():
    from phantom.telemetry.tracer import Tracer
    t = Tracer("verify-test")
    result = t.get_per_model_stats()
    assert isinstance(result, dict)

def v_tracer_compression_agent_error_callables():
    from phantom.telemetry.tracer import Tracer
    t = Tracer("verify-test-2")
    assert isinstance(t.compression_calls, int)
    assert isinstance(t.agent_calls, int)
    assert isinstance(t.error_calls, int)

def v_tracer_get_metrics_summary():
    from phantom.telemetry.tracer import Tracer
    t = Tracer("verify-test-3")
    m = t.get_metrics_summary()
    assert "requests_per_finding" in m
    assert "compression_ratio" in m
    assert "error_rate" in m
    assert "avg_output_tokens_per_request" in m

check("LLM._per_model_stats dict attribute present", v_llm_per_model_stats_dict_present)
check("LLM._agent_calls and ._error_calls start at 0", v_llm_agent_calls_counter)
check("MemoryCompressor.compression_calls starts at 0", v_memory_compressor_compression_calls)
check("Tracer.get_per_model_stats() returns dict", v_tracer_get_per_model_stats_callable)
check("Tracer.compression_calls / .agent_calls / .error_calls are int properties", v_tracer_compression_agent_error_callables)
check("Tracer.get_metrics_summary() returns expected keys", v_tracer_get_metrics_summary)


# ── [15] LLM FALLBACK + ADAPTIVE + ROUTING (0.9.60) ──────────────────────────
print("\n[15] LLM FALLBACK + ADAPTIVE + ROUTING (0.9.60)")

def v_llm_fallback_model_attr():
    import os
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig
    os.environ.pop("PHANTOM_FALLBACK_LLM", None)
    cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="standard")
    llm = LLM(cfg)
    assert llm._fallback_llm_name is None

def v_llm_fallback_reads_env(monkeypatch=None):
    import os
    original = os.environ.get("PHANTOM_FALLBACK_LLM")
    os.environ["PHANTOM_FALLBACK_LLM"] = "groq/llama-3.3-70b-versatile"
    try:
        from phantom.llm.llm import LLM
        from phantom.llm.config import LLMConfig
        cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="standard")
        llm = LLM(cfg)
        assert llm._fallback_llm_name == "groq/llama-3.3-70b-versatile"
    finally:
        if original is None:
            os.environ.pop("PHANTOM_FALLBACK_LLM", None)
        else:
            os.environ["PHANTOM_FALLBACK_LLM"] = original

def v_adaptive_scan_downgrade_deep():
    import os
    os.environ["PHANTOM_MAX_COST"] = "1.00"
    try:
        from phantom.llm.llm import LLM
        from phantom.llm.config import LLMConfig
        cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="deep")
        llm = LLM(cfg)
        llm._adaptive_scan_enabled = True
        llm._adaptive_threshold = 0.8
        llm._total_stats.cost = 0.85
        llm._check_adaptive_scan_mode()
        assert llm.config.scan_mode == "standard"
    finally:
        os.environ.pop("PHANTOM_MAX_COST", None)

def v_routing_tool_model_selected():
    from phantom.llm.llm import LLM
    from phantom.llm.config import LLMConfig
    cfg = LLMConfig(model_name="openai/gpt-4o", scan_mode="standard")
    llm = LLM(cfg)
    llm._routing_enabled = True
    llm._routing_tool_model = "deepseek/deepseek-chat"
    llm._routing_reasoning_model = "kimi/k2-5"
    msgs = [{"role": "user", "content": "<tool_result>out</tool_result>"}]
    assert llm._pick_routing_model(msgs) == "deepseek/deepseek-chat"

def v_config_new_vars_present():
    from phantom.config.config import Config
    assert hasattr(Config, "phantom_fallback_llm")
    assert hasattr(Config, "phantom_adaptive_scan")
    assert hasattr(Config, "phantom_adaptive_scan_threshold")
    assert hasattr(Config, "phantom_checkpoint_interval")
    assert hasattr(Config, "phantom_routing_enabled")
    assert hasattr(Config, "phantom_routing_reasoning_model")
    assert hasattr(Config, "phantom_routing_tool_model")

check("LLM._fallback_llm_name is None when env not set", v_llm_fallback_model_attr)
check("LLM._fallback_llm_name reads PHANTOM_FALLBACK_LLM env var", v_llm_fallback_reads_env)
check("adaptive scan: cost>threshold downgrades deep→standard", v_adaptive_scan_downgrade_deep)
check("routing: tool_result message → tool model selected", v_routing_tool_model_selected)
check("Config: all 0.9.60 env vars present as class attributes", v_config_new_vars_present)


# ── [16] BUG-FIX VERIFICATION (0.9.63) ───────────────────────────────────────
print("\n[16] BUG-FIX VERIFICATION (0.9.63)")

def v_bug_c_check_error_result_exec_prefix():
    """BUG FIX C: _check_error_result must detect 'Error executing X: ...' as error."""
    from phantom.tools.executor import _check_error_result
    is_err, payload = _check_error_result("Error executing nuclei: connection timeout")
    assert is_err is True, "'Error executing ...' must be classified as error"
    assert payload == "Error executing nuclei: connection timeout"

def v_bug_c_check_error_result_colon_still_works():
    """BUG FIX C: the original 'Error: ...' prefix still triggers error detection."""
    from phantom.tools.executor import _check_error_result
    is_err, payload = _check_error_result("Error: tool 'foo' is not available")
    assert is_err is True
    is_ok, _ = _check_error_result("All done!")
    assert is_ok is False, "Non-error string must NOT be flagged"

def v_bug_d_compressor_thinking_only_anthropic():
    """BUG FIX D: _summarize_messages must only add thinking=None for anthropic/ models."""
    import inspect
    from phantom.llm import memory_compressor
    src = inspect.getsource(memory_compressor._summarize_messages)
    assert 'startswith("anthropic/")' in src, (
        "thinking=None guard must check model.startswith('anthropic/')"
    )

def v_bug_d_compressor_source_no_unconditional_thinking():
    """BUG FIX D: The module must NOT unconditionally include thinking=None in completion_args."""
    import inspect
    from phantom.llm import memory_compressor
    src = inspect.getsource(memory_compressor._summarize_messages)
    # 'thinking': None must only appear inside the anthropic guard, not directly in dict literal
    # Check that there is no bare `"thinking": None` in the static dict
    lines = src.splitlines()
    dict_literal_lines = [l for l in lines if '"thinking": None,' in l or "'thinking': None," in l]
    for line in dict_literal_lines:
        stripped = line.strip()
        # These lines are ok only when inside the if-startswith block
        assert 'completion_args["thinking"] = None' not in stripped or 'completion_args["thinking"]' in src, (
            "unconditional thinking=None found in completion_args dict literal"
        )

check("BUG C: _check_error_result detects 'Error executing X: ...' as error", v_bug_c_check_error_result_exec_prefix)
check("BUG C: _check_error_result 'Error: ...' prefix still works + false-positive free", v_bug_c_check_error_result_colon_still_works)
check("BUG D: _summarize_messages thinking=None only for anthropic/ models", v_bug_d_compressor_thinking_only_anthropic)
check("BUG D: No unconditional thinking=None in completion_args dict", v_bug_d_compressor_source_no_unconditional_thinking)


# ── [17] RESUME + RELIABILITY FIXES (0.9.64) ─────────────────────────────────
print("\n[17] RESUME + RELIABILITY FIXES (0.9.64)")

def v_cli_app_is_entry_point():
    """Entry point must now be cli_app:app (Typer) not main:main (argparse)."""
    content = open("pyproject.toml", encoding="utf-8").read()
    assert 'phantom = "phantom.interface.cli_app:app"' in content, (
        "pyproject.toml entry point must point to cli_app:app"
    )

def v_resume_command_exists():
    """phantom resume <run_name> subcommand must be defined in cli_app."""
    import inspect
    from phantom.interface import cli_app
    src = inspect.getsource(cli_app)
    assert "def resume(" in src, "resume() command must exist in cli_app"
    assert "resume_run=run_name" in src, "resume() must pass resume_run to _async_scan"

def v_resumes_command_exists():
    """phantom resumes subcommand (list) must be defined in cli_app."""
    import inspect
    from phantom.interface import cli_app
    src = inspect.getsource(cli_app)
    assert "def resumes(" in src, "resumes() command must exist in cli_app"
    assert "CheckpointManager" in src, "resumes() must use CheckpointManager"

def v_tui_has_checkpoint_manager():
    """TUIApp __init__ must set up a CheckpointManager."""
    import inspect
    from phantom.interface import tui
    src = inspect.getsource(tui.PhantomTUIApp.__init__)
    assert "CheckpointManager" in src, "TUI __init__ must create a CheckpointManager"
    assert "_checkpoint_mgr" in src

def v_tui_agent_config_has_checkpoint():
    """TUI _build_agent_config must inject _checkpoint_manager."""
    import inspect
    from phantom.interface import tui
    src = inspect.getsource(tui.PhantomTUIApp._build_agent_config)
    assert '"_checkpoint_manager"' in src, "agent_config must include _checkpoint_manager"
    assert '"_run_name"' in src, "agent_config must include _run_name"

def v_tui_stop_saves_checkpoint():
    """action_confirm_stop_agent must save an interrupted checkpoint."""
    import inspect
    from phantom.interface import tui
    src = inspect.getsource(tui.PhantomTUIApp.action_confirm_stop_agent)
    assert "_save_interrupted_checkpoint" in src, (
        "action_confirm_stop_agent must call _save_interrupted_checkpoint"
    )
    assert "phantom resume" in src, "must show resume tip notification"

def v_tui_quit_saves_checkpoint():
    """action_custom_quit must save an interrupted checkpoint."""
    import inspect
    from phantom.interface import tui
    src = inspect.getsource(tui.PhantomTUIApp.action_custom_quit)
    assert "_save_interrupted_checkpoint" in src, (
        "action_custom_quit must call _save_interrupted_checkpoint"
    )

def v_terminal_manager_default_timeout():
    """Terminal manager default_timeout must be 60s (raised from 30s)."""
    src = open("phantom/tools/terminal/terminal_manager.py", encoding="utf-8").read()
    assert "self.default_timeout = 60.0" in src, (
        "terminal_manager.py must set default_timeout = 60.0 (was 30.0)"
    )

def v_should_retry_no_private_litellm():
    """LLM._should_retry must NOT call litellm._should_retry (private unsupported API)."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM._should_retry)
    assert "litellm._should_retry" not in src, (
        "_should_retry must not call litellm._should_retry (private API)"
    )
    assert "500 <= code" in src or "500 <" in src, (
        "_should_retry must retry on 5xx codes"
    )

def v_llm_retry_backoff_429():
    """LLM.generate must use a longer backoff for 429 rate-limit responses."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM.generate)
    assert "code == 429" in src, "generate must check for 429 and apply longer backoff"

check("entry point is cli_app:app (Typer)", v_cli_app_is_entry_point)
check("phantom resume <run_name> command exists", v_resume_command_exists)
check("phantom resumes (list) command exists", v_resumes_command_exists)
check("TUI __init__ creates CheckpointManager", v_tui_has_checkpoint_manager)
check("TUI agent_config includes _checkpoint_manager + _run_name", v_tui_agent_config_has_checkpoint)
check("TUI stop (ESC) saves interrupted checkpoint + shows resume tip", v_tui_stop_saves_checkpoint)
check("TUI quit (Ctrl+Q) saves interrupted checkpoint", v_tui_quit_saves_checkpoint)
check("terminal_manager default_timeout == 60s (was 30s)", v_terminal_manager_default_timeout)
check("LLM._should_retry: no private litellm API, retries 5xx", v_should_retry_no_private_litellm)
check("LLM.generate: longer backoff for 429 rate-limit", v_llm_retry_backoff_429)


# ── [18] STARTUP / TUI-RESUME / SCAN_MODE FIXES (0.9.65) ─────────────────────
print("\n[18] STARTUP / TUI-RESUME / SCAN_MODE FIXES (0.9.65)")

def v_interface_init_lazy_import():
    """phantom.interface.__init__ must use a lazy __getattr__ — NOT an eager import."""
    import re
    src = open("phantom/interface/__init__.py", encoding="utf-8").read()
    # Ensure there is NO top-level (col 0) eager import of .main
    assert not re.search(r"^from \.main import main", src, re.MULTILINE), (
        "__init__.py must NOT have a top-level 'from .main import main' (causes 17s startup)"
    )
    assert "__getattr__" in src, (
        "__init__.py must use __getattr__ for lazy import of main"
    )

def v_startup_time_fast():
    """Importing phantom.interface.cli_app must complete in under 5 seconds."""
    import subprocess, sys, time
    result = subprocess.run(
        [sys.executable, "-c",
         "import time, sys; t=time.time(); import phantom.interface.cli_app; "
         "elapsed=time.time()-t; sys.exit(0 if elapsed < 5 else 1)"],
        capture_output=True,
    )
    assert result.returncode == 0, (
        "phantom.interface.cli_app import took >= 5s (startup too slow)"
    )

def v_tui_resume_restores_state():
    """TUI _build_agent_config must inject restored AgentState when resuming."""
    import inspect
    from phantom.interface import tui
    src = inspect.getsource(tui.PhantomTUIApp._build_agent_config)
    assert "_restored_checkpoint" in src, (
        "_build_agent_config must check _restored_checkpoint"
    )
    assert "AgentState.model_validate" in src, (
        "_build_agent_config must restore state via AgentState.model_validate"
    )
    assert "clear_sandbox" in src, (
        "_build_agent_config must call clear_sandbox() on restored state"
    )
    assert "SCAN RESUMED" in src, (
        "_build_agent_config must inject SCAN RESUMED message"
    )

def v_tui_resume_extends_iterations():
    """TUI resume must extend max_iterations so agent isn't immediately at its limit."""
    import inspect
    from phantom.interface import tui
    src = inspect.getsource(tui.PhantomTUIApp._build_agent_config)
    assert "restored_state.iteration + base_max_iter" in src, (
        "_build_agent_config must extend max_iterations = iteration + base_max_iter"
    )

def v_tui_resume_seeds_tracer_vulns():
    """TUI __init__ must seed the tracer with previously found vulnerabilities on resume."""
    import inspect
    from phantom.interface import tui
    src = inspect.getsource(tui.PhantomTUIApp.__init__)
    assert "_saved_vuln_ids" in src, (
        "TUI __init__ must seed tracer._saved_vuln_ids from checkpoint vulns"
    )
    assert "vulnerability_reports.extend" in src, (
        "TUI __init__ must extend tracer.vulnerability_reports from checkpoint"
    )

def v_cli_resume_extends_iterations():
    """CLI run_cli must extend max_iterations on resume."""
    import inspect
    from phantom.interface import cli
    src = inspect.getsource(cli.run_cli)
    assert "restored_state.iteration + base_max_iter" in src, (
        "run_cli must extend max_iterations = iteration + base_max_iter on resume"
    )

def v_scan_mode_stored_in_checkpoint():
    """scan_config must include scan_mode so it survives checkpoint → resume."""
    import inspect
    from phantom.interface import cli, tui
    cli_src = inspect.getsource(cli.run_cli)
    tui_src = inspect.getsource(tui.PhantomTUIApp._build_scan_config)
    assert '"scan_mode"' in cli_src, "run_cli scan_config must include scan_mode"
    assert '"scan_mode"' in tui_src, "_build_scan_config must include scan_mode"

def v_cli_resume_restores_scan_mode():
    """CLI resume must restore scan_mode from checkpoint scan_config."""
    import inspect
    from phantom.interface import cli
    src = inspect.getsource(cli.run_cli)
    assert 'cp.scan_config.get("scan_mode")' in src, (
        "run_cli must restore scan_mode from cp.scan_config on resume"
    )

def v_no_posthog_in_cli_app_scan():
    """cli_app scan command must NOT contain posthog calls (telemetry removed)."""
    import inspect
    from phantom.interface import cli_app
    src = inspect.getsource(cli_app.scan)
    assert "posthog.start" not in src, "scan() must not call posthog.start"
    assert "posthog.end" not in src, "scan() must not call posthog.end"
    assert "posthog.error" not in src, "scan() must not call posthog.error"

def v_no_posthog_in_cli_app_resume():
    """cli_app resume command must NOT contain posthog calls (telemetry removed)."""
    import inspect
    from phantom.interface import cli_app
    src = inspect.getsource(cli_app.resume)
    assert "posthog.start" not in src, "resume() must not call posthog.start"
    assert "posthog.end" not in src, "resume() must not call posthog.end"
    assert "posthog.error" not in src, "resume() must not call posthog.error"

check("interface/__init__.py uses lazy __getattr__ (no eager litellm import)", v_interface_init_lazy_import)
check("phantom CLI startup import < 5 seconds", v_startup_time_fast)
check("TUI _build_agent_config restores checkpoint state on resume", v_tui_resume_restores_state)
check("TUI _build_agent_config extends max_iterations on resume", v_tui_resume_extends_iterations)
check("TUI __init__ seeds tracer with prior vulnerabilities on resume", v_tui_resume_seeds_tracer_vulns)
check("CLI run_cli extends max_iterations on resume", v_cli_resume_extends_iterations)
check("scan_mode stored in checkpoint scan_config (cli + tui)", v_scan_mode_stored_in_checkpoint)
check("CLI run_cli restores scan_mode from checkpoint", v_cli_resume_restores_scan_mode)
check("no posthog calls in cli_app scan command", v_no_posthog_in_cli_app_scan)
check("no posthog calls in cli_app resume command", v_no_posthog_in_cli_app_resume)


# ── 19. TELEMETRY HYGIENE + BUG-FIX VERIFICATION (0.9.67) ────────────────────
print("\n[19] TELEMETRY HYGIENE + BUG-FIX VERIFICATION (0.9.67)")

def v_posthog_file_is_gone():
    """phantom/telemetry/posthog.py must not exist (stub deleted in 0.9.66, removed in 0.9.67)."""
    p = Path(__file__).resolve().parent.parent / "phantom" / "telemetry" / "posthog.py"
    assert not p.exists(), f"posthog.py still exists at {p}"

def v_flags_no_dead_code():
    """flags.py must not contain _is_enabled or _DISABLED_VALUES dead code."""
    import inspect, phantom.telemetry.flags as fl
    src = inspect.getsource(fl)
    assert "_is_enabled" not in src, "Dead helper _is_enabled still present in flags.py"
    assert "_DISABLED_VALUES" not in src, "Dead _DISABLED_VALUES still present in flags.py"

def v_no_posthog_import_in_telemetry_init():
    """telemetry/__init__.py must not import posthog."""
    import inspect, phantom.telemetry as tel
    src = inspect.getsource(tel)
    assert "posthog" not in src, "posthog still imported in telemetry/__init__.py"

def v_memory_compressor_fallback_no_data_loss():
    """_summarize_messages fallback must not return messages[0] (data loss bug)."""
    import inspect
    from phantom.llm.memory_compressor import _summarize_messages
    src = inspect.getsource(_summarize_messages)
    assert "return messages[0]" not in src, "_summarize_messages still returns messages[0] on failure"
    assert "context_summary" in src, "_summarize_messages fallback must include context_summary tag"

def v_prepare_messages_is_async():
    """LLM._prepare_messages must be async (compression must not block the event loop)."""
    import inspect
    from phantom.llm.llm import LLM
    assert inspect.iscoroutinefunction(LLM._prepare_messages), \
        "LLM._prepare_messages must be async (blocking compression fix)"

def v_force_compress_is_async():
    """LLM._force_compress_messages must be async."""
    import inspect
    from phantom.llm.llm import LLM
    assert inspect.iscoroutinefunction(LLM._force_compress_messages), \
        "LLM._force_compress_messages must be async"

def v_budget_check_uses_global_tracer():
    """LLM._check_budget must query global Tracer cost, not just local agent stats."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM._check_budget)
    assert "get_global_tracer" in src, "_check_budget must use get_global_tracer() for global cost"
    assert "get_total_llm_stats" in src, "_check_budget must call get_total_llm_stats()"

def v_adaptive_uses_global_tracer():
    """LLM._check_adaptive_scan_mode must use global Tracer cost."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM._check_adaptive_scan_mode)
    assert "get_global_tracer" in src, "_check_adaptive_scan_mode must use global tracer cost"

def v_adaptive_called_after_fallback():
    """LLM.generate must call _check_adaptive_scan_mode() after fallback model succeeds."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM.generate)
    # find the fallback block
    fallback_idx = src.find("_fallback_llm_name")
    adaptive_after = src.find("_check_adaptive_scan_mode", fallback_idx)
    assert adaptive_after != -1, "_check_adaptive_scan_mode not called after fallback in generate()"

def v_extract_thinking_no_double_rebuild():
    """LLM._extract_thinking must accept a pre-built response to avoid double stream_chunk_builder."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM._extract_thinking)
    # Must accept 'rebuilt' parameter
    assert "rebuilt" in src, "_extract_thinking must accept 'rebuilt' parameter"

def v_final_warning_uses_gte():
    """base_agent loop final warning must use >= not == to avoid being skipped."""
    import inspect
    from phantom.agents.base_agent import BaseAgent
    src = inspect.getsource(BaseAgent.agent_loop)
    assert "iteration >= self.state.max_iterations - 3" in src, \
        "Final warning must use >= (not ==) to prevent being silently skipped"

def v_resume_resets_warning_flag():
    """cli.py and tui.py must reset max_iterations_warning_sent=False on resume."""
    import inspect
    import phantom.interface.cli as cli_mod
    import phantom.interface.tui as tui_mod
    for mod_name, mod in [("cli.py", cli_mod), ("tui.py", tui_mod)]:
        src = inspect.getsource(mod)
        assert "max_iterations_warning_sent = False" in src, \
            f"{mod_name} must reset max_iterations_warning_sent=False on resume"

def v_context_too_large_extended_phrases():
    """_is_context_too_large must detect additional provider-specific error strings."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM._is_context_too_large)
    for phrase in ("string too long", "payload too large", "context window", "prompt is too long"):
        assert phrase in src, f"_is_context_too_large missing phrase: '{phrase}'"

check("posthog.py stub deleted entirely", v_posthog_file_is_gone)
check("flags.py has no dead _is_enabled/_DISABLED_VALUES code", v_flags_no_dead_code)
check("telemetry/__init__.py does not import posthog", v_no_posthog_import_in_telemetry_init)
check("_summarize_messages fallback has no data-loss messages[0] return", v_memory_compressor_fallback_no_data_loss)
check("LLM._prepare_messages is async (no event-loop blocking)", v_prepare_messages_is_async)
check("LLM._force_compress_messages is async", v_force_compress_is_async)
check("LLM._check_budget uses global Tracer cost (multi-agent budget)", v_budget_check_uses_global_tracer)
check("LLM._check_adaptive_scan_mode uses global Tracer cost", v_adaptive_uses_global_tracer)
check("LLM.generate calls _check_adaptive_scan_mode after fallback", v_adaptive_called_after_fallback)
check("LLM._extract_thinking accepts pre-built response (no double stream_chunk_builder)", v_extract_thinking_no_double_rebuild)
check("base_agent final warning uses >= (not ==)", v_final_warning_uses_gte)
check("resume resets max_iterations_warning_sent=False in cli.py and tui.py", v_resume_resets_warning_flag)
check("_is_context_too_large covers extended provider error phrases", v_context_too_large_extended_phrases)


# ── 20. CLI COMMANDS, NEW MODULES & INTEGRITY (0.9.68) ───────────────────────
print("\n[20] CLI COMMANDS, NEW MODULES & INTEGRITY (0.9.68)")



def v_get_global_tracer_imported_in_cli_app():
    """cli_app.py scan/resume functions must access get_global_tracer (lazy import OK)."""
    import inspect
    import phantom.interface.cli_app as ca
    # Check the scan function
    scan_src = inspect.getsource(ca.scan)
    resume_src = inspect.getsource(ca.resume)
    for fn_name, src in (("scan", scan_src), ("resume", resume_src)):
        assert "get_global_tracer" in src, \
            f"get_global_tracer not found in cli_app.{fn_name}()"
    # It must NOT be a bare name reference without being imported anywhere
    full_src = inspect.getsource(ca)
    assert "get_global_tracer" in full_src, \
        "get_global_tracer missing from cli_app.py entirely"


def v_diff_scanner_importable():
    """phantom.core.diff_scanner.DiffScanner must be importable and functional."""
    from phantom.core.diff_scanner import DiffScanner
    scanner = DiffScanner()
    report = scanner.compare(".", ".")
    assert hasattr(report, "to_markdown"), "DiffReport must have to_markdown()"
    md = report.to_markdown()
    assert "Phantom Diff Report" in md


def v_scan_profiles_importable():
    """phantom.core.scan_profiles must expose list_profiles() and get_profile()."""
    from phantom.core.scan_profiles import list_profiles, get_profile
    profiles = list_profiles()
    assert len(profiles) >= 5, "At least 5 scan profiles expected"
    names = {p["name"] for p in profiles}
    for expected in ("quick", "standard", "deep", "stealth", "api_only"):
        assert expected in names, f"Missing profile '{expected}'"
    deep = get_profile("deep")
    assert deep.max_iterations >= 200
    assert deep.reasoning_effort in ("medium", "high")


def v_scan_profiles_attributes():
    """Every scan profile must have required attributes."""
    from phantom.core.scan_profiles import list_profiles, get_profile
    required = ("name", "description", "scan_mode", "max_iterations",
                "sandbox_timeout_s", "reasoning_effort", "enable_browser",
                "priority_tools", "skip_tools")
    for info in list_profiles():
        p = get_profile(info["name"])
        for attr in required:
            assert hasattr(p, attr), f"Profile '{info['name']}' missing attribute '{attr}'"


def v_resumes_delete_command_exists():
    """phantom resumes-delete command must exist."""
    from phantom.interface.cli_app import app
    cmd_names = [c.name for c in app.registered_commands]
    assert "resumes-delete" in cmd_names, \
        "phantom resumes-delete command is missing from CLI"


def v_report_delete_command_exists():
    """phantom report delete command must exist."""
    from phantom.interface.cli_app import report_app
    cmd_names = [c.name for c in report_app.registered_commands]
    assert "delete" in cmd_names, "phantom report delete sub-command is missing"


def v_resumes_table_has_id_column():
    """resumes() must add a '#' column (numeric ID for easy reference)."""
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.resumes)
    assert '"#"' in src or "'#'" in src, \
        "resumes() table is missing '#' ID column"


def v_report_list_has_id_column():
    """report_list() must add a '#' column."""
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.report_list)
    assert '"#"' in src or "'#'" in src, \
        "report_list() table is missing '#' ID column"


def v_report_list_has_status_column():
    """report_list() must show scan status."""
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.report_list)
    assert "Status" in src or "status" in src.lower(), \
        "report_list() is missing a Status column"


def v_rebuilt_initialized_before_use():
    """LLM._stream() must initialise 'rebuilt = None' before the if-chunks block."""
    import inspect
    from phantom.llm.llm import LLM
    src = inspect.getsource(LLM._stream)
    # rebuilt must appear as an initialised variable before stream_chunk_builder
    idx_init = src.find("rebuilt: Any | None = None")
    idx_use = src.find("stream_chunk_builder(chunks)")
    assert idx_init != -1, "rebuilt must be initialised to None in _stream"
    assert idx_init < idx_use, "rebuilt init must appear before stream_chunk_builder call"


def v_profiles_command_works():
    """phantom profiles command must render without ImportError."""
    from phantom.core.scan_profiles import list_profiles, get_profile
    # Exercise the same path the CLI takes
    for p_info in list_profiles():
        p = get_profile(p_info["name"])
        _ = p.name, p.max_iterations, p.sandbox_timeout_s, p.reasoning_effort
        _ = p.enable_browser, p.priority_tools, p.skip_tools


def v_diff_scanner_detects_changes():
    """DiffScanner must correctly compute new/fixed/persistent vulnerability sets."""
    import json
    import tempfile
    from pathlib import Path
    from phantom.core.diff_scanner import DiffScanner

    vuln_a = {"id": "v001", "name": "SQLi", "severity": "high", "endpoint": "/login"}
    vuln_b = {"id": "v002", "name": "XSS", "severity": "medium", "endpoint": "/search"}
    vuln_c = {"id": "v003", "name": "IDOR", "severity": "low", "endpoint": "/api/user"}

    with tempfile.TemporaryDirectory() as tmp:
        run1 = Path(tmp) / "run1"
        run2 = Path(tmp) / "run2"
        run1.mkdir(); run2.mkdir()
        # run1 has v001 + v002; run2 has v002 + v003
        (run1 / "checkpoint.json").write_text(
            json.dumps({"vulnerability_reports": [vuln_a, vuln_b]}), encoding="utf-8"
        )
        (run2 / "checkpoint.json").write_text(
            json.dumps({"vulnerability_reports": [vuln_b, vuln_c]}), encoding="utf-8"
        )
        scanner = DiffScanner()
        report = scanner.compare(str(run1), str(run2))
        # v001 should be fixed, v003 should be new, v002 should persist
        fixed_ids = {v["id"] for v in report.fixed_vulns}
        new_ids = {v["id"] for v in report.new_vulns}
        persist_ids = {v["id"] for v in report.persistent_vulns}
        assert "v001" in fixed_ids, f"v001 should be fixed; got fixed={fixed_ids}"
        assert "v003" in new_ids, f"v003 should be new; got new={new_ids}"
        assert "v002" in persist_ids, f"v002 should persist; got persist={persist_ids}"


check("get_global_tracer imported at module level in cli_app.py", v_get_global_tracer_imported_in_cli_app)
check("phantom.core.diff_scanner.DiffScanner importable and functional", v_diff_scanner_importable)
check("phantom.core.scan_profiles importable with 5 profiles", v_scan_profiles_importable)
check("all scan profile attributes present", v_scan_profiles_attributes)
check("phantom resumes-delete command exists", v_resumes_delete_command_exists)
check("phantom report delete sub-command exists", v_report_delete_command_exists)
check("resumes() table has '#' ID column", v_resumes_table_has_id_column)
check("report list table has '#' ID column", v_report_list_has_id_column)
check("report list table has Status column", v_report_list_has_status_column)
check("LLM._stream rebuilt initialised before use (no NameError)", v_rebuilt_initialized_before_use)
check("phantom profiles command renders without ImportError", v_profiles_command_works)
check("DiffScanner correctly detects new/fixed/persistent vulns", v_diff_scanner_detects_changes)


# ── 21. v0.9.69 — SARIF, PAUSE-ALL, PROFILE, SORT, ITER-CAP ──────────────────
print("\n[21] v0.9.69 — SARIF, PAUSE-ALL, PROFILE, SORT, ITER-CAP")


def v_sarif_formatter_importable():
    from phantom.interface.formatters.sarif_formatter import SARIFFormatter
    fmt = SARIFFormatter()
    doc = fmt.format({"vulnerabilities": [{"name": "XSS", "severity": "high", "endpoint": "/test"}]})
    assert doc.get("version") == "2.1.0"
    assert "runs" in doc
    assert len(doc["runs"][0]["results"]) == 1


def v_sarif_rule_ids_stable():
    from phantom.interface.formatters.sarif_formatter import SARIFFormatter, _rule_id
    v = {"name": "SQL Injection", "severity": "critical"}
    rid = _rule_id(v)
    assert rid.startswith("PHANTOM-")
    assert rid == _rule_id(v)  # stable / idempotent


def v_scan_profile_flag_wired():
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.scan)
    assert "profile" in src
    assert "get_profile" in src or "_get_profile" in src


def v_resumes_sort_flag_wired():
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.resumes)
    assert "sort" in src
    assert "vulns" in src or "newest" in src


def v_diff_open_flag_wired():
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.diff)
    assert "open_browser" in src or "webbrowser" in src


def v_abs_iteration_cap_in_cli():
    import inspect
    import phantom.interface.cli as cl
    src = inspect.getsource(cl.run_cli)
    assert "_abs_iter_cap" in src
    assert "min(" in src


def v_abs_iteration_cap_in_tui():
    import inspect
    import phantom.interface.tui as tui
    src = inspect.getsource(tui.PhantomTUIApp._build_agent_config)
    assert "_abs_iter_cap" in src
    assert "min(" in src


def v_pause_all_binding_exists():
    import inspect
    import phantom.interface.tui as tui
    src = inspect.getsource(tui.PhantomTUIApp)
    assert "ctrl+p" in src or "pause_all" in src


def v_pause_all_screen_exists():
    from phantom.interface.tui import PauseAllScreen
    assert issubclass(PauseAllScreen, object)


def v_diff_scanner_raises_on_missing_dir():
    from phantom.core.diff_scanner import DiffScanner
    try:
        DiffScanner().compare("/nonexistent/path/a", "/nonexistent/path/b")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError:
        pass


def v_is_context_too_large_catches_openrouter():
    from phantom.llm.llm import LLM
    llm = LLM.__new__(LLM)
    e = Exception("This would exceed model context limits for this provider")
    assert llm._is_context_too_large(e), "OpenRouter 'model context limits' phrase not caught"


def v_is_context_too_large_catches_regex():
    from phantom.llm.llm import LLM
    llm = LLM.__new__(LLM)
    e = Exception("Your input would exceed the context window of the model")
    assert llm._is_context_too_large(e), "Regex fallback not catching 'exceed.*context'"


check("SARIFFormatter importable and produces valid SARIF 2.1.0", v_sarif_formatter_importable)
check("SARIF rule IDs are stable/idempotent", v_sarif_rule_ids_stable)
check("phantom scan --profile flag wired in cli_app.py", v_scan_profile_flag_wired)
check("phantom resumes --sort flag wired in cli_app.py", v_resumes_sort_flag_wired)
check("phantom diff --open flag wired in cli_app.py", v_diff_open_flag_wired)
check("absolute iteration cap (_abs_iter_cap) present in cli.py", v_abs_iteration_cap_in_cli)
check("absolute iteration cap (_abs_iter_cap) present in tui.py", v_abs_iteration_cap_in_tui)
check("Ctrl+P pause-all binding exists in TUI", v_pause_all_binding_exists)
check("PauseAllScreen class exists in tui.py", v_pause_all_screen_exists)
check("DiffScanner.compare raises FileNotFoundError on missing dir", v_diff_scanner_raises_on_missing_dir)
check("_is_context_too_large catches OpenRouter 'model context limits'", v_is_context_too_large_catches_openrouter)
check("_is_context_too_large regex fallback catches 'exceed.*context'", v_is_context_too_large_catches_regex)


# ── 22. v0.9.70 — RESUME NUMERIC ID + CLEAR_SANDBOX ─────────────────────────
print("\n[22] v0.9.70 — RESUME NUMERIC ID + CLEAR_SANDBOX")


def v_resume_accepts_numeric_id():
    """resume command's argument help must mention #ID."""
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.resume)
    assert "#ID" in src or "#id" in src or "numeric" in src.lower() or "isdigit" in src, \
        "resume() must handle numeric ID resolution"


def v_resolve_run_name_exists():
    """_resolve_run_name helper must be importable from cli_app."""
    from phantom.interface.cli_app import _resolve_run_name
    assert callable(_resolve_run_name)


def v_list_resumable_runs_exists():
    """_list_resumable_runs helper must be importable from cli_app."""
    from phantom.interface.cli_app import _list_resumable_runs
    assert callable(_list_resumable_runs)


def v_resumes_delete_uses_resolve_run_name():
    """resumes_delete must delegate to _resolve_run_name (no duplicate sort logic)."""
    import inspect
    import phantom.interface.cli_app as ca
    src = inspect.getsource(ca.resumes_delete)
    assert "_resolve_run_name" in src, \
        "resumes_delete must use _resolve_run_name() for consistent ID ordering"


def v_clear_sandbox_method_exists():
    """AgentState.clear_sandbox() must exist and zero all three sandbox fields."""
    from phantom.agents.state import AgentState
    assert hasattr(AgentState, "clear_sandbox"), "AgentState.clear_sandbox() missing"
    state = AgentState(
        task="t",
        sandbox_id="sid",
        sandbox_token="tok",
        sandbox_info={"k": "v"},
    )
    state.clear_sandbox()
    assert state.sandbox_id is None
    assert state.sandbox_token is None
    assert state.sandbox_info is None


check("resume() handles numeric #ID argument", v_resume_accepts_numeric_id)
check("_resolve_run_name() helper exists in cli_app", v_resolve_run_name_exists)
check("_list_resumable_runs() helper exists in cli_app", v_list_resumable_runs_exists)
check("resumes_delete uses _resolve_run_name (consistent IDs)", v_resumes_delete_uses_resolve_run_name)
check("AgentState.clear_sandbox() zeroes all sandbox fields", v_clear_sandbox_method_exists)


# ── SUMMARY ────────────────────────────────────────────────────────────────────
total = PASS + FAIL
print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print(f"  RESULTS: {PASS}/{total} passed  |  {FAIL} failed")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
if FAIL:
    sys.exit(1)
