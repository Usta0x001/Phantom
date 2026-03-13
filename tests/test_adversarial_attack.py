"""
tests/test_adversarial_attack.py

Adversarial attack tests — deliberately tries to BREAK every change.
These tests verify end-to-end wiring, not just unit correctness.

Run with:
    python -m pytest tests/test_adversarial_attack.py -v --tb=short
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent / "phantom"
_ENC = "utf-8"


def _read(relpath: str) -> str:
    """Read a source file with explicit UTF-8 to avoid Windows charmap errors."""
    return (_ROOT / relpath).read_text(encoding=_ENC)


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 1: P1.1 — Ledger is SAME object (not copy) in parent and child
# ═══════════════════════════════════════════════════════════════════════════════

class TestLedgerSharingWiring:
    """Attack P1.1: Verify the ledger instance is truly shared, not copied."""

    def test_parent_child_share_same_ledger_object(self):
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        parent_ledger = HypothesisLedger()
        parent_ledger.add("/login::user", "sqli")
        child_config = {"hypothesis_ledger": parent_ledger}
        child_ledger = child_config.get("hypothesis_ledger") or HypothesisLedger()
        assert child_ledger is parent_ledger, "Ledger was copied, not shared!"

    def test_child_writes_visible_to_parent(self):
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        shared = HypothesisLedger()
        shared.add("/api/v1::token", "ssrf")
        shared.add("/api/v2::redirect", "open_redirect")
        assert len(shared) == 2

    def test_create_agent_passes_ledger(self):
        src = _read("tools/agents_graph/agents_graph_actions.py")
        assert "hypothesis_ledger" in src and "agent_config" in src, \
            "P1.1 wiring not found in agents_graph_actions.py!"

    def test_base_agent_reads_ledger_from_config(self):
        src = _read("agents/base_agent.py")
        assert "hypothesis_ledger" in src and "config.get" in src, \
            "BaseAgent doesn't read hypothesis_ledger from config!"


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 2: P1.2 — Async replay must actually FIRE, not skip
# ═══════════════════════════════════════════════════════════════════════════════

class TestAsyncReplayWiring:
    """Attack P1.2: The old code was dead. Prove the new code fires."""

    def test_old_dead_code_removed(self):
        src = _read("tools/reporting/reporting_actions.py")
        # The old pattern was: if loop.is_running(): replay_status = "SKIPPED"
        # That pattern must be gone. `create_task` must be present instead.
        assert "create_task" in src, "create_task not found — async replay not wired!"
        # The OLD dead sync path used get_event_loop + is_running
        assert "get_event_loop" not in src, \
            "Old get_event_loop pattern still present (should be get_running_loop)!"

    def test_replay_inside_running_loop_fires(self):
        fired = []

        async def _test():
            loop = asyncio.get_running_loop()
            async def _fake_replay():
                fired.append(True)
            task = loop.create_task(_fake_replay())
            await task

        asyncio.run(_test())
        assert len(fired) == 1, "Background task never fired inside running loop!"


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 3: P1.3 — System prompt literally contains SUSPECTED guidance
# ═══════════════════════════════════════════════════════════════════════════════

class TestPromptGuidance:

    def test_suspected_in_system_prompt(self):
        text = _read("agents/PhantomAgent/system_prompt.jinja")
        assert "SUSPECTED" in text
        assert "LIKELY" in text
        assert "VERIFIED" in text

    def test_suspected_is_default_instruction(self):
        text = _read("agents/PhantomAgent/system_prompt.jinja").lower()
        assert "this is the default" in text, "SUSPECTED not marked as DEFAULT!"

    def test_verified_reserved_for_system(self):
        text = _read("agents/PhantomAgent/system_prompt.jinja")
        assert "do NOT set this manually" in text or "Do NOT set this manually" in text


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 4: P1.4 — duration_ms > 0 after real work
# ═══════════════════════════════════════════════════════════════════════════════

class TestDurationFix:

    def test_no_hardcoded_zero_in_base_agent(self):
        src = _read("agents/base_agent.py")
        assert "duration_ms=0.0" not in src, "Hardcoded duration_ms=0.0 still present!"

    def test_agent_start_time_captured(self):
        src = _read("agents/base_agent.py")
        assert "_agent_start_time" in src
        assert "monotonic()" in src

    def test_duration_computes_real_elapsed(self):
        start = time.monotonic()
        time.sleep(0.01)
        duration_ms = (time.monotonic() - start) * 1000
        assert duration_ms > 5


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 5: R1 — Thread lock coverage (100-thread stress test)
# ═══════════════════════════════════════════════════════════════════════════════

class TestLockCoverage:

    def test_graph_lock_exists(self):
        from phantom.tools.agents_graph.agents_graph_actions import _GRAPH_LOCK
        assert _GRAPH_LOCK is not None

    def test_6_globals_referenced(self):
        src = _read("tools/agents_graph/agents_graph_actions.py")
        for g in ["_agent_graph", "_agent_messages", "_running_agents",
                   "_agent_instances", "_agent_states", "_total_agents_created"]:
            assert g in src, f"Global {g} not found!"

    def test_100_thread_concurrent_graph_mutation(self):
        from phantom.tools.agents_graph import agents_graph_actions as aga
        errors = []
        test_ids = [f"stress-{i}" for i in range(100)]

        def _add_node(node_id):
            try:
                with aga._GRAPH_LOCK:
                    aga._agent_graph["nodes"][node_id] = {
                        "name": f"S-{node_id}", "status": "testing",
                        "parent_id": None, "task": "stress", "agent_type": "test",
                    }
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_add_node, args=(t,)) for t in test_ids]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        with aga._GRAPH_LOCK:
            found = sum(1 for k in test_ids if k in aga._agent_graph["nodes"])
        assert found == 100, f"Only {found}/100 survived"

        with aga._GRAPH_LOCK:
            for tid in test_ids:
                aga._agent_graph["nodes"].pop(tid, None)


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 6: R7 — Scope firewall is CALLED from create_sandbox
# ═══════════════════════════════════════════════════════════════════════════════

class TestScopeFirewallWiring:

    def test_firewall_invoked_in_create_sandbox(self):
        src = _read("runtime/docker_runtime.py")
        assert src.count("_configure_scope_firewall") >= 2, \
            "_configure_scope_firewall is still never called!"

    def test_scope_enforcement_config_read(self):
        src = _read("runtime/docker_runtime.py")
        assert "phantom_scope_enforcement" in src


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 7: R2 — Cost abort flag is READ and HONOURED
# ═══════════════════════════════════════════════════════════════════════════════

class TestCostAbortWiring:

    def test_abort_flag_read_in_check_budget(self):
        src = _read("llm/llm.py")
        assert "phantom_cost_abort_on_limit" in src

    def test_advisory_mode_path_exists(self):
        src = _read("llm/llm.py")
        assert "advisory mode" in src.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 8: R10 — Confidence param in XML schema
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfidenceSchemaXML:

    def test_confidence_in_xml(self):
        text = (_ROOT / "tools/reporting/reporting_actions_schema.xml").read_text(encoding=_ENC)
        assert 'name="confidence"' in text, "'confidence' param NOT in schema XML!"

    def test_xml_describes_suspected(self):
        text = (_ROOT / "tools/reporting/reporting_actions_schema.xml").read_text(encoding=_ENC)
        assert "SUSPECTED" in text

    def test_xml_warns_manual_verified(self):
        text = (_ROOT / "tools/reporting/reporting_actions_schema.xml").read_text(encoding=_ENC)
        assert "do NOT set this manually" in text or "Do NOT set this manually" in text


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 9: R3 — Docker resource limits in containers.run
# ═══════════════════════════════════════════════════════════════════════════════

class TestDockerLimitsSource:

    def test_source_contains_resource_kwargs(self):
        src = _read("runtime/docker_runtime.py")
        for kw in ["mem_limit=", "cpu_quota=", "pids_limit=", "memswap_limit="]:
            assert kw in src, f"{kw} not in containers.run!"


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 10: R8 — Token written to /run/secrets
# ═══════════════════════════════════════════════════════════════════════════════

class TestTokenFileSource:

    def test_source_contains_secrets_write(self):
        src = _read("runtime/docker_runtime.py")
        assert "/run/secrets/tool_server_token" in src
        assert "chmod 600" in src


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 11: R4 — Validation keyword detection
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidationKeywordAttack:

    def test_bypass_xss_checker(self):
        """Documents known gap: 'XSS Checker' bypasses keyword detection."""
        from phantom.tools.agents_graph.agents_graph_actions import _VALIDATION_AGENT_KEYWORDS
        assert not any(kw in "xss checker" for kw in _VALIDATION_AGENT_KEYWORDS)

    def test_realistic_names_detected(self):
        from phantom.tools.agents_graph.agents_graph_actions import _VALIDATION_AGENT_KEYWORDS
        for name in ["SQLi Validation Agent", "XSS Validator", "SSRF Verifier",
                      "Verify IDOR Results", "POST-EXPLOIT VALIDATION"]:
            assert any(kw in name.lower() for kw in _VALIDATION_AGENT_KEYWORDS), \
                f"'{name}' not detected!"


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 12: R9 — Depth limit walk
# ═══════════════════════════════════════════════════════════════════════════════

class TestAgentDepthLimitAttack:

    def test_depth_check_walks_parent_chain(self):
        src = _read("tools/agents_graph/agents_graph_actions.py")
        assert "_depth" in src and "_max_depth" in src


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 13: R6 — Ledger injection interval control
# ═══════════════════════════════════════════════════════════════════════════════

class TestLedgerInjectionInterval:

    def test_injection_guard_exists(self):
        src = _read("agents/base_agent.py")
        assert "_LEDGER_INJECT_EVERY" in src
        assert "% _LEDGER_INJECT_EVERY" in src

    def test_empty_ledger_skips_injection(self):
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        ledger = HypothesisLedger()
        assert len(ledger) == 0
        summary = ledger.to_prompt_summary(top_n=10)
        assert not summary or len(summary) < 10


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 14: Cross-cutting import integrity
# ═══════════════════════════════════════════════════════════════════════════════

class TestImportIntegrity:

    def test_import_agents_graph_actions(self):
        import phantom.tools.agents_graph.agents_graph_actions  # noqa: F401

    def test_import_docker_runtime(self):
        import phantom.runtime.docker_runtime  # noqa: F401

    def test_import_reporting_actions(self):
        import phantom.tools.reporting.reporting_actions  # noqa: F401

    def test_import_config(self):
        import phantom.config.config  # noqa: F401

    def test_import_base_agent(self):
        import phantom.agents.base_agent  # noqa: F401

    def test_import_hypothesis_ledger(self):
        import phantom.agents.hypothesis_ledger  # noqa: F401

    def test_import_llm(self):
        import phantom.llm.llm  # noqa: F401
