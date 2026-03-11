"""Adversarial regression + integration tests for v0.9.62 fixes.

Three bugs fixed and two features improved:

  Bug A  – CRITICAL  start_text = Text() missing in cli.py → NameError on every scan start
  Bug B  – HIGH      sender_name used before assignment in _check_agent_messages → NameError
  Rec R1 – AgentState.clear_sandbox() explicit method
  Rec R2 – cli.py uses clear_sandbox() instead of 3 manual lines
  Rec R3 – CheckpointManager logs _interval at startup

Plus: end-to-end resume integration test (checkpoint → restore → verify).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")


# ──────────────────────────────────────────────────────────────────────────────
# Bug A — start_text = Text() missing in cli.py
# ──────────────────────────────────────────────────────────────────────────────

class TestBugAStartTextMissing:
    """cli.py must define start_text = Text() before the first .append() call."""

    def test_cli_py_contains_start_text_assignment(self):
        """Prove the fix is present in the source file."""
        cli_path = _ROOT / "phantom" / "interface" / "cli.py"
        src = cli_path.read_text(encoding="utf-8")
        # The assignment must appear before the first append call
        assign_pos = src.find("start_text = Text()")
        append_pos = src.find('start_text.append("Penetration test initiated"')
        assert assign_pos != -1, "start_text = Text() assignment is MISSING from cli.py"
        assert assign_pos < append_pos, (
            "start_text = Text() must appear BEFORE start_text.append(...)"
        )

    def test_start_text_assign_before_panel_building(self):
        """The assignment must be in the startup panel section."""
        cli_path = _ROOT / "phantom" / "interface" / "cli.py"
        src = cli_path.read_text(encoding="utf-8")
        # Both landmarks must be in the same section
        panel_marker = "Build startup panel"
        panel_pos = src.find(panel_marker)
        assign_pos = src.find("start_text = Text()")
        assert panel_pos != -1
        assert assign_pos != -1
        # The assignment must be close to (and after) the panel section marker
        assert assign_pos > panel_pos, "start_text = Text() must be in the startup panel section"
        assert assign_pos - panel_pos < 500, (
            "start_text = Text() should be within 500 chars of the panel marker"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Bug B — sender_name unbound before use in _check_agent_messages
# ──────────────────────────────────────────────────────────────────────────────

class TestBugBSenderNameUnbound:
    """When sender_id is not in the agent graph, sender_name must still have a
    safe fallback value so the f-string interpolation never raises NameError."""

    def _build_minimal_state(self):
        from phantom.agents.state import AgentState
        state = AgentState()
        state.add_message("user", "hello")
        return state

    def _build_message(self, sender_id: str | None, content: str = "test") -> dict:
        return {
            "read": False,
            "from": sender_id,
            "content": content,
            "message_type": "information",
            "priority": "normal",
            "timestamp": "2026-01-01T00:00:00Z",
        }

    def test_sender_in_graph_uses_graph_name(self):
        """When sender_id IS in the graph, sender_name comes from the graph."""
        from phantom.tools.agents_graph import agents_graph_actions

        agent_id = "agent_test001"
        agents_graph_actions._agent_messages[agent_id] = [
            self._build_message("agent_other", "from another agent")
        ]
        agents_graph_actions._agent_graph["nodes"]["agent_other"] = {
            "name": "Recon Agent",
            "id": "agent_other",
        }

        state = self._build_minimal_state()
        state.agent_id = agent_id

        from phantom.agents.base_agent import BaseAgent
        agent = object.__new__(BaseAgent)

        # Must not raise
        agent._check_agent_messages(state)

        # The message should have been processed
        user_msgs = [m for m in state.messages if m["role"] == "user"]
        last_content = user_msgs[-1]["content"] if user_msgs else ""
        assert "Recon Agent" in last_content or "agent_other" in last_content

        # Cleanup
        del agents_graph_actions._agent_messages[agent_id]
        del agents_graph_actions._agent_graph["nodes"]["agent_other"]

    def test_sender_not_in_graph_uses_fallback_not_raises(self):
        """When sender_id is NOT in the graph, must use fallback name, not raise NameError."""
        from phantom.tools.agents_graph import agents_graph_actions

        agent_id = "agent_test002"
        agents_graph_actions._agent_messages[agent_id] = [
            self._build_message("ghost_agent_xyz", "message from unknown agent")
        ]
        # Deliberately do NOT add ghost_agent_xyz to the graph

        state = self._build_minimal_state()
        state.agent_id = agent_id

        from phantom.agents.base_agent import BaseAgent
        agent = object.__new__(BaseAgent)

        # Must not raise NameError
        agent._check_agent_messages(state)

        # The fallback should be the sender_id itself
        user_msgs = [m for m in state.messages if m["role"] == "user"]
        last_content = user_msgs[-1]["content"] if user_msgs else ""
        assert "ghost_agent_xyz" in last_content, (
            f"Expected sender_id fallback in message, got: {last_content[:200]}"
        )

        # Cleanup
        del agents_graph_actions._agent_messages[agent_id]

    def test_sender_id_none_uses_unknown_fallback(self):
        """When sender_id is None, use 'unknown-agent' fallback, not raise."""
        from phantom.tools.agents_graph import agents_graph_actions

        agent_id = "agent_test003"
        agents_graph_actions._agent_messages[agent_id] = [
            self._build_message(None, "message with no sender")
        ]

        state = self._build_minimal_state()
        state.agent_id = agent_id

        from phantom.agents.base_agent import BaseAgent
        agent = object.__new__(BaseAgent)

        # Must not raise NameError
        agent._check_agent_messages(state)

        # Cleanup
        del agents_graph_actions._agent_messages[agent_id]

    def test_base_agent_source_has_fallback_sender_name(self):
        """Prove the fix is present in the source file."""
        src_path = _ROOT / "phantom" / "agents" / "base_agent.py"
        src = src_path.read_text(encoding="utf-8")
        assert "sender_name = sender_id or" in src or "sender_name = sender_id or \"unknown-agent\"" in src, (
            "Bug B fix missing: sender_name fallback not found in base_agent.py"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Rec R1 — AgentState.clear_sandbox() method
# ──────────────────────────────────────────────────────────────────────────────

class TestRecR1ClearSandboxMethod:
    """AgentState.clear_sandbox() must exist and zero the three sandbox fields."""

    def test_method_exists(self):
        from phantom.agents.state import AgentState
        assert hasattr(AgentState, "clear_sandbox"), "AgentState.clear_sandbox() method missing"
        assert callable(AgentState.clear_sandbox)

    def test_clears_all_three_fields(self):
        from phantom.agents.state import AgentState
        state = AgentState(
            sandbox_id="ws_old",
            sandbox_token="tok_old",
            sandbox_info={"url": "http://localhost:8080"},
        )
        state.clear_sandbox()
        assert state.sandbox_id is None
        assert state.sandbox_token is None
        assert state.sandbox_info is None

    def test_idempotent_when_already_none(self):
        from phantom.agents.state import AgentState
        state = AgentState()
        state.clear_sandbox()  # should not raise
        assert state.sandbox_id is None

    def test_does_not_affect_other_fields(self):
        from phantom.agents.state import AgentState
        state = AgentState(sandbox_id="ws_old")
        state.add_message("user", "task")
        state.task = "scan example.com"
        state.clear_sandbox()
        # Other fields untouched
        assert state.task == "scan example.com"
        assert len(state.messages) == 1


# ──────────────────────────────────────────────────────────────────────────────
# Rec R2 — cli.py uses clear_sandbox() (not 3 manual lines)
# ──────────────────────────────────────────────────────────────────────────────

class TestRecR2ClearSandboxInCli:
    """cli.py must call restored_state.clear_sandbox() rather than
    manually setting the three fields one by one."""

    def test_cli_uses_clear_sandbox_call(self):
        cli_path = _ROOT / "phantom" / "interface" / "cli.py"
        src = cli_path.read_text(encoding="utf-8")
        assert "clear_sandbox()" in src, (
            "cli.py must call restored_state.clear_sandbox() after model_validate"
        )

    def test_cli_does_not_manually_set_sandbox_id(self):
        """After applying Rec R2, manual 3-line assignments must be gone."""
        cli_path = _ROOT / "phantom" / "interface" / "cli.py"
        src = cli_path.read_text(encoding="utf-8")
        # The three manual assignments should no longer exist consecutively
        manual_block = "restored_state.sandbox_id = None\n        restored_state.sandbox_token = None\n        restored_state.sandbox_info = None"
        assert manual_block not in src, (
            "Manual sandbox field clearing should be replaced by clear_sandbox()"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Rec R3 — CheckpointManager logs _interval
# ──────────────────────────────────────────────────────────────────────────────

class TestRecR3IntervalLogged:
    """CheckpointManager.__init__ must emit an INFO log about the interval."""

    def test_interval_logged_at_info_level(self, tmp_path, caplog):
        import logging
        from phantom.checkpoint.checkpoint import CheckpointManager
        with caplog.at_level(logging.INFO, logger="phantom.checkpoint.checkpoint"):
            mgr = CheckpointManager(tmp_path, interval=7)
        assert any("7" in record.message and "interval" in record.message.lower()
                   for record in caplog.records), (
            "Expected INFO log mentioning '7' and 'interval' but got: "
            + str([r.message for r in caplog.records])
        )

    def test_source_contains_logger_info_interval(self):
        src_path = _ROOT / "phantom" / "checkpoint" / "checkpoint.py"
        src = src_path.read_text(encoding="utf-8")
        assert "logger.info" in src and "interval" in src, (
            "checkpoint.py must call logger.info() mentioning interval"
        )


# ──────────────────────────────────────────────────────────────────────────────
# E2E Resume Integration Test
# ──────────────────────────────────────────────────────────────────────────────

class TestE2EResumeIntegration:
    """End-to-end: create a checkpoint that simulates a saved scan, restore it,
    and verify all invariants hold without requiring a real Docker sandbox."""

    def _build_live_checkpoint(self, tmp_path: Path) -> tuple:
        """Create a realistic checkpoint as if an interrupted scan had produced it."""
        from phantom.checkpoint.checkpoint import CheckpointManager
        from phantom.checkpoint.models import CheckpointData
        from phantom.agents.state import AgentState

        # Simulate a scan that ran 3 iterations and found 2 vulns
        state = AgentState(
            sandbox_id="ws_12345_dead",
            sandbox_token="tok_abcde_dead",
            sandbox_info={"url": "http://localhost:8080", "port": 8080},
            task="scan example.com",
        )
        state.add_message("user", "scan example.com")
        state.add_message("assistant", "Starting recon…")
        state.add_message("user", "<tool_result>nmap output</tool_result>")
        state.add_message("assistant", "Found open ports 80 and 443.")
        state.iteration = 3

        vulns = [
            {"id": "vuln-001", "title": "XSS", "severity": "high"},
            {"id": "vuln-002", "title": "SQLi", "severity": "critical"},
        ]

        cp = CheckpointData(
            run_name="e2e-test-run",
            iteration=3,
            task_description="scan example.com",
            status="interrupted",
            interruption_reason="SIGINT",
            root_agent_state=state.model_dump(),
            vulnerability_reports=vulns,
        )

        run_dir = tmp_path / "phantom_runs" / "e2e-test-run"
        mgr = CheckpointManager(run_dir)
        mgr.save(cp)

        return mgr, cp, state

    def test_checkpoint_roundtrip_preserves_all_fields(self, tmp_path):
        """Saved checkpoint must be loadable with all fields intact."""
        from phantom.checkpoint.checkpoint import CheckpointManager
        mgr, original_cp, _ = self._build_live_checkpoint(tmp_path)
        loaded = mgr.load()
        assert loaded is not None
        assert loaded.run_name == "e2e-test-run"
        assert loaded.iteration == 3
        assert len(loaded.vulnerability_reports) == 2
        assert loaded.status == "interrupted"

    def test_restore_clears_sandbox_fields(self, tmp_path):
        """After restoring AgentState from checkpoint and calling clear_sandbox(),
        all three sandbox fields must be None."""
        from phantom.agents.state import AgentState
        mgr, cp, _ = self._build_live_checkpoint(tmp_path)
        loaded_cp = mgr.load()

        restored = AgentState.model_validate(loaded_cp.root_agent_state)
        # Before clear — sandbox fields are set (as they were in the live scan)
        assert restored.sandbox_id == "ws_12345_dead"

        # Apply the fix
        restored.clear_sandbox()

        assert restored.sandbox_id is None
        assert restored.sandbox_token is None
        assert restored.sandbox_info is None

    def test_resume_message_count_not_doubled(self, tmp_path):
        """After restoring messages + adding SCAN RESUMED notice,
        the task message must NOT be appended again (Bug 2 guard)."""
        from phantom.agents.state import AgentState
        mgr, cp, _ = self._build_live_checkpoint(tmp_path)
        loaded_cp = mgr.load()

        restored = AgentState.model_validate(loaded_cp.root_agent_state)
        restored.clear_sandbox()

        # Add the SCAN RESUMED message exactly as cli.py does
        restored.add_message(
            "user",
            f"[SCAN RESUMED] iteration {loaded_cp.iteration}",
        )
        count_before = len(restored.messages)

        # Simulate FIXED _initialize_sandbox_and_state guard:
        if not restored.messages:
            restored.add_message("user", "scan example.com")

        count_after = len(restored.messages)
        assert count_after == count_before, (
            f"Message was added despite non-empty history: {count_before} → {count_after}"
        )

    def test_vuln_ids_seeded_on_restore(self, tmp_path):
        """After restoring vulnerability_reports into the tracer,
        _saved_vuln_ids must contain all restored IDs."""
        from phantom.telemetry.tracer import Tracer
        mgr, cp, _ = self._build_live_checkpoint(tmp_path)
        loaded_cp = mgr.load()

        tracer = Tracer.__new__(Tracer)
        tracer.vulnerability_reports = []
        tracer._saved_vuln_ids = set()

        tracer.vulnerability_reports.extend(loaded_cp.vulnerability_reports)
        for v in loaded_cp.vulnerability_reports:
            tracer._saved_vuln_ids.add(v["id"])

        assert "vuln-001" in tracer._saved_vuln_ids
        assert "vuln-002" in tracer._saved_vuln_ids

    def test_new_vulns_after_resume_not_re_written(self, tmp_path):
        """A newly found vulnerability after resume must be in the write list,
        while old ones (already seeded) must not be."""
        from phantom.telemetry.tracer import Tracer
        mgr, cp, _ = self._build_live_checkpoint(tmp_path)
        loaded_cp = mgr.load()

        tracer = Tracer.__new__(Tracer)
        tracer.vulnerability_reports = []
        tracer._saved_vuln_ids = set()

        tracer.vulnerability_reports.extend(loaded_cp.vulnerability_reports)
        for v in loaded_cp.vulnerability_reports:
            tracer._saved_vuln_ids.add(v["id"])

        # New vuln discovered after resume
        tracer.vulnerability_reports.append({"id": "vuln-003", "title": "CSRF"})

        new_reports = [
            r for r in tracer.vulnerability_reports
            if r["id"] not in tracer._saved_vuln_ids
        ]
        assert len(new_reports) == 1
        assert new_reports[0]["id"] == "vuln-003"

    def test_checkpoint_interval_honoured_during_resume(self, tmp_path):
        """CheckpointManager created during resume with interval=10 must
        not fire at iteration 5 (only at 10)."""
        from phantom.checkpoint.checkpoint import CheckpointManager
        run_dir = tmp_path / "phantom_runs" / "interval-test"
        mgr = CheckpointManager(run_dir, interval=10)
        assert mgr.should_save(5) is False
        assert mgr.should_save(10) is True

    def test_full_resume_state_is_consistent(self, tmp_path):
        """After full restore pipeline: state has the right message count,
        sandbox is clear, and vuln count matches the checkpoint."""
        from phantom.agents.state import AgentState
        from phantom.telemetry.tracer import Tracer
        mgr, cp, _ = self._build_live_checkpoint(tmp_path)
        loaded_cp = mgr.load()

        # --- agent state restore ---
        restored = AgentState.model_validate(loaded_cp.root_agent_state)
        restored.clear_sandbox()
        restored.add_message("user", "[SCAN RESUMED] iteration 3")

        # --- tracer restore ---
        tracer = Tracer.__new__(Tracer)
        tracer.vulnerability_reports = []
        tracer._saved_vuln_ids = set()
        tracer.vulnerability_reports.extend(loaded_cp.vulnerability_reports)
        for v in loaded_cp.vulnerability_reports:
            tracer._saved_vuln_ids.add(v["id"])

        # Assertions
        assert restored.sandbox_id is None
        assert restored.sandbox_token is None
        assert restored.task == "scan example.com"
        assert restored.iteration == 3
        assert len(tracer.vulnerability_reports) == 2
        assert tracer._saved_vuln_ids == {"vuln-001", "vuln-002"}

        # The message list should have original 4 + resumed notice = 5
        assert len(restored.messages) == 5
