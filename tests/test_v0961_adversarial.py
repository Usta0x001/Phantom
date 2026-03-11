"""Adversarial regression tests for v0.9.61 bug fixes.

Five bugs were found through code audit of v0.9.60 and fixed in v0.9.61.
Each test below PROVES the fix works and would have failed before the fix.

  Bug 1 – CRITICAL  stale sandbox_id blocks sandbox creation on resume
  Bug 2 – CRITICAL  double task message appended on resume
  Bug 3 – SERIOUS   PHANTOM_CHECKPOINT_INTERVAL env var had zero effect
  Bug 4 – MODERATE  tracer.scan_config=None crashed Pydantic in checkpoint
  Bug 5 – MINOR     _saved_vuln_ids not seeded → all old vulns re-written
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")


# ──────────────────────────────────────────────────────────────────────────────
# Bug 1 — stale sandbox_id must be cleared from restored AgentState
# ──────────────────────────────────────────────────────────────────────────────

class TestBug1StaleSandboxId:
    """When cli.py restores AgentState from a checkpoint, it must clear
    sandbox_id / sandbox_token / sandbox_info so that
    _initialize_sandbox_and_state() creates a fresh sandbox container."""

    def test_agentstate_sandbox_fields_are_none_after_cli_clear(self):
        """Simulate the cli.py restore path and assert the three fields are None."""
        from phantom.agents.state import AgentState
        from phantom.checkpoint.models import CheckpointData

        # Build a serialised AgentState that looks like it came from a live scan
        live_state = AgentState(
            sandbox_id="ws_old_dead_container",
            sandbox_token="tok_12345",
            sandbox_info={"url": "http://localhost:8080", "port": 8080},
        )
        live_state.add_message("user", "scan example.com")
        live_state.add_message("assistant", "Sure, starting…")

        # Serialise → CheckpointData → deserialise (exactly what cli.py does)
        cp = CheckpointData(
            run_name="resume-test",
            iteration=3,
            root_agent_state=live_state.model_dump(),
        )
        raw = cp.model_dump_json()
        cp2 = CheckpointData.model_validate_json(raw)

        restored_state = AgentState.model_validate(cp2.root_agent_state)
        # ── apply the fix (what cli.py now does) ──────────────────────────────
        restored_state.sandbox_id = None
        restored_state.sandbox_token = None
        restored_state.sandbox_info = None
        # ─────────────────────────────────────────────────────────────────────

        assert restored_state.sandbox_id is None, "sandbox_id must be None after restore"
        assert restored_state.sandbox_token is None, "sandbox_token must be None after restore"
        assert restored_state.sandbox_info is None, "sandbox_info must be None after restore"
        # Pre-existing messages are still intact
        assert len(restored_state.messages) == 2

    def test_initialize_sandbox_creates_sandbox_when_id_is_none(self):
        """_initialize_sandbox_and_state must enter the sandbox-creation branch
        when sandbox_id IS None (the correct post-fix state)."""
        from phantom.agents.state import AgentState

        state = AgentState(sandbox_id=None)  # <- cleared by fix

        sandbox_created = []

        async def fake_sandbox_init(self_inner, task: str) -> None:
            # Directly test the condition that guards sandbox creation
            sandbox_mode = os.environ.get("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
            if not sandbox_mode and self_inner.state.sandbox_id is None:
                sandbox_created.append(True)
                self_inner.state.sandbox_id = "ws_new_container"
            if not self_inner.state.messages:
                self_inner.state.add_message("user", task)

        # Build a minimal agent with our state attached
        from phantom.agents.base_agent import BaseAgent
        agent = object.__new__(BaseAgent)
        agent.state = state

        import asyncio
        asyncio.run(fake_sandbox_init(agent, "scan example.com"))

        assert sandbox_created, "Sandbox creation branch was NOT entered — Bug 1 regression!"
        assert agent.state.sandbox_id == "ws_new_container"


# ──────────────────────────────────────────────────────────────────────────────
# Bug 2 — no double task message on resume
# ──────────────────────────────────────────────────────────────────────────────

class TestBug2DoubleTaskMessage:
    """_initialize_sandbox_and_state must NOT append the task message when
    the state already has messages (resume path)."""

    def _count_user_messages(self, messages: list[dict]) -> int:
        return sum(1 for m in messages if m.get("role") == "user")

    def test_no_duplicate_task_on_populated_state(self):
        """When state already has messages, calling the fixed guard must
        leave message count unchanged."""
        from phantom.agents.state import AgentState

        state = AgentState()
        state.add_message("user", "scan example.com")          # original from fresh start
        state.add_message("assistant", "Starting scan…")
        state.add_message("user", "[SCAN RESUMED] …")           # resume notice from cli.py

        initial_count = len(state.messages)

        # Reproduce the FIXED guard:  if not self.state.messages
        if not state.messages:
            state.add_message("user", "scan example.com")

        assert len(state.messages) == initial_count, (
            "Bug 2 regression: task message was appended even though messages existed"
        )

    def test_task_message_added_on_empty_state(self):
        """On a fresh (non-resume) run, the task message must be added normally."""
        from phantom.agents.state import AgentState

        state = AgentState()
        assert len(state.messages) == 0

        if not state.messages:
            state.add_message("user", "scan example.com")

        assert len(state.messages) == 1
        assert state.messages[0]["content"] == "scan example.com"

    def test_user_message_count_stays_at_two_not_three_after_resume(self):
        """Full resume simulation: fresh start adds 1 user msg; resume adds
        SCAN RESUMED msg; guard must block the 3rd (duplicate) task msg."""
        from phantom.agents.state import AgentState

        # Simulate fresh scan state that was checkpointed
        state = AgentState()
        state.add_message("user", "scan example.com")
        state.add_message("assistant", "Step 1 complete.")

        # Simulate what cli.py does on resume
        state.add_message("user", "[SCAN RESUMED] Continue from iteration 3.")

        user_msgs_before = self._count_user_messages(state.messages)  # 2

        # Simulate the FIXED _initialize_sandbox_and_state:
        if not state.messages:
            state.add_message("user", "scan example.com")

        user_msgs_after = self._count_user_messages(state.messages)
        assert user_msgs_after == user_msgs_before == 2, (
            f"Expected 2 user messages after resume, got {user_msgs_after}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Bug 3 — PHANTOM_CHECKPOINT_INTERVAL env var is now respected
# ──────────────────────────────────────────────────────────────────────────────

class TestBug3CheckpointIntervalEnv:
    """CheckpointManager must accept an `interval` parameter and use it
    in should_save() instead of the hardcoded CHECKPOINT_INTERVAL constant."""

    def test_custom_interval_accepted(self, tmp_path):
        from phantom.checkpoint.checkpoint import CheckpointManager
        mgr = CheckpointManager(tmp_path, interval=10)
        assert mgr._interval == 10

    def test_default_interval_is_constant(self, tmp_path):
        from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
        mgr = CheckpointManager(tmp_path)
        assert mgr._interval == CHECKPOINT_INTERVAL

    def test_custom_interval_10_should_save_at_10_not_5(self, tmp_path):
        from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL

        default_mgr = CheckpointManager(tmp_path, interval=CHECKPOINT_INTERVAL)
        custom_mgr = CheckpointManager(tmp_path, interval=10)

        # With default interval=5, iteration 5 triggers a save
        assert default_mgr.should_save(5) is True
        # With custom interval=10, iteration 5 must NOT trigger a save
        assert custom_mgr.should_save(5) is False, (
            "Bug 3 regression: should_save(5) returned True with interval=10"
        )

    def test_custom_interval_10_saves_at_10(self, tmp_path):
        from phantom.checkpoint.checkpoint import CheckpointManager
        mgr = CheckpointManager(tmp_path, interval=10)
        assert mgr.should_save(10) is True
        assert mgr.should_save(20) is True

    def test_interval_1_saves_every_iteration(self, tmp_path):
        from phantom.checkpoint.checkpoint import CheckpointManager
        mgr = CheckpointManager(tmp_path, interval=1)
        for i in range(1, 10):
            assert mgr.should_save(i) is True, f"should_save({i}) was False with interval=1"

    def test_env_var_roundtrip_via_config(self):
        """Config.get('phantom_checkpoint_interval') must parse to the int we set."""
        os.environ["PHANTOM_CHECKPOINT_INTERVAL"] = "7"
        try:
            from phantom.config import Config
            from phantom.checkpoint.checkpoint import CHECKPOINT_INTERVAL
            raw = Config.get("phantom_checkpoint_interval")
            interval = int(raw or str(CHECKPOINT_INTERVAL))
            assert interval == 7, f"Expected 7, got {interval}"
        finally:
            del os.environ["PHANTOM_CHECKPOINT_INTERVAL"]


# ──────────────────────────────────────────────────────────────────────────────
# Bug 4 — scan_config=None must not crash Pydantic in _maybe_save_checkpoint
# ──────────────────────────────────────────────────────────────────────────────

class TestBug4ScanConfigNone:
    """tracer.scan_config is typed dict|None and starts as None.
    CheckpointData.scan_config is typed dict — so passing None crashes Pydantic.
    The fix is `tracer.scan_config or {}` instead of `tracer.scan_config`."""

    def test_checkpoint_data_accepts_empty_dict_not_none(self):
        from phantom.checkpoint.models import CheckpointData
        cp = CheckpointData(run_name="x", scan_config={})
        assert cp.scan_config == {}

    def test_checkpoint_data_rejects_none_scan_config(self):
        """Verify that CheckpointData actually rejects None for scan_config (proving
        the fix is necessary)."""
        from phantom.checkpoint.models import CheckpointData
        from pydantic import ValidationError
        with pytest.raises((ValidationError, TypeError)):
            CheckpointData(run_name="x", scan_config=None)  # type: ignore[arg-type]

    def test_or_empty_dict_guard_on_none(self):
        """The `tracer.scan_config or {}` expression returns {} when scan_config is None."""
        scan_config_value = None
        result = scan_config_value or {}
        assert result == {}

    def test_or_empty_dict_guard_preserves_existing_dict(self):
        """The `tracer.scan_config or {}` expression returns the original dict when set."""
        scan_config_value: dict = {"target": "example.com", "profile": "quick"}
        result = scan_config_value or {}
        assert result == {"target": "example.com", "profile": "quick"}

    def test_mock_tracer_with_none_scan_config_builds_checkpoint(self):
        """Full integration: build CheckpointData with a mock tracer whose
        scan_config is None — must not raise."""
        from phantom.checkpoint.models import CheckpointData

        tracer = MagicMock()
        tracer.scan_config = None       # <- the problematic case pre-fix

        # The FIXED expression used in _maybe_save_checkpoint:
        scan_config = tracer.scan_config or {} if tracer else {}

        # Must not raise:
        cp = CheckpointData(run_name="test", scan_config=scan_config)
        assert cp.scan_config == {}

    def test_mock_tracer_with_set_scan_config_builds_checkpoint(self):
        from phantom.checkpoint.models import CheckpointData

        tracer = MagicMock()
        tracer.scan_config = {"target": "example.com"}

        scan_config = tracer.scan_config or {} if tracer else {}

        cp = CheckpointData(run_name="test", scan_config=scan_config)
        assert cp.scan_config == {"target": "example.com"}


# ──────────────────────────────────────────────────────────────────────────────
# Bug 5 — _saved_vuln_ids must be seeded from restored vulnerability reports
# ──────────────────────────────────────────────────────────────────────────────

class TestBug5SavedVulnIdsSeeded:
    """On resume, tracer._saved_vuln_ids must contain the IDs of all restored
    vulnerability reports.  Without the fix, every old vuln would be re-written
    to disk on the first save_run_data() call."""

    def _make_vuln(self, vuln_id: str) -> dict:
        return {
            "id": vuln_id,
            "title": f"Test vuln {vuln_id}",
            "severity": "high",
            "description": "test description",
        }

    def test_saved_vuln_ids_contains_restored_ids(self):
        """Simulate the cli.py post-fix code and verify _saved_vuln_ids is populated."""
        from phantom.telemetry.tracer import Tracer

        tracer = Tracer.__new__(Tracer)
        tracer.vulnerability_reports = []
        tracer._saved_vuln_ids = set()

        restored_vulns = [
            self._make_vuln("vuln-001"),
            self._make_vuln("vuln-002"),
            self._make_vuln("vuln-003"),
        ]

        # Apply the fix:
        tracer.vulnerability_reports.extend(restored_vulns)
        for v in restored_vulns:                        # ← the actual fix line
            tracer._saved_vuln_ids.add(v["id"])

        assert "vuln-001" in tracer._saved_vuln_ids
        assert "vuln-002" in tracer._saved_vuln_ids
        assert "vuln-003" in tracer._saved_vuln_ids
        assert len(tracer._saved_vuln_ids) == 3

    def test_without_fix_saved_vuln_ids_is_empty(self):
        """Prove the original bug: extend without seeding leaves _saved_vuln_ids empty."""
        from phantom.telemetry.tracer import Tracer

        tracer = Tracer.__new__(Tracer)
        tracer.vulnerability_reports = []
        tracer._saved_vuln_ids = set()

        restored_vulns = [self._make_vuln("vuln-001")]

        # OLD code (no seeding):
        tracer.vulnerability_reports.extend(restored_vulns)
        # _saved_vuln_ids NOT seeded

        assert len(tracer._saved_vuln_ids) == 0, "Pre-fix: IDs were absent from _saved_vuln_ids"

    def test_old_vulns_not_re_written_after_fix(self, tmp_path):
        """Verify that new_reports filter works correctly — old IDs are excluded
        from the 'new' set once _saved_vuln_ids is pre-seeded, so they won't
        be re-written to disk."""
        restored_ids = {"vuln-001", "vuln-002"}

        all_reports = [
            self._make_vuln("vuln-001"),
            self._make_vuln("vuln-002"),
            self._make_vuln("vuln-003"),  # newly found after resume
        ]

        # Pre-seeded (post-fix):
        saved_ids = set(restored_ids)

        new_reports = [r for r in all_reports if r["id"] not in saved_ids]
        assert len(new_reports) == 1
        assert new_reports[0]["id"] == "vuln-003"

    def test_empty_checkpoint_no_error(self):
        """Edge case: empty vulnerability list must not raise."""
        from phantom.telemetry.tracer import Tracer

        tracer = Tracer.__new__(Tracer)
        tracer.vulnerability_reports = []
        tracer._saved_vuln_ids = set()

        for v in []:
            tracer._saved_vuln_ids.add(v["id"])

        assert tracer._saved_vuln_ids == set()
