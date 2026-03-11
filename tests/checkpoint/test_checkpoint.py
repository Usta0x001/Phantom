"""Tests for phantom.checkpoint — CheckpointManager and CheckpointData.

Covers:
  - Atomic write: .tmp → .json rename
  - Crash safety: corrupt checkpoint is ignored, None returned
  - should_save() interval logic
  - mark_completed() sets status="completed"
  - CheckpointData round-trips through JSON
  - CheckpointManager.build() populates fields from AgentState
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o")
os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")

from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
from phantom.checkpoint.models import CheckpointData


# ── helpers ────────────────────────────────────────────────────────────────────

def make_checkpoint(run_dir: Path, iteration: int = 1) -> CheckpointData:
    return CheckpointData(
        run_name="test-run",
        iteration=iteration,
        task_description="scan example.com",
        status="in_progress",
    )


# ── CheckpointData model ───────────────────────────────────────────────────────

class TestCheckpointData:
    def test_default_status_is_in_progress(self):
        cp = CheckpointData(run_name="x")
        assert cp.status == "in_progress"

    def test_version_is_string_1(self):
        cp = CheckpointData(run_name="x")
        assert cp.version == "1"

    def test_json_round_trip(self):
        cp = CheckpointData(
            run_name="abc",
            iteration=42,
            compression_calls=3,
            agent_calls=10,
            per_model_stats={"deepseek/deepseek-chat": {"requests": 5}},
        )
        raw = cp.model_dump_json()
        restored = CheckpointData.model_validate_json(raw)
        assert restored.run_name == "abc"
        assert restored.iteration == 42
        assert restored.compression_calls == 3
        assert restored.agent_calls == 10
        assert restored.per_model_stats["deepseek/deepseek-chat"]["requests"] == 5


# ── CheckpointManager.should_save ─────────────────────────────────────────────

class TestShouldSave:
    def test_saves_at_iteration_1(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        assert mgr.should_save(1) is True

    def test_saves_at_interval_multiples(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        assert mgr.should_save(CHECKPOINT_INTERVAL) is True
        assert mgr.should_save(CHECKPOINT_INTERVAL * 2) is True

    def test_does_not_save_mid_interval(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        assert mgr.should_save(2) is False
        assert mgr.should_save(3) is False
        assert mgr.should_save(CHECKPOINT_INTERVAL - 1) is False

    def test_saves_at_zero_is_false(self, tmp_path):
        # Iteration 0 means pre-loop; should NOT trigger a save
        mgr = CheckpointManager(tmp_path)
        assert mgr.should_save(0) is False


# ── CheckpointManager save / load ─────────────────────────────────────────────

class TestSaveLoad:
    def test_save_creates_checkpoint_file(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        cp = make_checkpoint(tmp_path)
        mgr.save(cp)
        assert (tmp_path / "checkpoint.json").exists()

    def test_no_tmp_file_left_after_save(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        mgr.save(make_checkpoint(tmp_path))
        assert not (tmp_path / "checkpoint.tmp").exists()

    def test_load_returns_none_when_file_absent(self, tmp_path):
        mgr = CheckpointManager(tmp_path / "no_such_dir")
        assert mgr.load() is None

    def test_load_returns_correct_data(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        cp = CheckpointData(run_name="my-run", iteration=7, compression_calls=2)
        mgr.save(cp)
        loaded = mgr.load()
        assert loaded is not None
        assert loaded.run_name == "my-run"
        assert loaded.iteration == 7
        assert loaded.compression_calls == 2

    def test_load_returns_none_on_corrupt_file(self, tmp_path):
        f = tmp_path / "checkpoint.json"
        f.write_text("NOT VALID JSON{{{", encoding="utf-8")
        mgr = CheckpointManager(tmp_path)
        assert mgr.load() is None

    def test_exists_true_after_save(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        mgr.save(make_checkpoint(tmp_path))
        assert mgr.exists() is True

    def test_exists_false_before_save(self, tmp_path):
        mgr = CheckpointManager(tmp_path / "new")
        assert mgr.exists() is False

    def test_overwrite_updates_iteration(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        mgr.save(make_checkpoint(tmp_path, iteration=1))
        mgr.save(make_checkpoint(tmp_path, iteration=10))
        loaded = mgr.load()
        assert loaded is not None
        assert loaded.iteration == 10


# ── mark_completed ─────────────────────────────────────────────────────────────

class TestMarkCompleted:
    def test_mark_completed_sets_status(self, tmp_path):
        mgr = CheckpointManager(tmp_path)
        mgr.save(make_checkpoint(tmp_path))
        mgr.mark_completed()
        loaded = mgr.load()
        assert loaded is not None
        assert loaded.status == "completed"

    def test_mark_completed_noop_when_no_checkpoint(self, tmp_path):
        mgr = CheckpointManager(tmp_path / "empty")
        # Should not raise
        mgr.mark_completed()


# ── CheckpointManager.build ────────────────────────────────────────────────────

class TestBuild:
    def test_build_from_agent_state(self, tmp_path):
        from phantom.agents.state import AgentState

        state = AgentState(agent_name="Root Agent", max_iterations=300, task="scan foo")
        state.iteration = 5

        cp = CheckpointManager.build(
            run_name="my-run",
            state=state,
            tracer=None,
            scan_config={"targets": ["foo"]},
        )

        assert cp.run_name == "my-run"
        assert cp.iteration == 5
        assert cp.task_description == "scan foo"
        assert cp.scan_config == {"targets": ["foo"]}
        assert cp.status == "in_progress"
        assert isinstance(cp.root_agent_state, dict)
        assert cp.root_agent_state["agent_name"] == "Root Agent"

    def test_build_with_interrupted_status(self, tmp_path):
        from phantom.agents.state import AgentState

        state = AgentState()
        cp = CheckpointManager.build(
            run_name="r",
            state=state,
            tracer=None,
            scan_config={},
            status="interrupted",
            interruption_reason="SIGINT",
        )
        assert cp.status == "interrupted"
        assert cp.interruption_reason == "SIGINT"
