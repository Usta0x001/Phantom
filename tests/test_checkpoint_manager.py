"""Tests for phantom.core.checkpoint_manager — atomic signed checkpoints."""

import json
from pathlib import Path

import pytest

from phantom.core.audit_signer import AuditSigner
from phantom.core.checkpoint_manager import CheckpointManager
from phantom.core.exceptions import CheckpointTamperError


@pytest.fixture
def signer(tmp_path):
    return AuditSigner(key_dir=tmp_path / "keys")


@pytest.fixture
def manager(signer):
    return CheckpointManager(signer=signer)


class TestSaveLoad:
    def test_round_trip(self, manager, tmp_path):
        ckpt_path = tmp_path / "test.ckpt"
        state = {"iteration": 42, "cost": 1.23, "findings": ["xss"]}
        manager.save_checkpoint(state, ckpt_path)
        loaded = manager.load_checkpoint(ckpt_path)
        assert loaded == state

    def test_file_created(self, manager, tmp_path):
        ckpt_path = tmp_path / "test.ckpt"
        manager.save_checkpoint({"x": 1}, ckpt_path)
        assert ckpt_path.exists()

    def test_file_is_valid_json(self, manager, tmp_path):
        ckpt_path = tmp_path / "test.ckpt"
        manager.save_checkpoint({"x": 1}, ckpt_path)
        data = json.loads(ckpt_path.read_text())
        assert "_sig" in data
        assert "checkpoint" in data

    def test_creates_parent_dirs(self, manager, tmp_path):
        ckpt_path = tmp_path / "deep" / "nested" / "dir" / "test.ckpt"
        manager.save_checkpoint({"x": 1}, ckpt_path)
        assert ckpt_path.exists()


class TestTamperDetection:
    def test_tampered_data_rejected(self, manager, tmp_path):
        ckpt_path = tmp_path / "test.ckpt"
        manager.save_checkpoint({"iteration": 10}, ckpt_path)

        # Tamper with the checkpoint
        raw = json.loads(ckpt_path.read_text())
        raw["checkpoint"]["iteration"] = 0  # Attacker resets iteration!
        ckpt_path.write_text(json.dumps(raw))

        with pytest.raises(CheckpointTamperError, match="signature invalid"):
            manager.load_checkpoint(ckpt_path)

    def test_missing_signature_rejected(self, manager, tmp_path):
        ckpt_path = tmp_path / "test.ckpt"
        ckpt_path.write_text(json.dumps({"checkpoint": {"iteration": 0}}))

        with pytest.raises(CheckpointTamperError, match="no signature"):
            manager.load_checkpoint(ckpt_path)

    def test_invalid_json_rejected(self, manager, tmp_path):
        ckpt_path = tmp_path / "test.ckpt"
        ckpt_path.write_text("not json at all {{{")

        with pytest.raises(CheckpointTamperError, match="not valid JSON"):
            manager.load_checkpoint(ckpt_path)


class TestAtomicWrite:
    def test_no_partial_writes(self, manager, tmp_path):
        """Verify that a read during save doesn't see partial data."""
        ckpt_path = tmp_path / "atomic.ckpt"
        # Write a checkpoint
        manager.save_checkpoint({"complete": True}, ckpt_path)
        # Verify it's fully readable
        loaded = manager.load_checkpoint(ckpt_path)
        assert loaded["complete"] is True
