"""Test Suite 7: Strategic Planner (T1-07, DEFECT-SP-001)."""
import pytest
from phantom.core.strategic_planner import (
    StrategicPlanner,
    ToolEffectivenessTracker,
)


class TestGetStatusPlacement:
    """T1-07: get_status on StrategicPlanner, not ToolEffectivenessTracker."""

    def test_planner_has_get_status(self, strategic_planner):
        assert hasattr(strategic_planner, "get_status")
        status = strategic_planner.get_status()
        assert isinstance(status, dict)

    def test_tracker_has_no_get_status(self):
        tracker = ToolEffectivenessTracker()
        assert not hasattr(tracker, "get_status"), (
            "get_status should be on StrategicPlanner, not ToolEffectivenessTracker"
        )

    def test_status_contains_expected_keys(self, strategic_planner):
        status = strategic_planner.get_status()
        for key in ("total_tool_calls", "coverage"):
            assert key in status, f"Missing expected key '{key}' in status"


class TestPlannerSerialization:
    """Roundtrip serialization of StrategicPlanner."""

    def test_serialize_from_dict_roundtrip(self, strategic_planner):
        data = strategic_planner.serialize()
        assert isinstance(data, dict)

        restored = StrategicPlanner.from_dict(data)
        assert isinstance(restored, StrategicPlanner)

    def test_serialization_preserves_tool_history(self, strategic_planner, mock_state):
        strategic_planner.record_tool_call("nmap", args={}, result="open ports", state=mock_state)
        strategic_planner.record_tool_call("sqlmap", args={}, result="error", state=mock_state)

        data = strategic_planner.serialize()
        restored = StrategicPlanner.from_dict(data)

        original_status = strategic_planner.get_status()
        restored_status = restored.get_status()
        assert original_status["total_tool_calls"] == restored_status["total_tool_calls"]
