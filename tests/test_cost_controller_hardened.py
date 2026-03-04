"""Tests for cost_controller hardening — monotonicity, compression tracking."""

import pytest

from phantom.core.exceptions import CostLimitExceeded


class TestMonotonicity:
    """v0.9.39: Cost can never decrease."""

    def test_cost_increases_only(self):
        from phantom.core.cost_controller import CostController
        cc = CostController(max_cost_usd=100.0)
        cc.record_usage(input_tokens=100, output_tokens=50, cost_usd=0.01)
        cc.record_usage(input_tokens=100, output_tokens=50, cost_usd=0.02)
        assert cc._state.total_cost_usd == pytest.approx(0.03)

    def test_zero_cost_accepted(self):
        from phantom.core.cost_controller import CostController
        cc = CostController(max_cost_usd=100.0)
        cc.record_usage(input_tokens=100, output_tokens=50, cost_usd=0.0)
        assert cc._state.total_cost_usd >= 0


class TestCompressionTracking:
    """ARC-006: Compression calls are tracked and limited."""

    def test_compression_cost_recorded(self):
        from phantom.core.cost_controller import CostController
        cc = CostController(max_cost_usd=100.0, max_compression_calls=10)
        cc.record_usage(
            input_tokens=1000, output_tokens=200,
            cost_usd=0.05, is_compression=True,
        )
        assert cc._state.compression_calls == 1
        assert cc._state.compression_cost_usd == pytest.approx(0.05)

    def test_compression_limit_enforced(self):
        from phantom.core.cost_controller import CostController
        cc = CostController(max_cost_usd=100.0, max_compression_calls=2)
        cc.record_usage(cost_usd=0.01, is_compression=True)
        cc.record_usage(cost_usd=0.01, is_compression=True)
        with pytest.raises(CostLimitExceeded, match="[Cc]ompression"):
            cc.record_usage(cost_usd=0.01, is_compression=True)


class TestCostLimitExceededPropagation:
    """CostLimitExceeded propagates correctly."""

    def test_budget_exceeded_raises(self):
        from phantom.core.cost_controller import CostController
        cc = CostController(max_cost_usd=0.10)
        with pytest.raises(CostLimitExceeded):
            cc.record_usage(input_tokens=100, output_tokens=50, cost_usd=0.20)

    def test_per_request_ceiling(self):
        from phantom.core.cost_controller import CostController
        cc = CostController(max_cost_usd=100.0, max_single_request_cost=0.50)
        with pytest.raises(CostLimitExceeded, match="ceiling"):
            cc.record_usage(cost_usd=1.00)


class TestGlobalAccessor:
    def test_get_global_alias(self):
        from phantom.core.cost_controller import (
            get_cost_controller,
            get_global_cost_controller,
        )
        assert get_global_cost_controller is get_cost_controller
