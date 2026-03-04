"""Adversarial cost exhaustion test."""

import pytest

from phantom.core.cost_controller import CostController
from phantom.core.exceptions import CostLimitExceeded


class TestCostExhaustion:
    """Token flooding must trigger CostLimitExceeded within 1 iteration."""

    def test_cost_limit_fires_on_budget_exceed(self):
        cc = CostController(max_cost_usd=1.00)
        # Simulate a massive single call
        with pytest.raises(CostLimitExceeded):
            cc.record_usage(input_tokens=500_000, output_tokens=100_000, cost_usd=5.00)

    def test_cost_limit_fires_on_gradual_exceed(self):
        cc = CostController(max_cost_usd=0.10)
        cc.record_usage(cost_usd=0.05)
        cc.record_usage(cost_usd=0.04)
        with pytest.raises(CostLimitExceeded):
            cc.record_usage(cost_usd=0.05)  # Total: 0.14 > 0.10

    def test_per_request_ceiling_blocks_token_flood(self):
        cc = CostController(max_cost_usd=100.0, max_single_request_cost=1.0)
        with pytest.raises(CostLimitExceeded, match="ceiling"):
            cc.record_usage(cost_usd=2.0)  # Single request exceeds ceiling

    def test_compression_flood_limited(self):
        cc = CostController(max_cost_usd=100.0, max_compression_calls=5)
        for _ in range(5):
            cc.record_usage(cost_usd=0.01, is_compression=True)
        with pytest.raises(CostLimitExceeded, match="[Cc]ompression"):
            cc.record_usage(cost_usd=0.01, is_compression=True)
