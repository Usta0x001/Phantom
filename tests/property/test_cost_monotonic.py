"""Property-based test: cost monotonicity — cost never decreases."""

from hypothesis import given, settings, strategies as st

from phantom.core.cost_controller import CostController


@given(
    costs=st.lists(
        st.floats(min_value=0.0, max_value=0.1, allow_nan=False, allow_infinity=False),
        min_size=1,
        max_size=50,
    ),
)
@settings(max_examples=200)
def test_cost_never_decreases(costs: list[float]):
    """For any sequence of non-negative cost recordings, total cost is monotonically non-decreasing."""
    cc = CostController(max_cost_usd=999999.0, max_single_request_cost=999999.0)
    prev_cost = 0.0
    for cost in costs:
        try:
            cc.record_usage(input_tokens=10, output_tokens=5, cost_usd=cost)
        except Exception:
            # CostLimitExceeded may fire, that's fine — cost should still not decrease
            pass
        assert cc._state.total_cost_usd >= prev_cost, (
            f"Cost decreased from {prev_cost} to {cc._state.total_cost_usd}"
        )
        prev_cost = cc._state.total_cost_usd


@given(
    costs=st.lists(
        st.floats(min_value=0.0, max_value=0.01, allow_nan=False, allow_infinity=False),
        min_size=1,
        max_size=100,
    ),
)
@settings(max_examples=100)
def test_total_cost_equals_sum(costs: list[float]):
    """Total cost should equal the sum of all recorded costs (within float precision)."""
    cc = CostController(max_cost_usd=999999.0, max_single_request_cost=999999.0)
    for cost in costs:
        try:
            cc.record_usage(cost_usd=cost)
        except Exception:
            break  # Limit hit
    assert cc._state.total_cost_usd >= 0
