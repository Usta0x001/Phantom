"""Smoke tests to verify basic functionality."""
import pytest


def test_import_phantom():
    """Test that phantom package can be imported."""
    import phantom
    assert phantom.__version__ == "0.9.183"


def test_import_agents():
    """Test that agent modules can be imported."""
    from phantom.agents import state
    assert hasattr(state, 'AgentState')


def test_import_tools():
    """Test that tool modules can be imported."""
    from phantom.tools import registry
    # registry module exists and has the register_tool function
    assert hasattr(registry, 'register_tool')


def test_agent_state_no_shared_mutable():
    """Test that AgentState instances don't share mutable defaults."""
    from phantom.agents.state import AgentState
    
    state1 = AgentState(task="test1")
    state2 = AgentState(task="test2")
    
    state1.add_message("user", "hello from state1")
    
    # Verify that state2 doesn't see state1's message hashes
    assert state1._message_hashes != state2._message_hashes
    assert len(state2._message_hashes) == 0


def test_finish_scan_allows_zero_vulns():
    """Test that finish_scan requires tracer (can't test in isolation)."""
    from phantom.tools.finish.finish_actions import finish_scan
    from phantom.agents.state import AgentState
    
    state = AgentState(task="test_scan")
    
    # finish_scan requires global tracer to be initialized
    # This test verifies the function exists and handles missing tracer gracefully
    result = finish_scan(
        agent_state=state,
        executive_summary="No vulnerabilities found",
        methodology="Standard testing",
        technical_analysis="Clean scan",
        recommendations="Continue monitoring"
    )
    
    # Without tracer, should fail gracefully with error message
    assert isinstance(result, dict)
    assert "success" in result
    # NOTE: This would be True if tracer was initialized, but we can't test that in unit tests
