"""Smoke tests to verify basic functionality."""
import pytest


def test_import_phantom():
    """Test that phantom package can be imported."""
    import phantom
    assert phantom.__version__ == "0.9.130"


def test_import_agents():
    """Test that agent modules can be imported."""
    from phantom.agents import state
    assert hasattr(state, 'AgentState')


def test_import_tools():
    """Test that tool modules can be imported."""
    from phantom.tools import registry
    assert hasattr(registry, 'ToolRegistry')


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
    """Test that finish_scan allows scans with zero vulnerabilities."""
    from phantom.tools.finish.finish_actions import finish_scan
    from phantom.agents.state import AgentState
    
    state = AgentState(task="test_scan")
    
    # This should not crash or return success=False
    result = finish_scan(
        state=state,
        executive_summary="No vulnerabilities found",
        methodology="Standard testing",
        technical_analysis="Clean scan",
        recommendations="Continue monitoring"
    )
    
    assert result["success"] is True
    assert result["scan_completed"] is True
    assert result["vulnerabilities_found"] == 0
