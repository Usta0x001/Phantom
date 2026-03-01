"""
P0 Fix Verification Tests
Tests for AUTO-001, ARCH-003, SEC-004, SEC-005
Run: python -m pytest tests/test_p0_fixes.py -v
"""
import tempfile
from pathlib import Path


def test_sec004_hmac_key_not_default():
    """SEC-004: HMAC key must not be the hardcoded default."""
    from phantom.core.audit_logger import AuditLogger

    p = Path(tempfile.mkdtemp()) / "test_sec004.jsonl"
    logger = AuditLogger(p)
    assert logger._hmac_key != b"phantom-audit-default-key", "Still using hardcoded default key!"
    assert len(logger._hmac_key) >= 32, "Key too short"
    print("SEC-004 PASS: Unique HMAC key generated")


def test_sec004_hmac_key_persisted():
    """SEC-004: HMAC key must persist across logger instances."""
    from phantom.core.audit_logger import AuditLogger

    p = Path(tempfile.mkdtemp()) / "test_sec004_persist.jsonl"
    a = AuditLogger(p)
    b = AuditLogger(p)
    assert a._hmac_key == b._hmac_key, "Key not persisted between instances!"
    print("SEC-004 PASS: Key persistence verified")


def test_auto001_blocks_at_iteration_zero():
    """AUTO-001: finish_scan must be blocked at iteration 0."""
    from phantom.agents.state import AgentState
    from phantom.tools.finish.finish_actions import finish_scan

    state = AgentState(iteration=0, actions_taken=[])
    result = finish_scan("summary", "method", "analysis", "recs", agent_state=state)
    assert result["success"] is False
    assert "AUTO-001" in result.get("blocked_by", "")
    print("AUTO-001 PASS: Blocked at iteration 0")


def test_auto001_blocks_below_minimum_iterations():
    """AUTO-001: finish_scan must be blocked below 5 iterations."""
    from phantom.agents.state import AgentState
    from phantom.tools.finish.finish_actions import finish_scan

    state = AgentState(iteration=3, actions_taken=[{}, {}, {}])
    result = finish_scan("summary", "method", "analysis", "recs", agent_state=state)
    assert result["success"] is False
    assert "AUTO-001" in result.get("blocked_by", "")
    print("AUTO-001 PASS: Blocked at iteration 3")


def test_auto001_blocks_below_minimum_tools():
    """AUTO-001: finish_scan must be blocked with fewer than 3 tool calls."""
    from phantom.agents.state import AgentState
    from phantom.tools.finish.finish_actions import finish_scan

    state = AgentState(iteration=6, actions_taken=[{}, {}])
    result = finish_scan("summary", "method", "analysis", "recs", agent_state=state)
    assert result["success"] is False
    assert "AUTO-001" in result.get("blocked_by", "")
    print("AUTO-001 PASS: Blocked with only 2 tool calls")


def test_auto001_allows_sufficient_work():
    """AUTO-001: finish_scan must pass when minimum work is done."""
    from phantom.agents.state import AgentState
    from phantom.tools.finish.finish_actions import finish_scan

    state = AgentState(iteration=10, actions_taken=[{}, {}, {}, {}, {}])
    result = finish_scan("summary", "method", "analysis", "recs", agent_state=state)
    # Should not be blocked by AUTO-001 (may fail for other reasons like no tracer)
    assert "AUTO-001" not in result.get("blocked_by", "")
    print("AUTO-001 PASS: Allowed at iteration 10 with 5 tools")


def test_arch003_unverified_findings_field():
    """ARCH-003: AgentState must have _unverified_findings field."""
    from phantom.agents.state import AgentState

    state = AgentState()
    assert hasattr(state, "unverified_findings")
    assert isinstance(state.unverified_findings, list)
    state.unverified_findings.append({"tool": "nuclei", "severity": "critical", "name": "test", "url": "http://x"})
    assert len(state.unverified_findings) == 1
    print("ARCH-003 PASS: _unverified_findings field works")


def test_sec005_dockerfile_no_strix():
    """SEC-005: Dockerfile.sandbox must not reference strix."""
    dockerfile_path = Path(__file__).parent.parent / "containers" / "Dockerfile.sandbox"
    if dockerfile_path.exists():
        content = dockerfile_path.read_text()
        assert "usestrix" not in content, "Dockerfile still references usestrix!"
        assert "strix-sandbox" not in content.lower() or "phantom" in content.lower()
        assert "ghcr.io/usta0x001/phantom-sandbox" in content
        print("SEC-005 PASS: Dockerfile uses phantom-sandbox image")
    else:
        print(f"SEC-005 SKIP: {dockerfile_path} not found")


if __name__ == "__main__":
    test_sec004_hmac_key_not_default()
    test_sec004_hmac_key_persisted()
    test_auto001_blocks_at_iteration_zero()
    test_auto001_blocks_below_minimum_iterations()
    test_auto001_blocks_below_minimum_tools()
    test_auto001_allows_sufficient_work()
    test_arch003_unverified_findings_field()
    test_sec005_dockerfile_no_strix()
    print("\n=== ALL P0 VERIFICATION TESTS PASSED ===")
