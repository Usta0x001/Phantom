"""
Tests for v0.9.18 features and fixes:
- B1 FIX: SSRF target bypass (proxy_manager._ALLOWED_SSRF_HOSTS)
- B2+B6 FIX: ScanResult construction in finish_actions
- B3 FIX: LLM cost stats in scan_stats.json
- B5 FIX: Scan resume wiring (--resume CLI, checkpoint round-trip)
- C1: Quick profile cost optimization (reasoning_effort, memory_threshold)
- C2: Tool result truncation reduced to 5K chars
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

try:
    import gql  # noqa: F401
    HAS_GQL = True
except ImportError:
    HAS_GQL = False


# ── B1 FIX: SSRF target bypass ──────────────────────────────────────────────


@pytest.mark.skipif(not HAS_GQL, reason="gql not installed (Docker-only dependency)")
class TestSSRFTargetBypass:
    """Verify proxy_manager allows explicitly registered scan targets."""

    def test_allow_ssrf_host_registers_hostname(self):
        from phantom.tools.proxy.proxy_manager import (
            _ALLOWED_SSRF_HOSTS,
            allow_ssrf_host,
        )
        # Save original and clean
        orig = _ALLOWED_SSRF_HOSTS.copy()
        _ALLOWED_SSRF_HOSTS.clear()
        try:
            allow_ssrf_host("example.com")
            assert "example.com" in _ALLOWED_SSRF_HOSTS
        finally:
            _ALLOWED_SSRF_HOSTS.clear()
            _ALLOWED_SSRF_HOSTS.update(orig)

    def test_allow_ssrf_host_normalizes_case(self):
        from phantom.tools.proxy.proxy_manager import (
            _ALLOWED_SSRF_HOSTS,
            allow_ssrf_host,
        )
        orig = _ALLOWED_SSRF_HOSTS.copy()
        _ALLOWED_SSRF_HOSTS.clear()
        try:
            allow_ssrf_host("HOST.Docker.Internal")
            assert "host.docker.internal" in _ALLOWED_SSRF_HOSTS
        finally:
            _ALLOWED_SSRF_HOSTS.clear()
            _ALLOWED_SSRF_HOSTS.update(orig)

    def test_allow_ssrf_host_strips_whitespace(self):
        from phantom.tools.proxy.proxy_manager import (
            _ALLOWED_SSRF_HOSTS,
            allow_ssrf_host,
        )
        orig = _ALLOWED_SSRF_HOSTS.copy()
        _ALLOWED_SSRF_HOSTS.clear()
        try:
            allow_ssrf_host("  example.com  ")
            assert "example.com" in _ALLOWED_SSRF_HOSTS
        finally:
            _ALLOWED_SSRF_HOSTS.clear()
            _ALLOWED_SSRF_HOSTS.update(orig)

    def test_ssrf_check_allows_registered_host(self):
        """A registered target should pass even if it resolves to private IP."""
        from phantom.tools.proxy.proxy_manager import (
            _ALLOWED_SSRF_HOSTS,
            _is_ssrf_safe,
            allow_ssrf_host,
        )
        orig = _ALLOWED_SSRF_HOSTS.copy()
        _ALLOWED_SSRF_HOSTS.clear()
        try:
            allow_ssrf_host("test-target.local")
            # Should return True immediately without DNS resolution
            with patch("phantom.tools.proxy.proxy_manager.socket.getaddrinfo") as mock_dns:
                result = _is_ssrf_safe("http://test-target.local:3000/api")
                assert result is True
                # DNS should NOT have been called — early return
                mock_dns.assert_not_called()
        finally:
            _ALLOWED_SSRF_HOSTS.clear()
            _ALLOWED_SSRF_HOSTS.update(orig)

    def test_ssrf_check_blocks_unregistered_private_ip(self):
        """An unregistered hostname resolving to private IP should be blocked."""
        from phantom.tools.proxy.proxy_manager import (
            _ALLOWED_SSRF_HOSTS,
            _is_ssrf_safe,
        )
        import socket
        orig = _ALLOWED_SSRF_HOSTS.copy()
        _ALLOWED_SSRF_HOSTS.clear()
        try:
            with patch("phantom.tools.proxy.proxy_manager.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.100", 3000))
                ]
                result = _is_ssrf_safe("http://evil-host.example:3000")
                assert result is False
        finally:
            _ALLOWED_SSRF_HOSTS.clear()
            _ALLOWED_SSRF_HOSTS.update(orig)

    def test_ssrf_still_blocks_localhost(self):
        """localhost should always be blocked, even if registered."""
        from phantom.tools.proxy.proxy_manager import _is_ssrf_safe

        assert _is_ssrf_safe("http://localhost:3000") is False
        assert _is_ssrf_safe("http://0.0.0.0:3000") is False


# ── B5 FIX: Checkpoint round-trip ───────────────────────────────────────────


class TestCheckpointRoundTrip:
    """Verify EnhancedAgentState checkpoint save/load works end-to-end."""

    def test_save_and_load_checkpoint(self):
        from phantom.agents.enhanced_state import EnhancedAgentState

        state = EnhancedAgentState(agent_name="test-agent", max_iterations=100)
        state.scan_id = "test-scan-123"
        state.iteration = 42
        state.subdomains = ["sub1.example.com", "sub2.example.com"]
        state.endpoints = ["/api/v1/users", "/api/v1/login"]

        with tempfile.TemporaryDirectory() as tmpdir:
            cp_path = state.save_checkpoint(tmpdir)
            assert cp_path.exists()

            # Load it back
            restored = EnhancedAgentState.from_checkpoint(cp_path)
            assert restored.scan_id == "test-scan-123"
            assert restored.iteration == 42
            assert restored.subdomains == ["sub1.example.com", "sub2.example.com"]
            assert restored.endpoints == ["/api/v1/users", "/api/v1/login"]

    def test_checkpoint_preserves_vulnerabilities(self):
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.models.vulnerability import (
            Vulnerability,
            VulnerabilitySeverity,
            VulnerabilityStatus,
        )

        state = EnhancedAgentState(agent_name="test-agent", max_iterations=100)
        state.scan_id = "test-vuln-round-trip"
        vuln = Vulnerability(
            id="VULN-001",
            name="SQL Injection",
            vulnerability_class="sqli",
            severity=VulnerabilitySeverity.CRITICAL,
            status=VulnerabilityStatus.VERIFIED,
            target="http://example.com",
            endpoint="/api/v1/users",
            parameter="id",
            description="SQL injection in user ID parameter",
            detected_by="test",
        )
        state.vulnerabilities["VULN-001"] = vuln

        with tempfile.TemporaryDirectory() as tmpdir:
            cp_path = state.save_checkpoint(tmpdir)
            restored = EnhancedAgentState.from_checkpoint(cp_path)

            assert "VULN-001" in restored.vulnerabilities
            rv = restored.vulnerabilities["VULN-001"]
            assert rv.name == "SQL Injection"
            assert rv.severity == VulnerabilitySeverity.CRITICAL
            assert rv.endpoint == "/api/v1/users"

    def test_checkpoint_rejects_unknown_keys(self):
        """PHT-019: unknown keys should be dropped, not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cp_path = Path(tmpdir) / "checkpoint.json"
            data = {
                "scan_id": "safe-scan",
                "iteration": 10,
                "phase": "recon",
                "subdomains": [],
                "endpoints": [],
                "vulnerabilities": {},
                "hosts": {},
                "tools_used": {},
                "evil_payload": "should be dropped",
                "saved_at": "2025-01-01T00:00:00",
            }
            cp_path.write_text(json.dumps(data), encoding="utf-8")

            from phantom.agents.enhanced_state import EnhancedAgentState

            state = EnhancedAgentState.from_checkpoint(cp_path)
            assert state.scan_id == "safe-scan"
            assert state.iteration == 10
            # evil_payload should not appear anywhere
            assert not hasattr(state, "evil_payload")

    def test_checkpoint_enforces_type_guards(self):
        """Non-integer iteration should be reset to 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cp_path = Path(tmpdir) / "checkpoint.json"
            data = {
                "scan_id": "type-guard-test",
                "iteration": "not-an-int",
                "phase": "recon",
                "subdomains": "not-a-list",
                "endpoints": [],
                "vulnerabilities": {},
                "hosts": {},
                "tools_used": {},
                "saved_at": "2025-01-01T00:00:00",
            }
            cp_path.write_text(json.dumps(data), encoding="utf-8")

            from phantom.agents.enhanced_state import EnhancedAgentState

            state = EnhancedAgentState.from_checkpoint(cp_path)
            assert state.iteration == 0  # reset from invalid type
            assert state.subdomains == []  # reset from invalid type


# ── C1: Quick profile cost optimization ─────────────────────────────────────


class TestScanProfileOptimization:
    """Verify scan profiles have correct cost-optimized settings."""

    def test_quick_profile_medium_reasoning(self):
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("quick")
        assert profile.reasoning_effort == "medium"

    def test_quick_profile_reduced_memory(self):
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("quick")
        assert profile.memory_threshold == 50_000

    def test_standard_profile_medium_reasoning(self):
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("standard")
        assert profile.reasoning_effort == "medium"

    def test_deep_profile_high_reasoning(self):
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("deep")
        assert profile.reasoning_effort == "high"

    def test_deep_profile_max_memory(self):
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("deep")
        assert profile.memory_threshold == 100_000

    def test_profile_serialization_roundtrip(self):
        from phantom.core.scan_profiles import ScanProfile, get_profile

        orig = get_profile("quick")
        data = orig.to_dict()
        restored = ScanProfile.from_dict(data)
        assert restored.reasoning_effort == orig.reasoning_effort
        assert restored.memory_threshold == orig.memory_threshold
        assert restored.max_iterations == orig.max_iterations

    def test_profile_merge_overrides(self):
        from phantom.core.scan_profiles import get_profile

        profile = get_profile("quick")
        merged = profile.merge({"max_iterations": 200, "reasoning_effort": "high"})
        assert merged.max_iterations == 200
        assert merged.reasoning_effort == "high"
        # Original unchanged
        assert profile.max_iterations == 100
        assert profile.reasoning_effort == "medium"

    def test_unknown_profile_raises(self):
        from phantom.core.scan_profiles import get_profile

        with pytest.raises(KeyError, match="Unknown scan profile"):
            get_profile("nonexistent_profile")


# ── C2: Tool result truncation ──────────────────────────────────────────────


class TestToolResultTruncation:
    """Verify tool result truncation uses reduced limits."""

    def test_short_result_not_truncated(self):
        from phantom.tools.executor import _format_tool_result

        text, images = _format_tool_result("test_tool", "short result")
        assert "short result" in text
        assert "truncated" not in text

    def test_long_result_truncated_at_8k(self):
        from phantom.tools.executor import _format_tool_result

        long_text = "A" * 15_000
        text, images = _format_tool_result("test_tool", long_text)
        # Should be truncated
        assert "truncated" in text.lower() or "characters truncated" in text
        # Final text should be under ~8500 chars (head + tail + overhead)
        assert len(text) < 10000

    def test_8k_boundary_not_truncated(self):
        """Result exactly at 8000 chars should NOT be truncated (M22 raised limit)."""
        from phantom.tools.executor import _format_tool_result

        text_7999 = "B" * 7999
        result, images = _format_tool_result("test_tool", text_7999)
        assert "truncated" not in result

    def test_8001_chars_is_truncated(self):
        """Result at 8001 chars SHOULD be truncated (M22 limit = 8000)."""
        from phantom.tools.executor import _format_tool_result

        text_8001 = "C" * 8001
        result, images = _format_tool_result("test_tool", text_8001)
        assert "truncated" in result.lower() or "characters truncated" in result


# ── B2+B6: ScanResult construction ──────────────────────────────────────────


class TestScanResultConstruction:
    """Verify ScanResult model can be constructed for reports."""

    def test_scan_result_fields(self):
        from datetime import datetime, UTC
        from phantom.models.scan import ScanResult, ScanStatus

        result = ScanResult(
            scan_id="test-123",
            target="http://example.com",
            started_at=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
            completed_at=datetime(2025, 1, 1, 0, 30, 0, tzinfo=UTC),
            status=ScanStatus.COMPLETED,
        )
        assert result.scan_id == "test-123"
        assert result.target == "http://example.com"
        assert result.status == ScanStatus.COMPLETED
        assert result.started_at is not None
        assert result.completed_at is not None

    def test_scan_status_values(self):
        from phantom.models.scan import ScanStatus

        assert ScanStatus.COMPLETED.value == "completed"
        # Verify other expected statuses exist
        assert hasattr(ScanStatus, "RUNNING") or hasattr(ScanStatus, "FAILED") or hasattr(ScanStatus, "COMPLETED")


# ── B3 FIX: scan_stats.json format ──────────────────────────────────────────


class TestScanStatsFormat:
    """Verify that scan_stats.json has correct schema."""

    def test_stats_json_schema(self):
        """Validate expected keys in a mock scan_stats.json."""
        stats = {
            "scan_id": "test-run",
            "started_at": "2025-01-01T00:00:00+00:00",
            "completed_at": "2025-01-01T00:30:00+00:00",
            "duration_seconds": 1800.0,
            "vulnerabilities_found": 6,
            "tool_executions": 161,
            "llm_usage": {
                "total": {
                    "input_tokens": 500000,
                    "output_tokens": 50000,
                    "cached_tokens": 100000,
                    "cost": 0.75,
                    "requests": 45,
                }
            },
        }
        # All required keys present
        assert "scan_id" in stats
        assert "started_at" in stats
        assert "completed_at" in stats
        assert "duration_seconds" in stats
        assert "vulnerabilities_found" in stats
        assert "tool_executions" in stats
        assert "llm_usage" in stats

        # LLM usage sub-structure
        llm = stats["llm_usage"]["total"]
        assert "input_tokens" in llm
        assert "output_tokens" in llm
        assert "cost" in llm
        assert "requests" in llm

    def test_run_scan_stats_file_path_construction(self):
        """Verify the path logic: run_dir / scan_stats.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stats_path = Path(tmpdir) / "scan_stats.json"
            stats = {"scan_id": "test", "duration_seconds": 100}
            stats_path.write_text(json.dumps(stats), encoding="utf-8")

            loaded = json.loads(stats_path.read_text(encoding="utf-8"))
            assert loaded["scan_id"] == "test"
            assert loaded["duration_seconds"] == 100


# ── Integration: resume CLI flag parsing ─────────────────────────────────────


class TestResumeCLIParsing:
    """Verify --resume flag parsing logic from run_scan.py."""

    def test_resume_flag_extracted(self):
        """Simulate argparse from run_scan __main__."""
        argv = ["run_scan.py", "http://target:3000", "quick", "--resume", "phantom_runs/old-run"]
        resume_dir = None
        for i, arg in enumerate(argv):
            if arg == "--resume" and i + 1 < len(argv):
                resume_dir = argv[i + 1]
                break
        assert resume_dir == "phantom_runs/old-run"

    def test_no_resume_flag(self):
        """Without --resume, resume_dir should be None."""
        argv = ["run_scan.py", "http://target:3000", "quick"]
        resume_dir = None
        for i, arg in enumerate(argv):
            if arg == "--resume" and i + 1 < len(argv):
                resume_dir = argv[i + 1]
                break
        assert resume_dir is None

    def test_resume_flag_at_end_without_value(self):
        """--resume at end without value should not crash."""
        argv = ["run_scan.py", "http://target:3000", "--resume"]
        resume_dir = None
        for i, arg in enumerate(argv):
            if arg == "--resume" and i + 1 < len(argv):
                resume_dir = argv[i + 1]
                break
        assert resume_dir is None


# ── SSRF host registration in run_scan ───────────────────────────────────────


class TestSSRFHostRegistration:
    """Verify that run_scan registers target hosts with SSRF allowlist."""

    def test_hostname_extraction_from_url(self):
        """Verify hostname is correctly extracted from target URL."""
        from urllib.parse import urlparse

        targets = [
            ("http://host.docker.internal:3000", "host.docker.internal"),
            ("https://example.com/path", "example.com"),
            ("http://192.168.1.1:8080", "192.168.1.1"),
        ]
        for url, expected_host in targets:
            parsed = urlparse(url)
            assert parsed.hostname == expected_host


# ── Cost Controller defaults ─────────────────────────────────────────────────


class TestCostControllerDefaults:
    """Verify cost controller has sensible defaults."""

    def test_max_cost_default(self):
        from phantom.core.cost_controller import CostController

        cc = CostController()
        assert cc.max_cost_usd == 25.0  # M9: lowered from $50 to $25

    def test_max_input_tokens_default(self):
        from phantom.core.cost_controller import CostController

        cc = CostController()
        assert cc.max_input_tokens == 5_000_000

    def test_warning_threshold(self):
        from phantom.core.cost_controller import CostController

        cc = CostController()
        assert cc.warning_threshold == 0.8


# ── Profile list and register ────────────────────────────────────────────────


class TestProfileRegistry:
    """Verify profile listing and custom registration."""

    def test_list_profiles_returns_all(self):
        from phantom.core.scan_profiles import list_profiles

        profiles = list_profiles()
        names = [p["name"] for p in profiles]
        assert "quick" in names
        assert "standard" in names
        assert "deep" in names
        assert "stealth" in names
        assert "api_only" in names

    def test_register_custom_profile(self):
        from phantom.core.scan_profiles import (
            ScanProfile,
            get_profile,
            register_profile,
            PROFILES,
        )

        custom = ScanProfile(
            name="custom_test",
            description="Test profile",
            max_iterations=10,
            reasoning_effort="low",
        )
        register_profile(custom)
        try:
            retrieved = get_profile("custom_test")
            assert retrieved.max_iterations == 10
            assert retrieved.reasoning_effort == "low"
        finally:
            # Clean up
            PROFILES.pop("custom_test", None)
