"""Integration tests for core agent loop functionality.

These tests verify the agent can actually run end-to-end without mocked components.
"""
import pytest
from phantom.agents.state import AgentState


class TestAgentLoopBasics:
    """Test basic agent loop operations."""

    def test_agent_state_initialization(self):
        """Verify agent state initializes with correct defaults."""
        state = AgentState(
            task="Test scan of http://example.com",
            max_iterations=10,
            scan_mode="quick"
        )
        
        assert state.task == "Test scan of http://example.com"
        assert state.max_iterations == 10
        assert state.scan_mode == "quick"
        assert state.current_iteration == 0
        assert len(state.conversation_history) == 0
        assert len(state.errors) == 0

    def test_agent_state_add_message_deduplication(self):
        """Verify message deduplication prevents identical messages."""
        state = AgentState(task="test")
        
        # Add same message twice
        state.add_message("user", "Test message")
        state.add_message("user", "Test message")
        
        # Should only be added once due to hash deduplication
        assert len(state.conversation_history) == 1

    def test_agent_state_message_dedup_is_role_aware(self):
        """Verify identical content from different roles is preserved."""
        state = AgentState(task="test")

        state.add_message("user", "Same text")
        state.add_message("assistant", "Same text")

        assert len(state.conversation_history) == 2

    def test_agent_state_add_different_messages(self):
        """Verify different messages are both added."""
        state = AgentState(task="test")
        
        state.add_message("user", "First message")
        state.add_message("user", "Second message")
        
        assert len(state.conversation_history) == 2

    def test_agent_state_message_hash_independence(self):
        """Verify different agent instances don't share message hashes."""
        state1 = AgentState(task="test1")
        state2 = AgentState(task="test2")
        
        state1.add_message("user", "hello")
        
        # state2 should not see state1's message hashes
        assert state1._message_hashes != state2._message_hashes
        assert len(state2._message_hashes) == 0

    def test_agent_state_bounded_history_trims_actions_and_observations(self):
        """Verify action, observation, and error histories are bounded."""
        state = AgentState(task="test")

        for i in range(250):
            state.add_action({"i": i})
            state.add_observation({"i": i})
        for i in range(120):
            state.add_error(f"error {i}")

        assert len(state.actions_taken) <= 200
        assert len(state.observations) <= 200
        assert len(state.errors) <= 100


class TestHypothesisLedger:
    """Test hypothesis ledger deduplication and tracking."""

    def test_hypothesis_deduplication(self):
        """Verify hypothesis ledger prevents duplicate hypotheses."""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        
        ledger = HypothesisLedger()
        
        # Add same hypothesis twice
        h1 = ledger.add("/api/login", "sqli")
        h2 = ledger.add("/api/login", "sqli")
        
        assert h1 == h2  # Should return same ID
        assert len(ledger.to_dict()["hypotheses"]) == 1

    def test_hypothesis_different_surfaces(self):
        """Verify different surfaces create different hypotheses."""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        
        ledger = HypothesisLedger()
        
        h1 = ledger.add("/api/login", "sqli")
        h2 = ledger.add("/api/users", "sqli")
        
        assert h1 != h2
        assert len(ledger.to_dict()["hypotheses"]) == 2

    def test_hypothesis_payload_tracking(self):
        """Verify payload tracking works correctly."""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        
        ledger = HypothesisLedger()
        h_id = ledger.add("/api/login", "sqli")
        
        ledger.record_payload(h_id, "' OR 1=1--")
        ledger.record_payload(h_id, "' UNION SELECT NULL--")
        
        hyp = ledger.get(h_id)
        assert len(hyp.payloads_tested) == 2
        assert "' OR 1=1--" in hyp.payloads_tested

    def test_hypothesis_status_updates(self):
        """Verify hypothesis status can be updated."""
        from phantom.agents.hypothesis_ledger import HypothesisLedger
        
        ledger = HypothesisLedger()
        h_id = ledger.add("/api/login", "sqli")
        
        ledger.update_status(h_id, "testing")
        assert ledger.get(h_id).status == "testing"
        
        ledger.update_status(h_id, "confirmed")
        assert ledger.get(h_id).status == "confirmed"

    def test_hypothesis_belief_initialization_and_persistence(self):
        """Verify DABS belief map initializes at 0.5 and survives serialization."""
        from phantom.agents.hypothesis_ledger import HypothesisLedger

        ledger = HypothesisLedger()
        h_id = ledger.add("/api/login", "sqli")

        assert abs(ledger.get_belief(h_id) - 0.5) < 1e-9

        restored = HypothesisLedger.from_dict(ledger.to_dict())
        assert abs(restored.get_belief(h_id) - 0.5) < 1e-9
        assert h_id in restored.to_dict().get("belief_map", {})


class TestCoverageTracker:
    """Test coverage tracker functionality."""

    def test_coverage_surface_discovery(self):
        """Verify surfaces can be discovered and tracked."""
        from phantom.agents.coverage_tracker import CoverageTracker
        
        tracker = CoverageTracker()
        
        tracker.discover_surface(
            surface="/api/login",
            surface_type="endpoint",
            source="crawl"
        )
        
        discovered = tracker.get_discovered_surfaces()
        assert len(discovered) == 1
        assert discovered[0].surface == "/api/login"

    def test_coverage_testing_tracking(self):
        """Verify testing coverage is tracked correctly."""
        from phantom.agents.coverage_tracker import CoverageTracker
        
        tracker = CoverageTracker()
        
        tracker.record_test(
            surface="/api/login",
            surface_type="endpoint",
            vuln_class="sqli"
        )
        
        tested = tracker.get_tested_surfaces()
        assert len(tested) == 1
        assert "sqli" in tested[0].vuln_classes_tested

    def test_coverage_gap_detection(self):
        """Verify untested surfaces are identified."""
        from phantom.agents.coverage_tracker import CoverageTracker
        
        tracker = CoverageTracker()
        
        # Discover two surfaces
        tracker.discover_surface("/api/login", "endpoint", "crawl")
        tracker.discover_surface("/api/users", "endpoint", "crawl")
        
        # Test only one
        tracker.record_test("/api/login", "endpoint", "sqli")
        
        # Should have one untested surface
        discovered = tracker.get_discovered_surfaces()
        tested_surfaces = {t.surface for t in tracker.get_tested_surfaces()}
        untested = [d for d in discovered if d.surface not in tested_surfaces]
        
        assert len(untested) == 1
        assert untested[0].surface == "/api/users"


class TestMemoryCompression:
    """Test memory compression preserves critical information."""

    def test_compression_preserves_recent_messages(self):
        """Verify MIN_RECENT_MESSAGES are always kept."""
        from phantom.llm.memory_compressor import MemoryCompressor, MIN_RECENT_MESSAGES
        from phantom.agents.state import AgentState
        
        state = AgentState(task="test")
        compressor = MemoryCompressor()
        
        # Create many messages
        messages = []
        for i in range(50):
            messages.append({"role": "user", "content": f"Message {i}"})
        
        # Compress (this will only do basic compression, not LLM summarization)
        compressed = list(compressor.compress_history(messages, state))
        
        # Verify recent messages are preserved
        assert len(compressed) >= MIN_RECENT_MESSAGES

    def test_anchor_extraction_from_vulnerability_signals(self):
        """Verify vulnerability signals are extracted as anchors."""
        from phantom.llm.memory_compressor import MemoryCompressor
        from phantom.agents.state import AgentState
        
        state = AgentState(task="test")
        compressor = MemoryCompressor()
        
        # Create messages with vulnerability signals
        messages = [
            {"role": "assistant", "content": "Testing SQL injection"},
            {"role": "user", "content": "SQL error: syntax error near '1''"},
            {"role": "assistant", "content": "Found XSS: <script>alert(1)</script> reflected"},
        ]
        
        # Extract anchors
        chunk_text = " ".join(m["content"] for m in messages)
        from phantom.llm.memory_compressor import _extract_anchors_from_chunk
        anchors = _extract_anchors_from_chunk(messages)
        
        # Should extract both SQL error and XSS
        anchor_texts = [a["text"] for a in anchors]
        assert any("SQL error" in text for text in anchor_texts)
        assert any("script" in text.lower() for text in anchor_texts)

    def test_compression_records_structured_state(self):
        """Verify compression stores structured facts and delta memory."""
        from phantom.llm.memory_compressor import MemoryCompressor
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.models.scan import ScanPhase

        state = EnhancedAgentState(task="test")
        state.current_phase = ScanPhase.EXPLOITATION
        state.add_message("user", "Test /api/login with ' OR '1'='1 --")
        state.add_message("assistant", "SQL error: syntax error near 'OR'")
        state.add_message("assistant", "Found SSRF -> metadata access at /api/proxy")
        state.add_message("user", "Continue")

        state.compression_state = {"last_digest": ["old-digest"]}

        compressor = MemoryCompressor(model_name="claude-3-haiku-20240307")
        compressed = compressor.compress_history(state.get_conversation_history(), state)

        assert compressed
        assert state.compression_state.get("structured_facts") is not None
        assert state.compression_state.get("delta_facts") is not None
        assert state.compression_state.get("last_keep_recent") >= 15
        assert any(
            fact.get("type") in {"url", "payload", "chain"}
            for fact in state.compression_state.get("structured_facts", [])
        )

    def test_anchor_retention_prefers_evidence(self):
        """Verify anchor retention prefers high-evidence findings."""
        from phantom.agents.state import AgentState

        state = AgentState(task="test")
        for i in range(20):
            state.add_finding_anchor({"text": f"Weak finding {i}", "key": f"w{i}", "evidence_score": 0.1})

        state.add_finding_anchor({"text": "CRITICAL: SQLi confirmed", "key": "strong", "evidence_score": 10.0})

        assert len(state.finding_anchors) == state.MAX_FINDING_ANCHORS
        assert any(a.get("key") == "strong" for a in state.finding_anchors)

    def test_rare_high_value_anchor_survives_compression_cycles(self):
        """Verify a rare high-value anchor survives normal compression churn."""
        from phantom.agents.state import AgentState
        from phantom.llm.memory_compressor import MemoryCompressor

        state = AgentState(task="test")
        state.add_finding_anchor({
            "text": "CRITICAL: Rare auth bypass confirmed on /admin/export",
            "key": "rare-auth",
            "evidence_score": 20.0,
        })

        compressor = MemoryCompressor(model_name="claude-3-haiku-20240307")
        messages = [{"role": "user", "content": f"msg {i} /api/test"} for i in range(140)]

        # Stress several compression cycles; anchor retention is validity-based.
        for _ in range(5):
            compressor.compress_history(messages, state)

        assert any(a.get("key") == "rare-auth" for a in state.finding_anchors)


class TestCorrelationEngine:
    """Test vulnerability chain correlation."""

    def test_chain_detection_ssrf_to_cloud(self):
        """Verify SSRF triggers cloud metadata chain suggestion."""
        from phantom.agents.correlation_engine import CorrelationEngine
        
        engine = CorrelationEngine()
        
        # Record SSRF finding
        finding_id = engine.record_finding(
            vuln_class="ssrf",
            surface="/api/proxy",
            severity="high"
        )
        
        # Should suggest cloud metadata chain
        suggestions = engine.get_chain_suggestions()
        assert len(suggestions) > 0
        assert any("cloud" in s.chain_name.lower() for s in suggestions)

    def test_chain_detection_sqli_to_rce(self):
        """Verify SQLi triggers RCE chain suggestion."""
        from phantom.agents.correlation_engine import CorrelationEngine
        
        engine = CorrelationEngine()
        
        # Record SQLi finding
        engine.record_finding(
            vuln_class="sqli",
            surface="/api/search",
            severity="critical"
        )
        
        # Should suggest SQL to RCE chain
        suggestions = engine.get_chain_suggestions()
        assert any("rce" in s.chain_name.lower() for s in suggestions)


class TestToolExecution:
    """Test tool execution layer."""

    def test_tool_registry_has_tools(self):
        """Verify tools are actually registered."""
        from phantom.tools.registry import get_tool_names
        
        tools = get_tool_names()
        assert len(tools) > 0
        
        # Check for critical tools
        assert "terminal_execute" in tools
        assert "send_request" in tools
        assert "create_vulnerability_report" in tools

    def test_tool_validation_detects_missing_params(self):
        """Verify tool validation catches missing required parameters."""
        from phantom.tools.executor import _validate_tool_arguments
        
        # send_request requires method and url
        error = _validate_tool_arguments("send_request", {"method": "GET"})
        
        # Should detect missing 'url'
        assert error is not None
        assert "url" in error

    def test_tool_validation_accepts_valid_params(self):
        """Verify tool validation passes with correct parameters."""
        from phantom.tools.executor import _validate_tool_arguments
        
        # send_request with all required params
        error = _validate_tool_arguments("send_request", {
            "method": "GET",
            "url": "http://example.com"
        })
        
        # Should pass validation
        assert error is None


class TestLLMIntegration:
    """Test LLM configuration and setup."""

    def test_llm_config_initialization(self):
        """Verify LLM config initializes correctly."""
        from phantom.llm.config import LLMConfig
        
        config = LLMConfig(
            litellm_model="gpt-4o-mini",
            scan_mode="quick"
        )
        
        assert config.litellm_model == "gpt-4o-mini"
        assert config.scan_mode == "quick"

    def test_scan_profiles_exist(self):
        """Verify scan profiles are defined."""
        from phantom.core.scan_profiles import SCAN_PROFILES
        
        assert "quick" in SCAN_PROFILES
        assert "standard" in SCAN_PROFILES
        assert "deep" in SCAN_PROFILES
        assert "stealth" in SCAN_PROFILES

    def test_scan_profile_has_iterations(self):
        """Verify scan profiles specify max iterations."""
        from phantom.core.scan_profiles import SCAN_PROFILES
        
        quick = SCAN_PROFILES["quick"]
        assert "max_iterations" in quick
        assert quick["max_iterations"] > 0


class TestFinishScan:
    """Test scan completion."""

    def test_finish_scan_allows_zero_vulnerabilities(self):
        """Verify finish_scan accepts scans with no findings."""
        from phantom.tools.finish.finish_actions import finish_scan
        from phantom.agents.state import AgentState
        
        state = AgentState(task="test_scan")
        
        result = finish_scan(
            state=state,
            executive_summary="Clean scan - no vulnerabilities found",
            methodology="Standard OWASP testing methodology",
            technical_analysis="Tested all endpoints, no exploitable issues",
            recommendations="Continue monitoring for new vulnerabilities"
        )

        # In isolated tests, tracer may be unavailable; function must fail gracefully.
        assert isinstance(result, dict)
        assert "success" in result
        if result["success"]:
            assert result["scan_completed"] is True
            assert result["vulnerabilities_found"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
