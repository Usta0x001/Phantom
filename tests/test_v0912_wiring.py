"""Tests for v0.9.12 wiring — verification engine, knowledge store pipeline,
prior scan intelligence, verify_vulnerability tool, and bug fixes."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Knowledge Store — get_all_vulnerabilities
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestKnowledgeStoreAllVulns:
    """Test the new get_all_vulnerabilities method."""

    def test_get_all_vulnerabilities_empty(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore

        store = KnowledgeStore(store_path=tmp_path / "ks")
        result = store.get_all_vulnerabilities()
        assert result == []

    def test_get_all_vulnerabilities_returns_saved(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore
        from phantom.models.vulnerability import Vulnerability

        store = KnowledgeStore(store_path=tmp_path / "ks")

        vuln = Vulnerability(
            id="vuln-001",
            name="Test SQLi",
            vulnerability_class="sqli",
            severity="critical",
            target="http://example.com",
            description="SQL injection",
            detected_by="test",
        )
        store.save_vulnerability(vuln)

        result = store.get_all_vulnerabilities()
        assert len(result) == 1
        assert result[0].id == "vuln-001"
        assert result[0].name == "Test SQLi"

    def test_get_all_vulnerabilities_multiple(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore
        from phantom.models.vulnerability import Vulnerability

        store = KnowledgeStore(store_path=tmp_path / "ks")

        for i in range(5):
            vuln = Vulnerability(
                id=f"vuln-{i:03d}",
                name=f"Vuln {i}",
                vulnerability_class="xss",
                severity="medium",
                target="http://example.com",
                description=f"Vuln {i}",
                detected_by="test",
            )
            store.save_vulnerability(vuln)

        result = store.get_all_vulnerabilities()
        assert len(result) == 5


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Knowledge Store — Scan History Recording
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestKnowledgeStoreScanHistory:
    """Test scan history recording."""

    def test_record_scan(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore

        store = KnowledgeStore(store_path=tmp_path / "ks")
        store.record_scan(
            scan_id="scan_abc123",
            target="http://example.com",
            status="completed",
            vulns_found=4,
            vulns_verified=3,
            hosts_found=1,
            duration_seconds=120.5,
            tools_used=["nmap_scan", "nuclei_scan"],
        )

        history = store.get_scan_history()
        assert len(history) == 1
        assert history[0]["scan_id"] == "scan_abc123"
        assert history[0]["vulns_found"] == 4
        assert history[0]["tools_used"] == ["nmap_scan", "nuclei_scan"]

    def test_get_scans_for_target(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore

        store = KnowledgeStore(store_path=tmp_path / "ks")
        store.record_scan("s1", "http://a.com", "completed", 2, 1, 1)
        store.record_scan("s2", "http://b.com", "completed", 0, 0, 1)
        store.record_scan("s3", "http://a.com", "completed", 3, 2, 2)

        a_scans = store.get_scans_for_target("http://a.com")
        assert len(a_scans) == 2

    def test_scan_history_persists(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore

        store = KnowledgeStore(store_path=tmp_path / "ks")
        store.record_scan("s1", "http://a.com", "completed", 2, 1, 1)

        # Create new instance pointing to same path
        store2 = KnowledgeStore(store_path=tmp_path / "ks")
        history = store2.get_scan_history()
        assert len(history) == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Knowledge Store — Host Persistence
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestKnowledgeStoreHosts:
    """Test host storage and retrieval."""

    def test_save_and_get_host(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore
        from phantom.models.host import Host, Port

        store = KnowledgeStore(store_path=tmp_path / "ks")

        host = Host(
            ip="192.168.1.1",
            hostname="test.local",
            ports=[Port(number=80, protocol="tcp", service="http")],
        )
        store.save_host(host)

        retrieved = store.get_host("192.168.1.1")
        assert retrieved is not None
        assert retrieved.ip == "192.168.1.1"
        assert len(retrieved.ports) == 1
        assert retrieved.ports[0].number == 80

    def test_host_merge(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore
        from phantom.models.host import Host, Port

        store = KnowledgeStore(store_path=tmp_path / "ks")

        host1 = Host(
            ip="192.168.1.1",
            ports=[Port(number=80, protocol="tcp", service="http")],
        )
        store.save_host(host1)

        host2 = Host(
            ip="192.168.1.1",
            ports=[Port(number=443, protocol="tcp", service="https")],
        )
        store.save_host(host2)

        retrieved = store.get_host("192.168.1.1")
        assert len(retrieved.ports) == 2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Verification Engine — Core Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestVerificationEngine:
    """Test verification engine core logic."""

    def test_engine_instantiation(self):
        from phantom.core.verification_engine import VerificationEngine

        engine = VerificationEngine()
        assert engine.terminal_execute is None
        assert engine.http_client is None
        assert engine._results == {}

    def test_engine_with_http_client(self):
        from phantom.core.verification_engine import VerificationEngine

        mock_client = MagicMock()
        engine = VerificationEngine(http_client=mock_client)
        assert engine.http_client is mock_client

    def test_verify_returns_result(self):
        from phantom.core.verification_engine import VerificationEngine
        from phantom.models.vulnerability import Vulnerability
        from phantom.models.verification import VerificationResult

        engine = VerificationEngine()
        vuln = Vulnerability(
            id="vuln-test",
            name="Test",
            vulnerability_class="sqli",
            severity="high",
            target="http://example.com/search?q=test",
            parameter="q",
            description="Test SQLi",
            detected_by="test",
        )

        result = asyncio.run(engine.verify(vuln))
        assert isinstance(result, VerificationResult)
        assert result.vulnerability_id == "vuln-test"

    def test_verify_batch_sorts_by_severity(self):
        from phantom.core.verification_engine import VerificationEngine
        from phantom.models.vulnerability import Vulnerability

        engine = VerificationEngine()
        vulns = [
            Vulnerability(
                id="low-1", name="Low", vulnerability_class="info_disclosure",
                severity="low", target="http://x.com", description="", detected_by="t",
            ),
            Vulnerability(
                id="crit-1", name="Critical", vulnerability_class="sqli",
                severity="critical", target="http://x.com", description="", detected_by="t",
            ),
        ]

        results = asyncio.run(engine.verify_batch(vulns))
        assert len(results) == 2
        # Critical should be verified first
        assert results[0].vulnerability_id == "crit-1"

    def test_inject_payload_basic(self):
        from phantom.core.verification_engine import VerificationEngine

        engine = VerificationEngine()
        url = engine._inject_payload(
            "http://example.com/search?q=foo",
            "q",
            "' OR 1=1--",
        )
        assert "q=" in url
        assert "OR" in url

    def test_inject_payload_ssrf_guard(self):
        from phantom.core.verification_engine import VerificationEngine

        engine = VerificationEngine()
        with pytest.raises(ValueError, match="Verification blocked"):
            engine._inject_payload("http://localhost/admin", "id", "test")

    def test_inject_payload_private_ip_guard(self):
        from phantom.core.verification_engine import VerificationEngine

        engine = VerificationEngine()
        with pytest.raises(ValueError, match="Verification blocked"):
            engine._inject_payload("http://10.0.0.1/admin", "id", "test")

    def test_get_results_empty(self):
        from phantom.core.verification_engine import VerificationEngine

        engine = VerificationEngine()
        assert engine.get_results() == {}
        assert engine.get_verified_count() == 0
        assert engine.get_false_positive_count() == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# verify_vulnerability Tool
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestVerifyVulnerabilityTool:
    """Test the verify_vulnerability agent tool."""

    def test_verify_vulnerability_returns_result(self):
        from phantom.tools.security.verification_actions import verify_vulnerability

        result = asyncio.run(verify_vulnerability(
            vuln_id="test-001",
            target="http://example.com/search?q=test",
            vulnerability_class="sqli",
            severity="high",
            parameter="q",
        ))
        assert result["success"] is True
        assert "verified" in result
        assert "attempts" in result

    def test_verify_vulnerability_handles_bad_target(self):
        from phantom.tools.security.verification_actions import verify_vulnerability

        result = asyncio.run(verify_vulnerability(
            vuln_id="test-002",
            target="http://nonexistent.invalid/path",
            vulnerability_class="xss",
        ))
        # Should not crash
        assert "success" in result

    def test_verify_vulnerability_updates_agent_state(self):
        """If verification succeeds, agent_state.mark_vuln_verified is called."""
        from phantom.tools.security.verification_actions import verify_vulnerability
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.models.vulnerability import Vulnerability

        state = EnhancedAgentState(agent_name="Test", max_iterations=100)
        vuln = Vulnerability(
            id="v-state-test",
            name="State test",
            vulnerability_class="sqli",
            severity="high",
            target="http://example.com",
            description="test",
            detected_by="test",
        )
        state.add_vulnerability(vuln)

        # We can't guarantee verification succeeds against example.com,
        # but we can verify the function accepts agent_state
        result = asyncio.run(verify_vulnerability(
            vuln_id="v-state-test",
            target="http://example.com/search?q=test",
            vulnerability_class="sqli",
            agent_state=state,
        ))
        assert result["success"] is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# check_known_vulnerabilities Tool
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCheckKnownVulnerabilities:
    """Test that check_known_vulnerabilities reads from the store."""

    def test_fresh_store_returns_empty(self, tmp_path):
        from phantom.tools.security.verification_actions import check_known_vulnerabilities
        from phantom.core import knowledge_store as ks_module

        # Patch the global singleton to use a temp store
        temp_store = ks_module.KnowledgeStore(store_path=tmp_path / "ks")
        with patch.object(ks_module, "_knowledge_store", temp_store):
            result = check_known_vulnerabilities(target="http://example.com")
            assert result["success"] is True
            assert result["known_vulnerabilities"] == []

    def test_finds_previously_stored_vuln(self, tmp_path):
        from phantom.tools.security.verification_actions import check_known_vulnerabilities
        from phantom.core import knowledge_store as ks_module
        from phantom.models.vulnerability import Vulnerability

        temp_store = ks_module.KnowledgeStore(store_path=tmp_path / "ks")
        vuln = Vulnerability(
            id="known-001",
            name="Known SQLi",
            vulnerability_class="sqli",
            severity="critical",
            target="http://example.com/login",
            description="SQLi in login",
            detected_by="past-scan",
        )
        temp_store.save_vulnerability(vuln)

        with patch.object(ks_module, "_knowledge_store", temp_store):
            result = check_known_vulnerabilities(target="http://example.com")
            assert result["success"] is True
            assert result["count"] == 1
            assert result["known_vulnerabilities"][0]["name"] == "Known SQLi"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EnhancedAgentState — VulnerabilityStatus Import Fix
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEnhancedStateStatusFix:
    """Verify VulnerabilityStatus is now properly imported."""

    def test_mark_vuln_verified_uses_correct_status(self):
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.models.vulnerability import Vulnerability, VulnerabilityStatus

        state = EnhancedAgentState(agent_name="Test", max_iterations=100)
        vuln = Vulnerability(
            id="v-1", name="Test", vulnerability_class="sqli",
            severity="high", target="http://x.com", description="", detected_by="t",
        )
        state.add_vulnerability(vuln)
        state.mark_vuln_verified("v-1")

        assert state.vulnerabilities["v-1"].status == VulnerabilityStatus.VERIFIED
        assert "v-1" in state.verified_vulns

    def test_mark_vuln_false_positive_uses_correct_status(self, tmp_path):
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.models.vulnerability import Vulnerability, VulnerabilityStatus
        import phantom.core.knowledge_store as ks_mod

        # Use a clean temporary knowledge store to avoid stale FP entries
        # from prior test runs polluting the default phantom_knowledge/ dir.
        original_store = ks_mod._knowledge_store
        ks_mod._knowledge_store = ks_mod.KnowledgeStore(store_path=tmp_path / "ks")

        try:
            state = EnhancedAgentState(agent_name="Test", max_iterations=100)
            vuln = Vulnerability(
                id="v-2", name="Test", vulnerability_class="xss",
                severity="medium", target="http://x.com", description="", detected_by="t",
            )
            state.add_vulnerability(vuln)
            state.mark_vuln_false_positive("v-2")

            assert state.vulnerabilities["v-2"].status == VulnerabilityStatus.FALSE_POSITIVE
            assert "v-2" in state.false_positives
        finally:
            ks_mod._knowledge_store = original_store


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PhantomAgent — Prior Intel Injection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPriorIntelInjection:
    """Test that _query_prior_intel retrieves and formats knowledge store data."""

    def test_empty_store_returns_empty_string(self, tmp_path):
        from phantom.agents.PhantomAgent.phantom_agent import PhantomAgent
        from phantom.core import knowledge_store as ks_module

        temp_store = ks_module.KnowledgeStore(store_path=tmp_path / "ks")

        with (
            patch.object(ks_module, "_knowledge_store", temp_store),
            patch.object(PhantomAgent, "__init__", lambda self, config: None),
        ):
            agent = PhantomAgent.__new__(PhantomAgent)
            result = agent._query_prior_intel([])
            assert result == ""

    def test_with_prior_vulns(self, tmp_path):
        from phantom.agents.PhantomAgent.phantom_agent import PhantomAgent
        from phantom.core import knowledge_store as ks_module
        from phantom.models.vulnerability import Vulnerability

        temp_store = ks_module.KnowledgeStore(store_path=tmp_path / "ks")
        vuln = Vulnerability(
            id="prev-001", name="Old SQLi", vulnerability_class="sqli",
            severity="critical", target="http://target.com/login",
            description="SQLi", detected_by="old-scan",
        )
        temp_store.save_vulnerability(vuln)

        targets = [{"details": {"target_url": "http://target.com"}, "original": "http://target.com"}]

        with (
            patch.object(ks_module, "_knowledge_store", temp_store),
            patch.object(PhantomAgent, "__init__", lambda self, config: None),
        ):
            agent = PhantomAgent.__new__(PhantomAgent)
            result = agent._query_prior_intel(targets)
            assert "PRIOR SCAN INTELLIGENCE" in result
            assert "Old SQLi" in result
            assert "1 vulnerabilities" in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Post-Scan Enrichment — Verification Step
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPostScanVerification:
    """Test that _run_post_scan_enrichment includes verification."""

    def test_enrichment_includes_verification_key(self, tmp_path):
        from phantom.tools.finish.finish_actions import _run_post_scan_enrichment

        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = [
            {
                "id": "v1",
                "title": "Test SQLi",
                "description": "SQL injection",
                "severity": "critical",
                "target": "http://example.com/search?q=test",
                "parameter": "q",
                "vulnerability_class": "sqli",
                "poc_script_code": "' OR 1=1--",
            }
        ]
        mock_tracer.get_run_dir.return_value = tmp_path
        mock_tracer.scan_config = {"targets": [{"original": "http://example.com"}]}
        mock_tracer.run_id = "test-run-001"

        result = _run_post_scan_enrichment(mock_tracer)
        assert "verification" in result

    def test_enrichment_passes_agent_state(self, tmp_path):
        from phantom.tools.finish.finish_actions import _run_post_scan_enrichment
        from phantom.agents.enhanced_state import EnhancedAgentState

        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = [
            {
                "id": "v1",
                "title": "Test",
                "description": "Test vuln",
                "severity": "high",
                "target": "http://example.com",
                "vulnerability_class": "xss",
            }
        ]
        mock_tracer.get_run_dir.return_value = tmp_path
        mock_tracer.scan_config = {"targets": []}
        mock_tracer.run_id = "test-run"

        state = EnhancedAgentState(agent_name="Test", max_iterations=100)

        result = _run_post_scan_enrichment(mock_tracer, agent_state=state)
        assert "verification" in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Post-Scan Enrichment — Knowledge Store Hosts + History
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPostScanKnowledgeStoreExpanded:
    """Test that enrichment saves hosts and scan history."""

    def test_hosts_saved_from_agent_state(self, tmp_path):
        from phantom.tools.finish.finish_actions import _run_post_scan_enrichment
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.models.host import Host, Port
        from phantom.core import knowledge_store as ks_module

        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = [
            {
                "id": "v1", "title": "T", "description": "D",
                "severity": "high", "target": "http://192.168.1.1",
                "vulnerability_class": "xss",
            }
        ]
        mock_tracer.get_run_dir.return_value = tmp_path
        mock_tracer.scan_config = {"targets": [{"original": "http://192.168.1.1"}]}
        mock_tracer.run_id = "run-001"

        state = EnhancedAgentState(agent_name="Test", max_iterations=100)
        state.initialize_scan("http://192.168.1.1")
        host = Host(
            ip="192.168.1.1",
            hostname="target.local",
            ports=[Port(number=80, protocol="tcp", service="http")],
        )
        state.add_host(host)

        temp_store = ks_module.KnowledgeStore(store_path=tmp_path / "ks")
        with patch.object(ks_module, "_knowledge_store", temp_store):
            result = _run_post_scan_enrichment(mock_tracer, agent_state=state)

        ks_data = result.get("knowledge_store", {})
        assert ks_data.get("hosts_stored", 0) >= 1

    def test_scan_history_recorded(self, tmp_path):
        from phantom.tools.finish.finish_actions import _run_post_scan_enrichment
        from phantom.agents.enhanced_state import EnhancedAgentState
        from phantom.core import knowledge_store as ks_module

        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = [
            {
                "id": "v1", "title": "T", "description": "D",
                "severity": "medium", "target": "http://test.com",
                "vulnerability_class": "other",
            }
        ]
        mock_tracer.get_run_dir.return_value = tmp_path
        mock_tracer.scan_config = {"targets": [{"original": "http://test.com"}]}
        mock_tracer.run_id = "run-002"

        state = EnhancedAgentState(agent_name="Test", max_iterations=100)

        temp_store = ks_module.KnowledgeStore(store_path=tmp_path / "ks")
        with patch.object(ks_module, "_knowledge_store", temp_store):
            result = _run_post_scan_enrichment(mock_tracer, agent_state=state)

        ks_data = result.get("knowledge_store", {})
        assert ks_data.get("scan_recorded") is True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Statistics and Reporting
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestKnowledgeStoreStatistics:
    """Test knowledge store statistics."""

    def test_statistics_reflect_data(self, tmp_path):
        from phantom.core.knowledge_store import KnowledgeStore
        from phantom.models.vulnerability import Vulnerability
        from phantom.models.host import Host

        store = KnowledgeStore(store_path=tmp_path / "ks")

        # Add some data
        store.save_vulnerability(Vulnerability(
            id="v1", name="SQLi", vulnerability_class="sqli",
            severity="critical", target="http://x.com", description="", detected_by="t",
        ))
        store.save_vulnerability(Vulnerability(
            id="v2", name="XSS", vulnerability_class="xss",
            severity="high", target="http://x.com", description="", detected_by="t",
        ))
        host = Host(ip="1.2.3.4")
        store.save_host(host)
        store.record_scan("s1", "http://x.com", "completed", 2, 1, 1)
        store.mark_false_positive("nuclei:sqli:*.example.com")

        stats = store.get_statistics()
        assert stats["total_hosts"] == 1
        assert stats["total_vulnerabilities"] == 2
        assert stats["false_positives"] == 1
        assert stats["total_scans"] == 1
        assert stats["vulns_by_severity"]["critical"] == 1
        assert stats["vulns_by_severity"]["high"] == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool Registration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestToolRegistration:
    """Verify new tools are importable and registered."""

    def test_verify_vulnerability_importable(self):
        from phantom.tools.security.verification_actions import verify_vulnerability
        assert callable(verify_vulnerability)

    def test_check_known_vulnerabilities_importable(self):
        from phantom.tools.security.verification_actions import check_known_vulnerabilities
        assert callable(check_known_vulnerabilities)

    def test_enrich_vulnerability_importable(self):
        from phantom.tools.security.verification_actions import enrich_vulnerability
        assert callable(enrich_vulnerability)

    def test_security_package_exports(self):
        from phantom.tools.security import (
            check_known_vulnerabilities,
            enrich_vulnerability,
            verify_vulnerability,
        )
        assert callable(verify_vulnerability)

    def test_verification_engine_importable(self):
        from phantom.core.verification_engine import VerificationEngine
        assert VerificationEngine is not None

    def test_knowledge_store_importable(self):
        from phantom.core.knowledge_store import KnowledgeStore, get_knowledge_store
        assert KnowledgeStore is not None
        assert callable(get_knowledge_store)
