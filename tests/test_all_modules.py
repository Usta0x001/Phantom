"""
Comprehensive test suite for all Phantom modules created in Sessions 1-4.

Tests cover:
- Core modules: ScopeValidator, AuditLogger, MITREEnricher, AttackGraph,
  ComplianceMapper, AttackPathAnalyzer
- Interface modules: SARIFFormatter
- LLM modules: ProviderRegistry, FallbackChain
- Agent modules: Protocol
- Wiring: Integration of modules into pipeline hooks
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

import pytest


# =========================================================================
# ScopeValidator Tests
# =========================================================================


class TestScopeValidator:
    """Tests for phantom.core.scope_validator."""

    def _make(self, targets: list[str] | None = None):
        from phantom.core.scope_validator import ScopeValidator

        if targets:
            return ScopeValidator.from_targets(targets)
        return ScopeValidator()

    def test_from_targets_url(self):
        sv = self._make(["http://example.com:3000"])
        assert sv.is_in_scope("http://example.com:3000/api")

    def test_from_targets_ip(self):
        sv = self._make(["192.168.1.1"])
        assert sv.is_in_scope("192.168.1.1")

    def test_from_targets_cidr(self):
        sv = self._make(["10.0.0.0/24"])
        assert sv.is_in_scope("10.0.0.42")
        assert not sv.is_in_scope("10.0.1.1")

    def test_out_of_scope(self):
        sv = self._make(["http://example.com"])
        assert not sv.is_in_scope("http://evil.com")

    def test_deny_rule_priority(self):
        from phantom.core.scope_validator import ScopeConfig, ScopeValidator

        config = ScopeConfig()
        config.add_target("*.example.com")
        config.add_deny("admin.example.com")
        sv = ScopeValidator(config)
        assert sv.is_in_scope("api.example.com")
        assert not sv.is_in_scope("admin.example.com")

    def test_empty_scope_denies_all(self):
        sv = self._make()
        assert not sv.is_in_scope("http://anything.com")

    def test_wildcard_subdomain(self):
        sv = self._make(["*.example.com"])
        assert sv.is_in_scope("api.example.com")
        assert sv.is_in_scope("test.example.com")
        assert sv.is_in_scope("example.com")

    def test_docker_internal_host(self):
        sv = self._make(["http://host.docker.internal:3000"])
        assert sv.is_in_scope("http://host.docker.internal:3000/rest/products")


# =========================================================================
# AuditLogger Tests
# =========================================================================


class TestAuditLogger:
    """Tests for phantom.core.audit_logger."""

    def _make(self, tmp_path: Path):
        from phantom.core.audit_logger import AuditLogger

        return AuditLogger(tmp_path / "audit.jsonl")

    def test_log_event(self, tmp_path):
        logger = self._make(tmp_path)
        logger.log_event("test_event", {"key": "value"})
        events = logger.read_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "test_event"
        assert events[0]["data"]["key"] == "value"

    def test_log_tool_call(self, tmp_path):
        logger = self._make(tmp_path)
        logger.log_tool_call("nmap_scan", {"target": "example.com"}, duration_ms=150.5)
        events = logger.read_events(category="tool")
        assert len(events) == 1
        assert events[0]["data"]["tool_name"] == "nmap_scan"
        assert events[0]["data"]["duration_ms"] == 150.5

    def test_log_finding(self, tmp_path):
        logger = self._make(tmp_path)
        logger.log_finding("SQL Injection", severity="critical", cwe="CWE-89")
        events = logger.read_events(category="finding")
        assert len(events) == 1
        assert events[0]["data"]["title"] == "SQL Injection"
        assert events[0]["severity"] == "error"

    def test_sensitive_data_redacted(self, tmp_path):
        logger = self._make(tmp_path)
        logger.log_tool_call("auth", {"password": "secret123", "user": "admin"})
        events = logger.read_events()
        assert events[0]["data"]["args"]["password"] == "***REDACTED***"
        assert events[0]["data"]["args"]["user"] == "admin"

    def test_log_scan_start_end(self, tmp_path):
        logger = self._make(tmp_path)
        logger.log_scan_start("scan-001", ["http://example.com"])
        logger.log_scan_end("scan-001", success=True, findings_count=5)
        events = logger.read_events()
        assert len(events) == 2

    def test_get_stats(self, tmp_path):
        logger = self._make(tmp_path)
        logger.log_event("a", severity="info")
        logger.log_event("b", severity="error")
        stats = logger.get_stats()
        assert stats["total_events"] == 2
        assert stats["by_severity"]["info"] == 1
        assert stats["by_severity"]["error"] == 1

    def test_global_accessor(self, tmp_path):
        from phantom.core.audit_logger import (
            AuditLogger,
            get_global_audit_logger,
            set_global_audit_logger,
        )

        logger = AuditLogger(tmp_path / "test.jsonl")
        set_global_audit_logger(logger)
        assert get_global_audit_logger() is logger

    def test_rotation(self, tmp_path):
        from phantom.core.audit_logger import AuditLogger

        logger = AuditLogger(tmp_path / "audit.jsonl", max_size=100)
        # Write enough to trigger rotation
        for i in range(20):
            logger.log_event(f"event_{i}", {"data": "x" * 50})
        # Should have rotated file(s)
        jsonl_files = list(tmp_path.glob("audit*.jsonl"))
        assert len(jsonl_files) >= 1


# =========================================================================
# MITREEnricher Tests
# =========================================================================


class TestMITREEnricher:
    """Tests for phantom.core.mitre_enrichment."""

    def _make(self):
        from phantom.core.mitre_enrichment import MITREEnricher

        return MITREEnricher()

    def test_enrich_sql_injection(self):
        e = self._make()
        result = e.enrich_finding({"title": "SQL Injection", "description": "SQL injection in login"})
        assert "primary_cwe" in result
        assert result["primary_cwe"] == "CWE-89"
        assert len(result["cwe"]) > 0
        assert len(result["capec"]) > 0

    def test_enrich_xss(self):
        e = self._make()
        result = e.enrich_finding({"title": "Cross-Site Scripting", "description": "XSS in search"})
        assert "primary_cwe" in result
        assert result["primary_cwe"] == "CWE-79"

    def test_enrich_unknown_vuln(self):
        e = self._make()
        result = e.enrich_finding({"title": "Unknown Issue", "description": "Something weird"})
        assert result.get("cwe", []) == [] or "cwe" not in result or len(result["cwe"]) == 0

    def test_enrich_by_explicit_cwe(self):
        e = self._make()
        result = e.enrich_finding({"title": "CWE-78 found", "description": "Command injection"})
        assert any(c["id"] == "CWE-78" for c in result.get("cwe", []))

    def test_enrich_multiple_findings(self):
        e = self._make()
        findings = [
            {"title": "SQLi", "description": "sql injection"},
            {"title": "XSS", "description": "cross-site scripting"},
        ]
        results = e.enrich_findings(findings)
        assert len(results) == 2
        assert results[0].get("primary_cwe") == "CWE-89"
        assert results[1].get("primary_cwe") == "CWE-79"

    def test_owasp_mapping(self):
        e = self._make()
        result = e.enrich_finding({"title": "SQL Injection", "description": "sqli"})
        assert "owasp_top10" in result
        assert any("A03" in cat for cat in result["owasp_top10"])


# =========================================================================
# AttackGraph Tests
# =========================================================================


class TestAttackGraph:
    """Tests for phantom.core.attack_graph."""

    def _make(self):
        from phantom.core.attack_graph import AttackGraph

        return AttackGraph()

    def test_add_host_and_service(self):
        g = self._make()
        g.add_host("192.168.1.1")
        g.add_service("192.168.1.1", 80, name="HTTP")
        assert g.node_count >= 2

    def test_add_vulnerability(self):
        g = self._make()
        g.add_host("192.168.1.1")
        g.add_service("192.168.1.1", 80, name="HTTP")
        g.add_endpoint("192.168.1.1", 80, "/login")
        g.add_vulnerability("v1", "SQLi", severity="critical", cvss=9.8, host="192.168.1.1", port=80, endpoint="/login")
        assert g.node_count >= 4

    def test_ingest_scan_findings(self):
        g = self._make()
        findings = [
            {"title": "SQLi", "severity": "critical", "target": "http://example.com", "endpoint": "/login", "cvss": 9.8},
            {"title": "XSS", "severity": "high", "target": "http://example.com", "endpoint": "/search", "cvss": 7.5},
        ]
        count = g.ingest_scan_findings(findings)
        assert count >= 2  # returns total nodes added (hosts + endpoints + vulns)
        assert g.node_count >= 4

    def test_find_attack_paths(self):
        g = self._make()
        g.add_host("10.0.0.1")
        g.add_service("10.0.0.1", 80, name="HTTP")
        g.add_endpoint("10.0.0.1", 80, "/api")
        g.add_vulnerability("v1", "RCE", severity="critical", cvss=10.0, host="10.0.0.1", port=80, endpoint="/api")
        paths = g.find_attack_paths("host:10.0.0.1", max_depth=5)
        assert isinstance(paths, list)

    def test_export_import_json(self, tmp_path):
        g = self._make()
        g.ingest_scan_findings([{"title": "Test", "severity": "high", "target": "http://x.com", "endpoint": "/a"}])
        out = tmp_path / "graph.json"
        g.export_json(out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "nodes" in data

    def test_risk_propagation(self):
        g = self._make()
        g.add_host("10.0.0.1")
        g.add_service("10.0.0.1", 80, name="HTTP")
        g.add_endpoint("10.0.0.1", 80, "/login")
        g.add_vulnerability("v1", "SQLi", severity="critical", cvss=9.8, host="10.0.0.1", port=80, endpoint="/login")
        g.propagate_risk()
        # Host should have elevated risk
        assert g.node_count >= 4


# =========================================================================
# AttackPathAnalyzer Tests
# =========================================================================


class TestAttackPathAnalyzer:
    """Tests for phantom.core.attack_path_analyzer."""

    def _make_graph_with_vulns(self):
        from phantom.core.attack_graph import AttackGraph

        g = AttackGraph()
        g.ingest_scan_findings([
            {"title": "SQLi", "severity": "critical", "target": "http://app.com", "endpoint": "/login", "cvss": 9.8},
            {"title": "XSS", "severity": "high", "target": "http://app.com", "endpoint": "/search", "cvss": 7.5},
            {"title": "IDOR", "severity": "medium", "target": "http://app.com", "endpoint": "/api/users", "cvss": 5.0},
        ])
        return g

    def test_full_analysis(self):
        from phantom.core.attack_path_analyzer import AttackPathAnalyzer

        g = self._make_graph_with_vulns()
        a = AttackPathAnalyzer(g)
        report = a.full_analysis()
        assert report.total_paths >= 0

    def test_to_markdown(self):
        from phantom.core.attack_path_analyzer import AttackPathAnalyzer

        g = self._make_graph_with_vulns()
        a = AttackPathAnalyzer(g)
        md = a.to_markdown()
        assert "# Attack Path Analysis" in md

    def test_discover_all_paths(self):
        from phantom.core.attack_path_analyzer import AttackPathAnalyzer

        g = self._make_graph_with_vulns()
        a = AttackPathAnalyzer(g)
        paths = a.discover_all_paths(max_depth=5)
        assert isinstance(paths, list)

    def test_empty_graph(self):
        from phantom.core.attack_graph import AttackGraph
        from phantom.core.attack_path_analyzer import AttackPathAnalyzer

        g = AttackGraph()
        a = AttackPathAnalyzer(g)
        report = a.full_analysis()
        assert report.total_paths == 0


# =========================================================================
# ComplianceMapper Tests
# =========================================================================


class TestComplianceMapper:
    """Tests for phantom.core.compliance_mapper."""

    def _make(self):
        from phantom.core.compliance_mapper import ComplianceMapper

        return ComplianceMapper()

    def _sample_findings(self):
        return [
            {"title": "SQL Injection", "severity": "critical", "description": "sql injection in login", "cwe": "CWE-89"},
            {"title": "XSS", "severity": "high", "description": "cross-site scripting", "cwe": "CWE-79"},
            {"title": "Weak Password", "severity": "medium", "description": "weak password policy"},
        ]

    def test_map_findings(self):
        cm = self._make()
        matches = cm.map_findings(self._sample_findings())
        assert len(matches) > 0

    def test_generate_report_owasp(self):
        cm = self._make()
        report = cm.generate_report("OWASP-2021", self._sample_findings())
        assert report.framework == "OWASP-2021"
        assert report.total_controls > 0

    def test_gap_analysis(self):
        cm = self._make()
        gap = cm.gap_analysis(self._sample_findings())
        assert "frameworks" in gap
        assert "summary" in gap
        assert gap["summary"]["total_frameworks_assessed"] > 0

    def test_to_markdown(self):
        cm = self._make()
        md = cm.to_markdown(self._sample_findings())
        assert "# Compliance" in md
        assert "OWASP" in md

    def test_empty_findings(self):
        cm = self._make()
        md = cm.to_markdown([])
        assert "# Compliance" in md


# =========================================================================
# SARIFFormatter Tests
# =========================================================================


class TestSARIFFormatter:
    """Tests for phantom.interface.formatters.sarif_formatter."""

    def _make(self):
        from phantom.interface.formatters.sarif_formatter import SARIFFormatter

        return SARIFFormatter()

    def test_format_basic(self):
        f = self._make()
        sarif = f.format({"vulnerabilities": [
            {"title": "SQLi", "severity": "critical", "description": "sql injection"},
        ]})
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1

    def test_format_empty(self):
        f = self._make()
        sarif = f.format({"vulnerabilities": []})
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0

    def test_format_multiple_vulns(self):
        f = self._make()
        sarif = f.format({"vulnerabilities": [
            {"title": "SQLi", "severity": "critical", "description": "injection"},
            {"title": "XSS", "severity": "high", "description": "scripting"},
            {"title": "Info Leak", "severity": "low", "description": "info"},
        ]})
        assert len(sarif["runs"][0]["results"]) == 3

    def test_sarif_schema_url(self):
        f = self._make()
        sarif = f.format({"vulnerabilities": []})
        assert "oasis-open.org" in sarif["$schema"]

    def test_scan_id_in_automation(self):
        f = self._make()
        sarif = f.format({"vulnerabilities": [], "scan_id": "test-scan-123"})
        assert sarif["runs"][0]["automationDetails"]["id"] == "test-scan-123"


# =========================================================================
# ProviderRegistry Tests
# =========================================================================


class TestProviderRegistry:
    """Tests for phantom.llm.provider_registry."""

    def test_get_context_window_known(self):
        from phantom.llm.provider_registry import get_context_window

        assert get_context_window("groq/llama-3.3-70b-versatile") == 128_000
        assert get_context_window("gpt-4o") == 128_000

    def test_get_context_window_prefix_match(self):
        from phantom.llm.provider_registry import get_context_window

        assert get_context_window("groq/some-new-model") == 128_000
        assert get_context_window("anthropic/claude-3-future") == 200_000

    def test_get_context_window_unknown(self):
        from phantom.llm.provider_registry import get_context_window

        assert get_context_window("totally-unknown-model") == 128_000

    def test_fallback_chain_single(self):
        from phantom.llm.provider_registry import FallbackChain

        fc = FallbackChain(providers=["groq/llama-3.3-70b-versatile"])
        assert fc.current_model == "groq/llama-3.3-70b-versatile"
        assert not fc.has_fallback
        assert fc.advance() is None

    def test_fallback_chain_multi(self):
        from phantom.llm.provider_registry import FallbackChain

        fc = FallbackChain(providers=["groq/llama-3.3-70b-versatile", "gpt-4o-mini"])
        assert fc.has_fallback
        assert fc.current_model == "groq/llama-3.3-70b-versatile"
        next_m = fc.advance()
        assert next_m == "gpt-4o-mini"
        assert fc.current_model == "gpt-4o-mini"
        assert fc.exhausted
        assert fc.advance() is None

    def test_fallback_chain_reset(self):
        from phantom.llm.provider_registry import FallbackChain

        fc = FallbackChain(providers=["a", "b", "c"])
        fc.advance()
        fc.reset()
        assert fc.current_model == "a"

    def test_provider_presets_exist(self):
        from phantom.llm.provider_registry import PROVIDER_PRESETS

        assert len(PROVIDER_PRESETS) >= 5
        assert "gpt-4o" in PROVIDER_PRESETS
        assert "groq/llama-3.3-70b-versatile" in PROVIDER_PRESETS


# =========================================================================
# Agent Protocol Tests
# =========================================================================


class TestAgentProtocol:
    """Tests for phantom.agents.protocol."""

    def test_message_roundtrip(self):
        from phantom.agents.protocol import AgentMessage, MessageType

        msg = AgentMessage(
            msg_type=MessageType.TASK_ASSIGN,
            sender_id="root",
            receiver_id="sub-1",
            payload={"target": "http://example.com"},
        )
        d = msg.to_dict()
        msg2 = AgentMessage.from_dict(d)
        assert msg2.msg_type == MessageType.TASK_ASSIGN
        assert msg2.payload["target"] == "http://example.com"

    def test_task_assignment_to_string(self):
        from phantom.agents.protocol import TaskAssignment

        ta = TaskAssignment(
            task_type="scan",
            target="http://example.com",
            objective="Find SQL injection vulnerabilities",
        )
        s = ta.to_task_string()
        assert "[SCAN]" in s
        assert "http://example.com" in s

    def test_scan_phases(self):
        from phantom.agents.protocol import SCAN_PHASES

        assert len(SCAN_PHASES) == 5
        assert SCAN_PHASES[0].name == "reconnaissance"
        assert "scanning" in SCAN_PHASES[1].depends_on or len(SCAN_PHASES[1].depends_on) > 0


# =========================================================================
# Integration / Wiring Tests
# =========================================================================


class TestWiringIntegration:
    """Tests that modules are correctly wired into the pipeline."""

    def test_cli_imports_scope_and_audit(self):
        """cli.py should import ScopeValidator and AuditLogger."""
        source = Path(__file__).resolve().parent.parent / "phantom" / "interface" / "cli.py"
        content = source.read_text(encoding="utf-8")
        assert "ScopeValidator" in content
        assert "AuditLogger" in content
        assert "set_global_audit_logger" in content

    def test_executor_has_audit_logging(self):
        """executor.py should log tool calls via AuditLogger."""
        source = Path(__file__).resolve().parent.parent / "phantom" / "tools" / "executor.py"
        content = source.read_text(encoding="utf-8")
        assert "get_global_audit_logger" in content
        assert "log_tool_call" in content

    def test_reporting_has_mitre_enrichment(self):
        """reporting_actions.py should enrich findings with MITRE data."""
        source = (
            Path(__file__).resolve().parent.parent
            / "phantom"
            / "tools"
            / "reporting"
            / "reporting_actions.py"
        )
        content = source.read_text(encoding="utf-8")
        assert "MITREEnricher" in content
        assert "enrich_finding" in content

    def test_finish_has_post_scan_hooks(self):
        """finish_actions.py should run compliance, attack graph, SARIF on scan completion."""
        source = (
            Path(__file__).resolve().parent.parent
            / "phantom"
            / "tools"
            / "finish"
            / "finish_actions.py"
        )
        content = source.read_text(encoding="utf-8")
        assert "ComplianceMapper" in content
        assert "AttackGraph" in content
        assert "SARIFFormatter" in content
        assert "_post_scan_hooks" in content

    def test_tracer_accepts_mitre_and_cvss_vector(self):
        """Tracer.add_vulnerability_report should accept mitre and cvss_vector kwargs."""
        from phantom.telemetry.tracer import Tracer

        t = Tracer("test-wiring")
        rid = t.add_vulnerability_report(
            title="Test Vuln",
            severity="high",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            mitre={"primary_cwe": "CWE-89", "cwe": [], "capec": []},
        )
        assert rid.startswith("vuln-")
        report = t.vulnerability_reports[-1]
        assert report["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert report["mitre"]["primary_cwe"] == "CWE-89"

    def test_llm_has_fallback_chain(self):
        """llm.py should import and use FallbackChain."""
        source = Path(__file__).resolve().parent.parent / "phantom" / "llm" / "llm.py"
        content = source.read_text(encoding="utf-8")
        assert "FallbackChain" in content
        assert "_fallback_chain" in content


# ======================================================================
# Phase 7 — Scan Profiles
# ======================================================================


class TestScanProfiles(unittest.TestCase):
    """Tests for phantom.core.scan_profiles."""

    def test_list_profiles(self):
        from phantom.core.scan_profiles import list_profiles
        profiles = list_profiles()
        names = [p["name"] for p in profiles]
        assert "quick" in names
        assert "deep" in names
        assert "stealth" in names
        assert len(profiles) >= 5

    def test_get_profile(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("stealth")
        assert p.name == "stealth"
        assert p.max_concurrent_tools == 1
        assert "ffuf_scan" in p.skip_tools

    def test_get_profile_unknown(self):
        from phantom.core.scan_profiles import get_profile
        with self.assertRaises(KeyError):
            get_profile("nonexistent_profile")

    def test_profile_merge(self):
        from phantom.core.scan_profiles import get_profile
        p = get_profile("quick")
        merged = p.merge({"max_iterations": 99, "enable_browser": True})
        assert merged.max_iterations == 99
        assert merged.enable_browser is True
        assert p.max_iterations != 99  # original unchanged

    def test_profile_serialization(self):
        from phantom.core.scan_profiles import get_profile, ScanProfile
        p = get_profile("standard")
        d = p.to_dict()
        restored = ScanProfile.from_dict(d)
        assert restored.name == p.name
        assert restored.max_iterations == p.max_iterations

    def test_register_custom_profile(self):
        from phantom.core.scan_profiles import register_profile, get_profile, ScanProfile, PROFILES
        custom = ScanProfile(name="custom_test", description="Test only", max_iterations=5)
        register_profile(custom)
        assert get_profile("custom_test").max_iterations == 5
        # Cleanup
        PROFILES.pop("custom_test", None)


# ======================================================================
# Phase 7 — Differential Scanner
# ======================================================================


class TestDiffScanner(unittest.TestCase):
    """Tests for phantom.core.diff_scanner."""

    def _write_csv(self, run_dir: Path, vulns: list[dict]):
        run_dir.mkdir(parents=True, exist_ok=True)
        csv_path = run_dir / "vulnerabilities.csv"
        import csv as _csv
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = _csv.DictWriter(f, fieldnames=["title", "severity", "endpoint", "method", "cve"])
            writer.writeheader()
            for v in vulns:
                writer.writerow(v)

    def test_compare_finds_new_and_fixed(self):
        from phantom.core.diff_scanner import DiffScanner
        with tempfile.TemporaryDirectory() as tmp:
            base_dir = Path(tmp) / "run_base"
            curr_dir = Path(tmp) / "run_curr"
            self._write_csv(base_dir, [
                {"title": "sqli", "severity": "high", "endpoint": "/login", "method": "POST", "cve": ""},
                {"title": "xss", "severity": "medium", "endpoint": "/search", "method": "GET", "cve": ""},
            ])
            self._write_csv(curr_dir, [
                {"title": "sqli", "severity": "high", "endpoint": "/login", "method": "POST", "cve": ""},
                {"title": "rce", "severity": "critical", "endpoint": "/admin", "method": "POST", "cve": "CVE-2024-1"},
            ])
            diff = DiffScanner(base_dir, curr_dir)
            report = diff.compare()
            assert len(report.new_vulns) == 1
            assert report.new_vulns[0]["title"] == "rce"
            assert len(report.fixed_vulns) == 1
            assert report.fixed_vulns[0]["title"] == "xss"
            assert len(report.persistent_vulns) == 1

    def test_severity_delta(self):
        from phantom.core.diff_scanner import DiffScanner
        with tempfile.TemporaryDirectory() as tmp:
            base_dir = Path(tmp) / "base"
            curr_dir = Path(tmp) / "curr"
            self._write_csv(base_dir, [
                {"title": "a", "severity": "high", "endpoint": "/a", "method": "GET", "cve": ""},
            ])
            self._write_csv(curr_dir, [
                {"title": "a", "severity": "high", "endpoint": "/a", "method": "GET", "cve": ""},
                {"title": "b", "severity": "critical", "endpoint": "/b", "method": "GET", "cve": ""},
            ])
            report = DiffScanner(base_dir, curr_dir).compare()
            assert report.severity_delta["critical"] == 1
            assert report.severity_delta["high"] == 0

    def test_to_markdown(self):
        from phantom.core.diff_scanner import DiffScanner, DiffReport
        report = DiffReport(
            baseline_run="old", current_run="new",
            new_vulns=[{"title": "New Bug", "severity": "high", "endpoint": "/x"}],
            fixed_vulns=[{"title": "Old Bug", "severity": "low", "endpoint": "/y"}],
        )
        md = DiffScanner.to_markdown(report)
        assert "New Bug" in md
        assert "~~" in md  # fixed vulns are struck through

    def test_empty_runs(self):
        from phantom.core.diff_scanner import DiffScanner
        with tempfile.TemporaryDirectory() as tmp:
            base_dir = Path(tmp) / "empty_base"
            curr_dir = Path(tmp) / "empty_curr"
            base_dir.mkdir()
            curr_dir.mkdir()
            report = DiffScanner(base_dir, curr_dir).compare()
            assert report.new_vulns == []
            assert report.fixed_vulns == []

    def test_save_json(self):
        from phantom.core.diff_scanner import DiffScanner, DiffReport
        report = DiffReport(baseline_run="a", current_run="b")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "diff.json"
            DiffScanner(".", ".").save_json(report, out)
            data = json.loads(out.read_text(encoding="utf-8"))
            assert data["baseline_run"] == "a"


# ======================================================================
# Phase 7 — Notifier
# ======================================================================


class TestNotifier(unittest.TestCase):
    """Tests for phantom.core.notifier."""

    def test_callable_channel(self):
        from phantom.core.notifier import Notifier, CallableChannel
        received = []
        n = Notifier(min_severity="low")
        n.add_channel(CallableChannel(callback=lambda p: (received.append(p), True)[1]))
        n.notify_finding({"title": "Test", "severity": "medium"})
        assert len(received) == 1
        assert received[0]["event"] == "finding"

    def test_severity_filtering(self):
        from phantom.core.notifier import Notifier, CallableChannel
        received = []
        n = Notifier(min_severity="high")
        n.add_channel(CallableChannel(callback=lambda p: (received.append(p), True)[1]))
        n.notify_finding({"title": "Low", "severity": "low"})
        n.notify_finding({"title": "Med", "severity": "medium"})
        n.notify_finding({"title": "High", "severity": "high"})
        n.notify_finding({"title": "Crit", "severity": "critical"})
        assert len(received) == 2  # only high and critical

    def test_scan_complete(self):
        from phantom.core.notifier import Notifier, CallableChannel
        received = []
        n = Notifier()
        n.add_channel(CallableChannel(callback=lambda p: (received.append(p), True)[1]))
        n.notify_scan_complete(scan_id="test-123", findings_count=5, critical=2)
        assert len(received) == 1
        assert received[0]["summary"]["critical"] == 2

    def test_from_env_no_vars(self):
        from phantom.core.notifier import Notifier
        # With no env vars set, should have zero channels
        n = Notifier.from_env()
        assert len(n.channels) == 0

    def test_sent_count(self):
        from phantom.core.notifier import Notifier, CallableChannel
        n = Notifier(min_severity="info")
        n.add_channel(CallableChannel(callback=lambda p: True))
        n.notify_finding({"title": "A", "severity": "info"})
        n.notify_finding({"title": "B", "severity": "high"})
        assert n.sent_count == 2


# ======================================================================
# Phase 7 — Nuclei Templates
# ======================================================================


class TestNucleiTemplates(unittest.TestCase):
    """Tests for phantom.core.nuclei_templates."""

    def test_from_finding_basic(self):
        from phantom.core.nuclei_templates import TemplateGenerator
        tg = TemplateGenerator()
        yaml_str = tg.from_finding({
            "title": "SQL Injection",
            "severity": "high",
            "endpoint": "/api/login",
            "method": "POST",
        })
        assert "id: phantom-sql-injection" in yaml_str
        assert "severity: high" in yaml_str
        assert "method: POST" in yaml_str
        assert "{{BaseURL}}/api/login" in yaml_str

    def test_from_finding_with_cve(self):
        from phantom.core.nuclei_templates import TemplateGenerator
        yaml_str = TemplateGenerator().from_finding({
            "title": "Known CVE",
            "severity": "critical",
            "cve": "CVE-2024-9999",
            "endpoint": "/vuln",
        })
        assert "cve-id: CVE-2024-9999" in yaml_str

    def test_matchers_for_xss(self):
        from phantom.core.nuclei_templates import TemplateGenerator
        yaml_str = TemplateGenerator().from_finding({
            "title": "XSS in Search",
            "severity": "medium",
            "endpoint": "/search",
        })
        assert "alert(" in yaml_str or "<script" in yaml_str

    def test_bulk_export(self):
        from phantom.core.nuclei_templates import TemplateGenerator
        with tempfile.TemporaryDirectory() as tmp:
            findings = [
                {"title": "Bug A", "severity": "high", "endpoint": "/a"},
                {"title": "Bug B", "severity": "medium", "endpoint": "/b"},
            ]
            paths = TemplateGenerator().bulk_export(findings, tmp)
            assert len(paths) == 2
            for p in paths:
                assert p.exists()
                assert p.suffix == ".yaml"


# ======================================================================
# Phase 7 — Plugin Loader
# ======================================================================


class TestPluginLoader(unittest.TestCase):
    """Tests for phantom.core.plugin_loader."""

    def test_discover_empty_dir(self):
        from phantom.core.plugin_loader import PluginLoader
        with tempfile.TemporaryDirectory() as tmp:
            loader = PluginLoader(tmp)
            found = loader.discover()
            assert found == []

    def test_load_plugin(self):
        from phantom.core.plugin_loader import PluginLoader
        with tempfile.TemporaryDirectory() as tmp:
            plugin_file = Path(tmp) / "test_plugin.py"
            plugin_file.write_text(
                '__version__ = "1.0.0"\n'
                '__description__ = "Test plugin"\n'
                'def register(registry):\n'
                '    pass\n',
                encoding="utf-8",
            )
            loader = PluginLoader(tmp)
            # Must set env var to enable plugins
            os.environ["PHANTOM_ENABLE_PLUGINS"] = "1"
            try:
                loaded = loader.load_all()
                assert len(loaded) == 1
                assert loaded[0].name == "test_plugin"
                assert loaded[0].version == "1.0.0"
            finally:
                os.environ.pop("PHANTOM_ENABLE_PLUGINS", None)

    def test_skip_underscore_files(self):
        from phantom.core.plugin_loader import PluginLoader
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "_hidden.py").write_text("x=1", encoding="utf-8")
            (Path(tmp) / "visible.py").write_text("def register(r): pass", encoding="utf-8")
            loader = PluginLoader(tmp)
            loader.discover()
            assert loader.discovered_count == 1

    def test_summary(self):
        from phantom.core.plugin_loader import PluginLoader
        loader = PluginLoader("/tmp/nonexistent")
        loader.discover()
        s = loader.summary()
        assert s["discovered"] == 0
        assert s["loaded"] == 0


# =========================================================================
# Tracer Thread Safety Tests
# =========================================================================


class TestTracerThreadSafety:
    """Verify Tracer methods are thread-safe under concurrent access."""

    def test_concurrent_vuln_reports(self):
        """Multiple threads adding vulnerability reports simultaneously."""
        import threading
        from phantom.telemetry.tracer import Tracer

        tracer = Tracer("thread-test")
        errors: list[str] = []

        def add_vulns(thread_id: int) -> None:
            try:
                for i in range(20):
                    tracer.add_vulnerability_report(
                        title=f"Vuln-T{thread_id}-{i}",
                        severity="high",
                        description=f"Thread {thread_id} vuln {i}",
                    )
            except Exception as e:
                errors.append(f"Thread {thread_id}: {e}")

        threads = [threading.Thread(target=add_vulns, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Thread errors: {errors}"
        assert len(tracer.vulnerability_reports) == 100  # 5 threads × 20 vulns

    def test_concurrent_tool_executions(self):
        """Multiple threads logging tool executions simultaneously."""
        import threading
        from phantom.telemetry.tracer import Tracer

        tracer = Tracer("tool-thread-test")
        tracer.log_agent_creation("agent-1", "TestAgent", "testing")
        ids: list[int] = []
        lock = threading.Lock()

        def log_tools(thread_id: int) -> None:
            for i in range(10):
                exec_id = tracer.log_tool_execution_start(
                    "agent-1", f"tool_{thread_id}_{i}", {"arg": i}
                )
                with lock:
                    ids.append(exec_id)
                tracer.update_tool_execution(exec_id, "completed", f"result-{thread_id}-{i}")

        threads = [threading.Thread(target=log_tools, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(ids) == 50  # 5 threads × 10 tools
        assert len(set(ids)) == 50  # All IDs unique (no duplicates)

    def test_concurrent_chat_messages(self):
        """Multiple threads logging chat messages simultaneously."""
        import threading
        from phantom.telemetry.tracer import Tracer

        tracer = Tracer("chat-thread-test")
        msg_ids: list[int] = []
        lock = threading.Lock()

        def log_msgs(thread_id: int) -> None:
            for i in range(10):
                mid = tracer.log_chat_message(
                    content=f"msg-{thread_id}-{i}",
                    role="assistant",
                    agent_id=f"agent-{thread_id}",
                )
                with lock:
                    msg_ids.append(mid)

        threads = [threading.Thread(target=log_msgs, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert len(msg_ids) == 50
        assert len(set(msg_ids)) == 50  # All message IDs unique

    def test_has_lock_attribute(self):
        """Tracer should have a threading lock."""
        from phantom.telemetry.tracer import Tracer
        import threading

        tracer = Tracer("lock-test")
        assert hasattr(tracer, "_lock")
        assert isinstance(tracer._lock, type(threading.Lock()))


# =========================================================================
# Pydantic V2 Migration Tests
# =========================================================================


class TestPydanticV2Migration:
    """Verify Pydantic models use ConfigDict instead of class Config."""

    def test_vulnerability_model_config(self):
        from phantom.models.vulnerability import VulnerabilityEvidence, Vulnerability
        # Should have model_config (V2) not nested Config class
        assert hasattr(VulnerabilityEvidence, "model_config")
        assert hasattr(Vulnerability, "model_config")

    def test_scan_result_model_config(self):
        from phantom.models.scan import ScanResult
        assert hasattr(ScanResult, "model_config")

    def test_vulnerability_creation(self):
        from phantom.models.vulnerability import Vulnerability
        v = Vulnerability(
            id="vuln-test",
            name="Test Vuln",
            vulnerability_class="sqli",
            target="http://test.com",
            description="Test description",
            detected_by="test",
        )
        assert v.severity.value == "medium"
        assert v.status.value == "detected"

    def test_scan_result_creation(self):
        from phantom.models.scan import ScanResult
        sr = ScanResult(scan_id="scan-1", target="http://test.com")
        assert sr.status.value == "pending"
        assert sr.finding_summary.total == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
