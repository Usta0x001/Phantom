"""
Tests for the Evidence Registry.

Validates:
- Evidence storage and deduplication
- Vulnerability/host indexing
- Quality filtering
- Export for reporting
"""

import pytest

from phantom.core.evidence_registry import (
    Evidence,
    EvidenceQuality,
    EvidenceRegistry,
    EvidenceType,
)


# ── Basic Operations ──


class TestEvidenceAdd:
    def test_add_evidence(self):
        reg = EvidenceRegistry()
        eid = reg.add(
            EvidenceType.SCAN_OUTPUT,
            EvidenceQuality.MODERATE,
            "nuclei_scan",
            "Found XSS at /api",
            "HTTP/1.1 200 OK\n<script>alert(1)</script>",
        )
        assert eid is not None
        assert reg.count == 1

    def test_add_with_links(self):
        reg = EvidenceRegistry()
        eid = reg.add(
            EvidenceType.HTTP_RESPONSE,
            EvidenceQuality.STRONG,
            "send_request",
            "Verified XSS",
            "response body",
            vuln_ids=["v1", "v2"],
            host="10.0.0.1",
            endpoint="/api/search",
        )
        assert eid is not None
        ev = reg.get(eid)
        assert ev.linked_vuln_ids == ["v1", "v2"]
        assert ev.linked_host == "10.0.0.1"

    def test_add_with_metadata(self):
        reg = EvidenceRegistry()
        eid = reg.add(
            EvidenceType.EXPLOITATION,
            EvidenceQuality.DEFINITIVE,
            "sqlmap_test",
            "SQLi confirmed",
            "database dumped",
            metadata={"param": "id", "technique": "error-based"},
        )
        ev = reg.get(eid)
        assert ev.metadata["param"] == "id"


# ── Deduplication ──


class TestDeduplication:
    def test_duplicate_returns_none(self):
        reg = EvidenceRegistry()
        data = "same exact evidence content"
        eid1 = reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei_scan", "First", data,
        )
        eid2 = reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei_scan", "Second", data,
        )
        assert eid1 is not None
        assert eid2 is None
        assert reg.count == 1

    def test_different_data_not_deduplicated(self):
        reg = EvidenceRegistry()
        eid1 = reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei_scan", "First", "data-1",
        )
        eid2 = reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei_scan", "Second", "data-2",
        )
        assert eid1 is not None
        assert eid2 is not None
        assert reg.count == 2


# ── Data Truncation ──


class TestTruncation:
    def test_large_data_truncated(self):
        reg = EvidenceRegistry()
        large_data = "x" * 20000
        eid = reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.WEAK,
            "nuclei_scan", "Big output", large_data,
        )
        ev = reg.get(eid)
        assert len(ev.data) < 20000
        assert "truncated" in ev.data

    def test_description_truncated(self):
        reg = EvidenceRegistry()
        long_desc = "d" * 1000
        eid = reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.WEAK,
            "tool", long_desc, "data",
        )
        ev = reg.get(eid)
        assert len(ev.description) <= 500


# ── Indexing & Querying ──


class TestQuerying:
    def test_get_for_vuln(self):
        reg = EvidenceRegistry()
        reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei_scan", "Found v1", "data-v1",
            vuln_ids=["v1"],
        )
        reg.add(
            EvidenceType.EXPLOITATION, EvidenceQuality.DEFINITIVE,
            "sqlmap", "Exploited v1", "data-v1-exploit",
            vuln_ids=["v1"],
        )
        reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.WEAK,
            "nuclei_scan", "Found v2", "data-v2",
            vuln_ids=["v2"],
        )

        v1_evidence = reg.get_for_vuln("v1")
        assert len(v1_evidence) == 2

        v2_evidence = reg.get_for_vuln("v2")
        assert len(v2_evidence) == 1

    def test_get_for_host(self):
        reg = EvidenceRegistry()
        reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nmap", "Port scan", "80/tcp open",
            host="10.0.0.1",
        )
        reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nmap", "Port scan 2", "443/tcp open",
            host="10.0.0.1",
        )

        evidence = reg.get_for_host("10.0.0.1")
        assert len(evidence) == 2

    def test_get_conclusive_evidence(self):
        reg = EvidenceRegistry()
        reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.WEAK, "t", "weak", "d1")
        reg.add(EvidenceType.EXPLOITATION, EvidenceQuality.DEFINITIVE, "t", "definitive", "d2")
        reg.add(EvidenceType.HTTP_RESPONSE, EvidenceQuality.STRONG, "t", "strong", "d3")
        reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE, "t", "moderate", "d4")

        conclusive = reg.get_conclusive_evidence()
        assert len(conclusive) == 2  # definitive + strong

    def test_has_evidence_for_vuln(self):
        reg = EvidenceRegistry()
        reg.add(
            EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
            "nuclei", "Found", "data",
            vuln_ids=["v1"],
        )
        assert reg.has_evidence_for_vuln("v1") is True
        assert reg.has_evidence_for_vuln("v2") is False


# ── Summary & Export ──


class TestSummaryExport:
    def test_summary(self):
        reg = EvidenceRegistry()
        reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE, "nmap", "scan", "d1", host="h1")
        reg.add(EvidenceType.EXPLOITATION, EvidenceQuality.DEFINITIVE, "sqlmap", "exploit", "d2", vuln_ids=["v1"])

        summary = reg.get_summary()
        assert summary["total_evidence"] == 2
        assert "scan_output" in summary["by_type"]
        assert "exploitation" in summary["by_type"]
        assert summary["linked_vulns"] == 1
        assert summary["linked_hosts"] == 1

    def test_export_for_report(self):
        reg = EvidenceRegistry()
        reg.add(EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE, "nmap", "scan", "data123")

        export = reg.export_for_report()
        assert len(export) == 1
        assert export[0]["type"] == "scan_output"
        assert export[0]["quality"] == "moderate"
        assert export[0]["data_preview"] == "data123"

    def test_export_empty(self):
        reg = EvidenceRegistry()
        assert reg.export_for_report() == []


# ── Evidence Dataclass ──


class TestEvidenceDataclass:
    def test_is_conclusive(self):
        ev = Evidence(
            id="ev-1",
            evidence_type=EvidenceType.EXPLOITATION,
            quality=EvidenceQuality.DEFINITIVE,
            source_tool="sqlmap",
            description="Confirmed",
            data="output",
        )
        assert ev.is_conclusive is True

    def test_not_conclusive(self):
        ev = Evidence(
            id="ev-2",
            evidence_type=EvidenceType.SCAN_OUTPUT,
            quality=EvidenceQuality.WEAK,
            source_tool="nuclei",
            description="Heuristic",
            data="output",
        )
        assert ev.is_conclusive is False
