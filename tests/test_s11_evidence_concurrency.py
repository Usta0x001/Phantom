"""Test Suite 3: Evidence Registry Concurrency (T1-05, T1-06, DEFECT-ER-001/002)."""
import threading
import time
import pytest
from phantom.core.evidence_registry import EvidenceRegistry, EvidenceType, EvidenceQuality


class TestLockCoverage:
    """All read methods should be protected by _lock."""

    def test_get_conclusive_evidence_locked(self, evidence_registry):
        errors = []

        def writer():
            for i in range(50):
                evidence_registry.add(
                    EvidenceType.SCAN_OUTPUT, EvidenceQuality.STRONG,
                    f"tool_{i}", f"desc_{i}", f"data_{i}_{time.monotonic()}",
                    vuln_ids=[f"v-{i}"],
                )

        def reader():
            for _ in range(50):
                try:
                    result = evidence_registry.get_conclusive_evidence()
                    assert isinstance(result, list)
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors, f"Concurrent access errors: {errors}"

    def test_export_for_report_locked(self, evidence_registry):
        errors = []

        def writer():
            for i in range(100):
                evidence_registry.add(
                    EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                    "tool", f"desc_{i}", f"unique_data_{i}_{time.monotonic()}",
                )

        def reader():
            for _ in range(50):
                try:
                    report = evidence_registry.export_for_report()
                    for entry in report:
                        assert "id" in entry
                        assert "type" in entry
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(3)]
        threads += [threading.Thread(target=reader) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        assert not errors, f"Detected {len(errors)} errors: {errors[:3]}"

    def test_count_property_locked(self, evidence_registry):
        results = []

        def writer():
            for i in range(100):
                evidence_registry.add(
                    EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                    "tool", "desc", f"data_{i}_{time.monotonic()}",
                )

        def reader():
            for _ in range(100):
                c = evidence_registry.count
                results.append(c)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        assert all(isinstance(c, int) and c >= 0 for c in results)

    def test_get_summary_locked(self, evidence_registry):
        errors = []

        def writer():
            for i in range(50):
                evidence_registry.add(
                    EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                    "tool", "desc", f"summary_data_{i}_{time.monotonic()}",
                )

        def reader():
            for _ in range(50):
                try:
                    s = evidence_registry.get_summary()
                    assert "total_evidence" in s
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors, f"get_summary errors: {errors}"


class TestTOCTOURace:
    """T1-06: Hash computation inside lock prevents duplicate entries."""

    def test_no_duplicates_under_contention(self, evidence_registry):
        duplicate_data = "IDENTICAL_EVIDENCE_PAYLOAD_FOR_TOCTOU_TEST"
        results = []

        def add_same():
            eid = evidence_registry.add(
                EvidenceType.SCAN_OUTPUT, EvidenceQuality.STRONG,
                "nuclei", "same finding", duplicate_data,
            )
            results.append(eid)

        threads = [threading.Thread(target=add_same) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        non_none = [r for r in results if r is not None]
        assert len(non_none) == 1, (
            f"Expected 1 non-duplicate, got {len(non_none)}. TOCTOU race may exist."
        )


class TestStressConcurrency:
    def test_10_writers_5_readers_no_crash(self, evidence_registry):
        errors = []

        def writer(wid):
            for i in range(50):
                try:
                    evidence_registry.add(
                        EvidenceType.SCAN_OUTPUT, EvidenceQuality.MODERATE,
                        f"tool_{wid}", f"finding_{i}",
                        f"data_w{wid}_i{i}_{time.monotonic()}",
                        vuln_ids=[f"vuln-{i % 10}"],
                        host=f"host-{i % 5}",
                    )
                except Exception as e:
                    errors.append(("write", wid, i, e))

        def reader(rid):
            for _ in range(100):
                try:
                    evidence_registry.count
                    evidence_registry.get_summary()
                    evidence_registry.export_for_report()
                    evidence_registry.get_conclusive_evidence()
                except Exception as e:
                    errors.append(("read", rid, e))

        threads = [threading.Thread(target=writer, args=(w,)) for w in range(10)]
        threads += [threading.Thread(target=reader, args=(r,)) for r in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not errors, f"Stress test produced {len(errors)} errors: {errors[:5]}"
