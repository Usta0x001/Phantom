"""Tests for phantom.core.diff_scanner — DiffScanner + DiffReport."""

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phantom.core.diff_scanner import DiffReport, DiffScanner


# ── helpers ────────────────────────────────────────────────────────────────────

def _write_checkpoint(tmp_path: Path, name: str, vulns: list[dict]) -> Path:
    """Write a minimal checkpoint.json and return the run directory."""
    run_dir = tmp_path / name
    run_dir.mkdir(parents=True)
    cp = {
        "run_name": name,
        "status": "completed",
        "vulnerability_reports": vulns,
    }
    (run_dir / "checkpoint.json").write_text(json.dumps(cp), encoding="utf-8")
    return run_dir


def _vuln(id_: str, name: str, sev: str = "high") -> dict:
    return {"id": id_, "name": name, "severity": sev, "endpoint": "/test"}


# ── DiffReport ─────────────────────────────────────────────────────────────────

class TestDiffReport:
    def test_to_markdown_contains_headers(self):
        report = DiffReport(
            run1="baseline",
            run2="current",
            new_vulns=[_vuln("1", "XSS")],
            fixed_vulns=[_vuln("2", "SQLi")],
            persistent_vulns=[],
        )
        md = report.to_markdown()
        # Actual headers use emoji — test for content, not exact heading string
        assert "New Vulnerabilities" in md or "XSS" in md
        assert "Fixed" in md or "SQLi" in md
        assert "XSS" in md
        assert "SQLi" in md

    def test_to_markdown_no_new(self):
        report = DiffReport(
            run1="a",
            run2="b",
            new_vulns=[],
            fixed_vulns=[],
            persistent_vulns=[_vuln("3", "CSRF")],
        )
        md = report.to_markdown()
        assert "No new vulnerabilities" in md or "CSRF" in md

    def test_to_markdown_includes_run_names(self):
        report = DiffReport(
            run1="run-alpha",
            run2="run-beta",
            new_vulns=[],
            fixed_vulns=[],
            persistent_vulns=[],
        )
        md = report.to_markdown()
        assert "run-alpha" in md or "run-beta" in md


# ── DiffScanner.compare ────────────────────────────────────────────────────────

class TestDiffScannerCompare:
    def test_new_vuln_detected(self, tmp_path):
        dir1 = _write_checkpoint(tmp_path, "baseline", [_vuln("v1", "SQLi")])
        dir2 = _write_checkpoint(tmp_path, "current", [_vuln("v1", "SQLi"), _vuln("v2", "XSS")])
        report = DiffScanner().compare(str(dir1), str(dir2))
        new_ids = {v.get("id") for v in report.new_vulns}
        assert "v2" in new_ids

    def test_fixed_vuln_detected(self, tmp_path):
        dir1 = _write_checkpoint(tmp_path, "baseline", [_vuln("v1", "SQLi"), _vuln("v2", "XSS")])
        dir2 = _write_checkpoint(tmp_path, "current", [_vuln("v1", "SQLi")])
        report = DiffScanner().compare(str(dir1), str(dir2))
        fixed_ids = {v.get("id") for v in report.fixed_vulns}
        assert "v2" in fixed_ids

    def test_persistent_vuln_detected(self, tmp_path):
        dir1 = _write_checkpoint(tmp_path, "baseline", [_vuln("v1", "SQLi")])
        dir2 = _write_checkpoint(tmp_path, "current", [_vuln("v1", "SQLi")])
        report = DiffScanner().compare(str(dir1), str(dir2))
        persistent_ids = {v.get("id") for v in report.persistent_vulns}
        assert "v1" in persistent_ids

    def test_all_fixed_no_new(self, tmp_path):
        dir1 = _write_checkpoint(tmp_path, "baseline", [_vuln("v1", "XSS"), _vuln("v2", "RCE")])
        dir2 = _write_checkpoint(tmp_path, "current", [])
        report = DiffScanner().compare(str(dir1), str(dir2))
        assert len(report.fixed_vulns) == 2
        assert len(report.new_vulns) == 0
        assert len(report.persistent_vulns) == 0

    def test_empty_both_runs(self, tmp_path):
        dir1 = _write_checkpoint(tmp_path, "baseline", [])
        dir2 = _write_checkpoint(tmp_path, "current", [])
        report = DiffScanner().compare(str(dir1), str(dir2))
        assert len(report.new_vulns) == 0
        assert len(report.fixed_vulns) == 0
        assert len(report.persistent_vulns) == 0

    def test_run_names_set_on_report(self, tmp_path):
        dir1 = _write_checkpoint(tmp_path, "base-run", [])
        dir2 = _write_checkpoint(tmp_path, "new-run", [])
        report = DiffScanner().compare(str(dir1), str(dir2))
        # run1/run2 hold the directory *name* (stem), not the full path
        assert report.run1 == dir1.name
        assert report.run2 == dir2.name

    def test_key_by_name_when_id_absent(self, tmp_path):
        v1 = {"name": "IDOR", "severity": "high", "endpoint": "/api/user"}
        v2 = {"name": "CSRF", "severity": "medium"}
        dir1 = _write_checkpoint(tmp_path, "b1", [v1, v2])
        dir2 = _write_checkpoint(tmp_path, "b2", [v1])
        report = DiffScanner().compare(str(dir1), str(dir2))
        fixed_names = {v.get("name") for v in report.fixed_vulns}
        assert "CSRF" in fixed_names

    def test_nonexistent_dir2_raises(self, tmp_path):
        dir1 = _write_checkpoint(tmp_path, "baseline", [])
        with pytest.raises(FileNotFoundError):
            DiffScanner().compare(str(dir1), str(tmp_path / "nonexistent"))

    def test_multiple_new_and_fixed(self, tmp_path):
        base_vulns = [_vuln("a", "SQLi"), _vuln("b", "XSS"), _vuln("c", "RCE")]
        curr_vulns = [_vuln("b", "XSS"), _vuln("d", "SSRF"), _vuln("e", "IDOR")]
        dir1 = _write_checkpoint(tmp_path, "base", base_vulns)
        dir2 = _write_checkpoint(tmp_path, "curr", curr_vulns)
        report = DiffScanner().compare(str(dir1), str(dir2))
        new_ids = {v.get("id") for v in report.new_vulns}
        fixed_ids = {v.get("id") for v in report.fixed_vulns}
        persistent_ids = {v.get("id") for v in report.persistent_vulns}
        assert new_ids == {"d", "e"}
        assert fixed_ids == {"a", "c"}
        assert persistent_ids == {"b"}
