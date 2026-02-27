"""Differential scanning — compare two Phantom scan runs to identify new,
fixed, and persistent vulnerabilities.

Usage::

    from phantom.core.diff_scanner import DiffScanner

    diff = DiffScanner("phantom_runs/run_a", "phantom_runs/run_b")
    report = diff.compare()
    print(diff.to_markdown(report))
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class VulnFingerprint:
    """Lightweight identity for dedup / matching."""

    title: str
    severity: str
    endpoint: str
    method: str
    cve: str

    @classmethod
    def from_report(cls, rpt: dict[str, Any]) -> "VulnFingerprint":
        return cls(
            title=(rpt.get("title") or "").strip().lower(),
            severity=(rpt.get("severity") or "info").strip().lower(),
            endpoint=(rpt.get("endpoint") or "").strip(),
            method=(rpt.get("method") or "").strip().upper(),
            cve=(rpt.get("cve") or "").strip(),
        )

    @property
    def key(self) -> str:
        """Stable identity string for diffing."""
        return f"{self.title}|{self.endpoint}|{self.method}|{self.cve}"


@dataclass
class DiffReport:
    """Result of comparing two scan runs."""

    baseline_run: str
    current_run: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    new_vulns: list[dict[str, Any]] = field(default_factory=list)
    fixed_vulns: list[dict[str, Any]] = field(default_factory=list)
    persistent_vulns: list[dict[str, Any]] = field(default_factory=list)
    severity_delta: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_run": self.baseline_run,
            "current_run": self.current_run,
            "timestamp": self.timestamp,
            "new_vulns": self.new_vulns,
            "fixed_vulns": self.fixed_vulns,
            "persistent_vulns": self.persistent_vulns,
            "severity_delta": self.severity_delta,
            "summary": {
                "new": len(self.new_vulns),
                "fixed": len(self.fixed_vulns),
                "persistent": len(self.persistent_vulns),
            },
        }


class DiffScanner:
    """Compare two Phantom scan runs and produce a diff report.

    Parameters:
        baseline_path:  Path to the *older* (reference) run directory.
        current_path:   Path to the *newer* run directory.
    """

    def __init__(
        self,
        baseline_path: str | Path,
        current_path: str | Path,
    ) -> None:
        self.baseline_path = Path(baseline_path)
        self.current_path = Path(current_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compare(self) -> DiffReport:
        """Run the diff and return a structured ``DiffReport``."""
        base_vulns = self._load_vulns(self.baseline_path)
        curr_vulns = self._load_vulns(self.current_path)

        base_map = {VulnFingerprint.from_report(v).key: v for v in base_vulns}
        curr_map = {VulnFingerprint.from_report(v).key: v for v in curr_vulns}

        base_keys = set(base_map)
        curr_keys = set(curr_map)

        new_keys = curr_keys - base_keys
        fixed_keys = base_keys - curr_keys
        persist_keys = base_keys & curr_keys

        report = DiffReport(
            baseline_run=self.baseline_path.name,
            current_run=self.current_path.name,
            new_vulns=[curr_map[k] for k in sorted(new_keys)],
            fixed_vulns=[base_map[k] for k in sorted(fixed_keys)],
            persistent_vulns=[curr_map[k] for k in sorted(persist_keys)],
        )

        # Severity delta
        for sev in ("critical", "high", "medium", "low", "info"):
            base_count = sum(
                1
                for v in base_vulns
                if (v.get("severity") or "info").lower() == sev
            )
            curr_count = sum(
                1
                for v in curr_vulns
                if (v.get("severity") or "info").lower() == sev
            )
            report.severity_delta[sev] = curr_count - base_count

        return report

    # ------------------------------------------------------------------
    # Markdown output
    # ------------------------------------------------------------------

    @staticmethod
    def to_markdown(report: DiffReport) -> str:
        """Render a human-readable markdown diff report."""
        lines: list[str] = [
            "# Differential Scan Report",
            "",
            f"**Baseline:** `{report.baseline_run}`  ",
            f"**Current:**  `{report.current_run}`  ",
            f"**Generated:** {report.timestamp}",
            "",
            "## Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| New vulnerabilities | {len(report.new_vulns)} |",
            f"| Fixed vulnerabilities | {len(report.fixed_vulns)} |",
            f"| Persistent vulnerabilities | {len(report.persistent_vulns)} |",
            "",
            "### Severity Delta (current vs baseline)",
            "",
            "| Severity | Change |",
            "|----------|--------|",
        ]
        for sev, delta in report.severity_delta.items():
            sign = "+" if delta > 0 else ""
            lines.append(f"| {sev.capitalize()} | {sign}{delta} |")

        if report.new_vulns:
            lines += ["", "## New Vulnerabilities", ""]
            for v in report.new_vulns:
                lines.append(
                    f"- **[{(v.get('severity') or 'info').upper()}]** "
                    f"{v.get('title', 'Untitled')} — `{v.get('endpoint', 'N/A')}`"
                )

        if report.fixed_vulns:
            lines += ["", "## Fixed Vulnerabilities", ""]
            for v in report.fixed_vulns:
                lines.append(
                    f"- ~~**[{(v.get('severity') or 'info').upper()}]** "
                    f"{v.get('title', 'Untitled')} — `{v.get('endpoint', 'N/A')}`~~"
                )

        if report.persistent_vulns:
            lines += ["", "## Persistent Vulnerabilities", ""]
            for v in report.persistent_vulns:
                lines.append(
                    f"- **[{(v.get('severity') or 'info').upper()}]** "
                    f"{v.get('title', 'Untitled')} — `{v.get('endpoint', 'N/A')}`"
                )

        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def save_json(self, report: DiffReport, output_path: str | Path) -> Path:
        """Write the diff report as JSON."""
        out = Path(output_path)
        out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_vulns(self, run_dir: Path) -> list[dict[str, Any]]:
        """Load vulnerability data from a run directory.

        Tries three sources in priority order:
        1. ``results.sarif`` → extract SARIF results
        2. ``vulnerabilities.csv``
        3. ``penetration_test_report.md`` (parse titles / severity from headers)
        """
        # SARIF
        sarif_path = run_dir / "results.sarif"
        if sarif_path.exists():
            return self._parse_sarif(sarif_path)

        # CSV (written by Tracer)
        csv_path = run_dir / "vulnerabilities.csv"
        if csv_path.exists():
            return self._parse_csv(csv_path)

        # Markdown vuln files
        vuln_dir = run_dir / "vulnerabilities"
        if vuln_dir.is_dir():
            return self._parse_vuln_dir(vuln_dir)

        return []

    @staticmethod
    def _parse_sarif(path: Path) -> list[dict[str, Any]]:
        # Map SARIF levels to Phantom severity
        _SARIF_LEVEL_MAP = {
            "error": "high",
            "warning": "medium",
            "note": "low",
            "none": "info",
        }
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            results: list[dict[str, Any]] = []
            for run in data.get("runs", []):
                for r in run.get("results", []):
                    sarif_level = r.get("level", "note")
                    results.append(
                        {
                            "title": r.get("message", {}).get("text", ""),
                            "severity": _SARIF_LEVEL_MAP.get(sarif_level, "info"),
                            "endpoint": (
                                r.get("locations", [{}])[0]
                                .get("physicalLocation", {})
                                .get("artifactLocation", {})
                                .get("uri", "")
                                if r.get("locations")
                                else ""
                            ),
                            "method": "",
                            "cve": "",
                        }
                    )
            return results
        except (json.JSONDecodeError, KeyError):
            return []

    @staticmethod
    def _parse_csv(path: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            with path.open(encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    results.append(
                        {
                            "title": row.get("title", ""),
                            "severity": row.get("severity", "info"),
                            "endpoint": row.get("endpoint", ""),
                            "method": row.get("method", ""),
                            "cve": row.get("cve", ""),
                        }
                    )
        except (csv.Error, UnicodeDecodeError):
            pass
        return results

    @staticmethod
    def _parse_vuln_dir(vuln_dir: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for md_file in sorted(vuln_dir.glob("*.md")):
            try:
                text = md_file.read_text(encoding="utf-8")
                title = ""
                severity = "info"
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("# ") and not title:
                        title = stripped[2:].strip()
                    if "severity" in stripped.lower() and ":" in stripped:
                        sev_val = stripped.split(":", 1)[1].strip().lower()
                        if sev_val in ("critical", "high", "medium", "low", "info"):
                            severity = sev_val
                results.append(
                    {
                        "title": title,
                        "severity": severity,
                        "endpoint": "",
                        "method": "",
                        "cve": "",
                    }
                )
            except UnicodeDecodeError:
                continue
        return results
