"""
Phantom diff scanner — compares two scan runs and highlights new / fixed /
persistent vulnerabilities.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _load_vulns(run_dir: str | Path) -> list[dict[str, Any]]:
    """
    Load vulnerability reports from a phantom run directory.

    Works with both checkpoint.json (has vulnerability_reports key) and any
    top-level *.json files that look like scan report data.
    """
    run_path = Path(run_dir)

    # Prefer checkpoint.json — it always carries the canonical vuln list
    cp_file = run_path / "checkpoint.json"
    if cp_file.exists():
        try:
            data = json.loads(cp_file.read_text(encoding="utf-8"))
            vulns = data.get("vulnerability_reports", [])
            if isinstance(vulns, list):
                return vulns
        except Exception:
            pass

    # Fallback: scan any *.json file for a vulnerabilities / findings key
    for json_file in sorted(run_path.glob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            for key in ("vulnerability_reports", "vulnerabilities", "findings"):
                if isinstance(data.get(key), list):
                    return data[key]
        except Exception:
            continue

    return []


def _vuln_key(v: dict[str, Any]) -> str:
    """Deterministic identity key for a vulnerability (used for diff matching)."""
    name = str(v.get("name", v.get("title", ""))).strip().lower()
    endpoint = str(v.get("endpoint", v.get("url", ""))).strip().lower()
    sev = str(v.get("severity", "info")).strip().lower()
    # Use id field if present (Phantom assigns stable UUIDs)
    vid = str(v.get("id", "")).strip()
    if vid:
        return vid
    return f"{name}|{endpoint}|{sev}"


@dataclass
class DiffReport:
    run1: str
    run2: str
    new_vulns: list[dict[str, Any]] = field(default_factory=list)
    fixed_vulns: list[dict[str, Any]] = field(default_factory=list)
    persistent_vulns: list[dict[str, Any]] = field(default_factory=list)

    # ── Summary helpers ───────────────────────────────────────────────────

    def _sev_badge(self, v: dict[str, Any]) -> str:
        sev_map = {
            "critical": "🔴 CRITICAL",
            "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM",
            "low": "🟢 LOW",
            "info": "🔵 INFO",
        }
        sev = str(v.get("severity", "info")).lower()
        return sev_map.get(sev, sev.upper())

    def _vuln_summary(self, v: dict[str, Any]) -> str:
        name = v.get("name", v.get("title", "Unknown"))
        endpoint = v.get("endpoint", v.get("url", ""))
        sev = self._sev_badge(v)
        line = f"- [{sev}] **{name}**"
        if endpoint:
            line += f" → `{endpoint}`"
        return line

    def to_markdown(self) -> str:
        lines = [
            f"# Phantom Diff Report",
            f"",
            f"| | Value |",
            f"|---|---|",
            f"| Baseline | `{self.run1}` |",
            f"| Current  | `{self.run2}` |",
            f"| New vulnerabilities | **{len(self.new_vulns)}** |",
            f"| Fixed vulnerabilities | **{len(self.fixed_vulns)}** |",
            f"| Persistent | **{len(self.persistent_vulns)}** |",
            f"",
        ]

        if self.new_vulns:
            lines += ["## 🆕 New Vulnerabilities (introduced in current scan)", ""]
            for v in self.new_vulns:
                lines.append(self._vuln_summary(v))
            lines.append("")

        if self.fixed_vulns:
            lines += ["## ✅ Fixed Vulnerabilities (present in baseline, gone now)", ""]
            for v in self.fixed_vulns:
                lines.append(self._vuln_summary(v))
            lines.append("")

        if self.persistent_vulns:
            lines += ["## ⚠️ Persistent Vulnerabilities (not yet remediated)", ""]
            for v in self.persistent_vulns:
                lines.append(self._vuln_summary(v))
            lines.append("")

        if not any([self.new_vulns, self.fixed_vulns, self.persistent_vulns]):
            lines += ["_No differences found between the two runs._", ""]

        return "\n".join(lines)

    def __str__(self) -> str:
        return self.to_markdown()


class DiffScanner:
    """Compare two Phantom scan run directories."""

    def compare(self, run_dir1: str, run_dir2: str) -> DiffReport:
        vulns1 = _load_vulns(run_dir1)
        vulns2 = _load_vulns(run_dir2)

        keys1 = {_vuln_key(v): v for v in vulns1}
        keys2 = {_vuln_key(v): v for v in vulns2}

        new_vulns = [v for k, v in keys2.items() if k not in keys1]
        fixed_vulns = [v for k, v in keys1.items() if k not in keys2]
        persistent_vulns = [v for k, v in keys1.items() if k in keys2]

        return DiffReport(
            run1=Path(run_dir1).name,
            run2=Path(run_dir2).name,
            new_vulns=new_vulns,
            fixed_vulns=fixed_vulns,
            persistent_vulns=persistent_vulns,
        )
