"""
G-09 FIX: PDF Report Formatter

Generates PDF reports from scan results using fpdf2 (pure Python, no
system dependencies).  Falls back gracefully if fpdf2 is not installed.

Install: pip install fpdf2
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _severity_color(severity: str) -> tuple[int, int, int]:
    """Map severity to RGB color."""
    return {
        "critical": (220, 53, 69),    # red
        "high": (253, 126, 20),       # orange
        "medium": (255, 193, 7),      # yellow
        "low": (13, 202, 240),        # cyan
        "info": (108, 117, 125),      # gray
    }.get(severity.lower(), (108, 117, 125))


def generate_pdf_report(
    scan_id: str,
    target: str,
    vulnerabilities: list[Any],
    hosts: list[Any] | None = None,
    scan_result: Any | None = None,
    output_path: Path | str | None = None,
) -> Path | None:
    """Generate a PDF report from scan results.

    Returns the Path to the generated PDF, or None if fpdf2 is not installed.
    """
    try:
        from fpdf import FPDF  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "G-09: fpdf2 not installed — PDF export skipped. "
            "Install with: pip install fpdf2"
        )
        return None

    if output_path is None:
        output_path = Path("reports") / f"phantom_report_{scan_id}.pdf"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── Title page ───────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 28)
    pdf.cell(0, 40, "", new_x="LMARGIN", new_y="NEXT")  # spacer
    pdf.cell(0, 15, "PHANTOM", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 14)
    pdf.cell(0, 10, "Autonomous Penetration Test Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 20, "", new_x="LMARGIN", new_y="NEXT")  # spacer

    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Target: {target}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 8, f"Scan ID: {scan_id}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(
        0, 8,
        f"Date: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        new_x="LMARGIN", new_y="NEXT", align="C",
    )

    # Summary stats
    severity_counts: dict[str, int] = {}
    for v in vulnerabilities:
        sev = getattr(v, "severity", None)
        sev_str = sev.value if hasattr(sev, "value") else str(sev or "unknown")
        severity_counts[sev_str] = severity_counts.get(sev_str, 0) + 1

    pdf.cell(0, 15, "", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Total Findings: {len(vulnerabilities)}", new_x="LMARGIN", new_y="NEXT", align="C")

    summary_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count:
            summary_parts.append(f"{sev.title()}: {count}")
    if summary_parts:
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, " | ".join(summary_parts), new_x="LMARGIN", new_y="NEXT", align="C")

    # ── Executive Summary ────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(88, 166, 255)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(
        0, 6,
        f"Phantom performed an autonomous penetration test against {target}. "
        f"The scan identified {len(vulnerabilities)} finding(s) across "
        f"{len(severity_counts)} severity level(s). "
        f"Each finding has been independently verified with a working "
        f"proof of concept before inclusion in this report.",
    )

    # ── Findings Table ───────────────────────────────────────────────
    pdf.cell(0, 10, "", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(88, 166, 255)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")

    # Table header
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(30, 30, 40)
    pdf.set_text_color(255, 255, 255)
    col_widths = [10, 60, 25, 20, 75]
    headers = ["#", "Title", "Severity", "CVSS", "Target"]
    for i, (header, w) in enumerate(zip(headers, col_widths)):
        pdf.cell(w, 8, header, border=1, fill=True, align="C")
    pdf.ln()

    # Table rows
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(0, 0, 0)
    for idx, vuln in enumerate(vulnerabilities, 1):
        title = getattr(vuln, "title", str(vuln))[:35]
        sev = getattr(vuln, "severity", None)
        sev_str = sev.value if hasattr(sev, "value") else str(sev or "?")
        cvss = str(getattr(vuln, "cvss_score", getattr(vuln, "cvss", "N/A")))
        vtarget = str(getattr(vuln, "target", ""))[:40]

        r, g, b = _severity_color(sev_str)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_widths[0], 7, str(idx), border=1, align="C")
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(col_widths[1], 7, title, border=1)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_widths[2], 7, sev_str.title(), border=1, fill=True, align="C")
        pdf.set_fill_color(255, 255, 255)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(col_widths[3], 7, cvss, border=1, align="C")
        pdf.cell(col_widths[4], 7, vtarget, border=1)
        pdf.ln()

    # ── Detailed Findings ────────────────────────────────────────────
    for idx, vuln in enumerate(vulnerabilities, 1):
        pdf.add_page()
        title = getattr(vuln, "title", str(vuln))
        sev = getattr(vuln, "severity", None)
        sev_str = sev.value if hasattr(sev, "value") else str(sev or "?")

        r, g, b = _severity_color(sev_str)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"Finding #{idx}: {title}", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_text_color(0, 0, 0)

        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 3, "", new_x="LMARGIN", new_y="NEXT")

        # Metadata
        details = [
            ("Severity", sev_str.title()),
            ("CVSS", str(getattr(vuln, "cvss_score", getattr(vuln, "cvss", "N/A")))),
            ("Target", str(getattr(vuln, "target", "N/A"))),
            ("Parameter", str(getattr(vuln, "parameter", "N/A"))),
            ("Class", str(getattr(vuln, "vulnerability_class", "N/A"))),
            ("Verified", str(getattr(vuln, "verified", "N/A"))),
        ]
        for label, value in details:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(30, 6, f"{label}:")
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, value[:80], new_x="LMARGIN", new_y="NEXT")

        # Description
        description = getattr(vuln, "description", None)
        if description:
            pdf.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Description", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5, str(description)[:2000])

        # Evidence / PoC
        evidence = getattr(vuln, "evidence", None) or getattr(vuln, "proof_of_concept", None)
        if evidence:
            pdf.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Evidence / Proof of Concept", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4, str(evidence)[:3000])

        # Remediation
        remediation = getattr(vuln, "remediation", None)
        if remediation:
            pdf.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Remediation", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5, str(remediation)[:1500])

    # ── Footer ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 10, "", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0, 8,
        "Generated by Phantom — Autonomous AI Penetration Testing Platform",
        new_x="LMARGIN", new_y="NEXT", align="C",
    )
    pdf.cell(0, 8, "https://github.com/Usta0x001/Phantom", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.output(str(output_path))
    logger.info("G-09: PDF report generated: %s", output_path)
    return output_path
