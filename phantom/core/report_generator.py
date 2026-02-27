"""
Structured Report Generator

Generates comprehensive scan reports in JSON and HTML formats.
Integrates with the enhanced agent state and vulnerability models.
"""

import json
import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phantom.models.vulnerability import Vulnerability, VulnerabilitySeverity
from phantom.models.host import Host
from phantom.models.scan import ScanResult


class ReportGenerator:
    """
    Generate structured reports from scan results.
    
    Supports:
    - JSON export (machine-readable)
    - HTML export (human-readable)
    - Markdown export (documentation)
    """
    
    def __init__(self, output_dir: str | Path = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(
        self,
        scan_id: str,
        target: str,
        vulnerabilities: list[Vulnerability],
        hosts: list[Host],
        scan_result: ScanResult | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """Generate JSON report."""
        
        report = {
            "report_metadata": {
                "report_id": f"report_{scan_id}",
                "generated_at": datetime.now(UTC).isoformat(),
                "generator": "Phantom Security Scanner",
                "version": "1.0.0",
            },
            "scan_info": {
                "scan_id": scan_id,
                "target": target,
                "started_at": scan_result.started_at.isoformat() if scan_result and scan_result.started_at else None,
                "completed_at": scan_result.completed_at.isoformat() if scan_result and scan_result.completed_at else None,
                "duration_seconds": scan_result.duration_seconds() if scan_result else None,
                "status": scan_result.status.value if scan_result else "unknown",
            },
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "by_severity": self._count_by_severity(vulnerabilities),
                "verified_count": sum(1 for v in vulnerabilities if v.status.value == "verified"),
                "hosts_discovered": len(hosts),
                "unique_endpoints": len(set(v.endpoint for v in vulnerabilities if v.endpoint)),
            },
            "vulnerabilities": [
                self._vuln_to_dict(v) for v in sorted(
                    vulnerabilities,
                    key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value)
                )
            ],
            "hosts": [self._host_to_dict(h) for h in hosts],
            "metadata": metadata or {},
        }
        
        filename = self.output_dir / f"{scan_id}_report.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename
    
    def generate_html_report(
        self,
        scan_id: str,
        target: str,
        vulnerabilities: list[Vulnerability],
        hosts: list[Host],
        scan_result: ScanResult | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """Generate HTML report."""
        
        severity_counts = self._count_by_severity(vulnerabilities)
        verified_count = sum(1 for v in vulnerabilities if v.status.value == "verified")
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phantom Security Report - {html.escape(target)}</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
            --verified: #16a34a;
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --border: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }}
        h1 {{ color: #60a5fa; font-size: 2rem; margin-bottom: 0.5rem; }}
        .subtitle {{ color: #94a3b8; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }}
        .stat-value {{ font-size: 2rem; font-weight: bold; }}
        .stat-label {{ color: #94a3b8; font-size: 0.875rem; }}
        .stat.critical .stat-value {{ color: var(--critical); }}
        .stat.high .stat-value {{ color: var(--high); }}
        .stat.medium .stat-value {{ color: var(--medium); }}
        .stat.low .stat-value {{ color: var(--low); }}
        .stat.verified .stat-value {{ color: var(--verified); }}
        section {{ margin-bottom: 2rem; }}
        h2 {{
            color: #60a5fa;
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .vuln-card {{
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }}
        .vuln-title {{ font-size: 1.125rem; font-weight: 600; }}
        .severity {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity.critical {{ background: var(--critical); color: white; }}
        .severity.high {{ background: var(--high); color: white; }}
        .severity.medium {{ background: var(--medium); color: black; }}
        .severity.low {{ background: var(--low); color: white; }}
        .severity.info {{ background: var(--info); color: white; }}
        .verified-badge {{
            background: var(--verified);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-left: 0.5rem;
        }}
        .vuln-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
        }}
        .meta-item {{ color: #94a3b8; }}
        .meta-item strong {{ color: var(--text); }}
        .description {{ margin-bottom: 1rem; }}
        .code-block {{
            background: #0d1117;
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 1rem;
            overflow-x: auto;
            font-family: 'Fira Code', monospace;
            font-size: 0.875rem;
            margin-top: 0.5rem;
        }}
        .evidence {{ margin-top: 1rem; }}
        .evidence-title {{ font-weight: 600; margin-bottom: 0.5rem; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{ color: #94a3b8; font-weight: 600; }}
        .footer {{
            text-align: center;
            color: #64748b;
            font-size: 0.875rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Phantom Security Report</h1>
            <p class="subtitle">Target: {html.escape(target)}</p>
            <p class="subtitle">Scan ID: {html.escape(scan_id)} | Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}</p>
        </header>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{len(vulnerabilities)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat critical">
                <div class="stat-value">{severity_counts.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat high">
                <div class="stat-value">{severity_counts.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat medium">
                <div class="stat-value">{severity_counts.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat low">
                <div class="stat-value">{severity_counts.get('low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat verified">
                <div class="stat-value">{verified_count}</div>
                <div class="stat-label">Verified</div>
            </div>
        </div>
        
        <section>
            <h2>Vulnerabilities</h2>
            {self._generate_vuln_cards_html(vulnerabilities)}
        </section>
        
        <section>
            <h2>Discovered Hosts ({len(hosts)})</h2>
            {self._generate_hosts_table_html(hosts)}
        </section>
        
        <footer class="footer">
            <p>Generated by Phantom Security Scanner</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </footer>
    </div>
</body>
</html>"""
        
        filename = self.output_dir / f"{scan_id}_report.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return filename
    
    def generate_markdown_report(
        self,
        scan_id: str,
        target: str,
        vulnerabilities: list[Vulnerability],
        hosts: list[Host],
        scan_result: ScanResult | None = None,
    ) -> Path:
        """Generate Markdown report."""
        
        severity_counts = self._count_by_severity(vulnerabilities)
        verified_count = sum(1 for v in vulnerabilities if v.status.value == "verified")
        
        lines = [
            f"# Phantom Security Report",
            f"",
            f"**Target:** {target}",
            f"**Scan ID:** {scan_id}",
            f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | {len(vulnerabilities)} |",
            f"| Critical | {severity_counts.get('critical', 0)} |",
            f"| High | {severity_counts.get('high', 0)} |",
            f"| Medium | {severity_counts.get('medium', 0)} |",
            f"| Low | {severity_counts.get('low', 0)} |",
            f"| Verified | {verified_count} |",
            f"| Hosts Discovered | {len(hosts)} |",
            f"",
            f"## Vulnerabilities",
            f"",
        ]
        
        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value)
        )
        
        for vuln in sorted_vulns:
            status_badge = "✅ VERIFIED" if vuln.status.value == "verified" else ""
            
            lines.extend([
                f"### {vuln.name} [{vuln.severity.value.upper()}] {status_badge}",
                f"",
                f"**ID:** `{vuln.id}`",
                f"**Target:** `{vuln.target}`",
                f"**Class:** {vuln.vulnerability_class}",
                f"",
                f"{vuln.description}",
                f"",
            ])
            
            if vuln.payload:
                lines.extend([
                    f"**Payload:**",
                    f"```",
                    f"{vuln.payload}",
                    f"```",
                    f"",
                ])
            
            if vuln.remediation:
                lines.extend([
                    f"**Remediation:** {vuln.remediation}",
                    f"",
                ])
            
            lines.append("---")
            lines.append("")
        
        lines.extend([
            f"## Discovered Hosts",
            f"",
            f"| IP | Hostname | OS | Open Ports |",
            f"|----|---------|----|------------|",
        ])
        
        for host in hosts:
            ports = ", ".join(str(p.number) for p in host.ports[:5])
            if len(host.ports) > 5:
                ports += f" (+{len(host.ports) - 5} more)"
            
            lines.append(f"| {host.ip} | {host.hostname or '-'} | {host.os or '-'} | {ports} |")
        
        lines.extend([
            f"",
            f"---",
            f"*Report generated by Phantom Security Scanner*",
        ])
        
        content = "\n".join(lines)
        
        filename = self.output_dir / f"{scan_id}_report.md"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        
        return filename
    
    def _count_by_severity(self, vulns: list[Vulnerability]) -> dict[str, int]:
        """Count vulnerabilities by severity."""
        counts: dict[str, int] = {}
        for v in vulns:
            sev = v.severity.value.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _vuln_to_dict(self, vuln: Vulnerability) -> dict[str, Any]:
        """Convert vulnerability to dict for JSON export."""
        return {
            "id": vuln.id,
            "name": vuln.name,
            "class": vuln.vulnerability_class,
            "severity": vuln.severity.value,
            "status": vuln.status.value,
            "cvss_score": vuln.cvss_score,
            "target": vuln.target,
            "endpoint": vuln.endpoint,
            "parameter": vuln.parameter,
            "method": vuln.method,
            "description": vuln.description,
            "payload": vuln.payload,
            "evidence": [
                {
                    "type": e.type,
                    "description": e.description,
                    "data": e.data[:1000],  # Truncate
                }
                for e in vuln.evidence
            ],
            "cve_ids": vuln.cve_ids,
            "cwe_ids": vuln.cwe_ids,
            "references": vuln.references,
            "remediation": vuln.remediation,
            "detected_by": vuln.detected_by,
            "detected_at": vuln.detected_at.isoformat(),
            "verified_by": vuln.verified_by,
            "verified_at": vuln.verified_at.isoformat() if vuln.verified_at else None,
        }
    
    def _host_to_dict(self, host: Host) -> dict[str, Any]:
        """Convert host to dict for JSON export."""
        return {
            "ip": host.ip,
            "hostname": host.hostname,
            "hostnames": host.hostnames,
            "os": host.os,
            "ports": [
                {
                    "number": p.number,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                }
                for p in host.ports
            ],
            "technologies": [
                {"name": t.name, "version": t.version}
                for t in host.technologies
            ],
            "vulnerability_count": len(host.vulnerability_ids),
        }
    
    def _generate_vuln_cards_html(self, vulns: list[Vulnerability]) -> str:
        """Generate HTML cards for vulnerabilities."""
        if not vulns:
            return "<p>No vulnerabilities found.</p>"
        
        cards = []
        sorted_vulns = sorted(
            vulns,
            key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value)
        )
        
        for vuln in sorted_vulns:
            verified_badge = '<span class="verified-badge">✓ VERIFIED</span>' if vuln.status.value == "verified" else ""
            
            payload_block = ""
            if vuln.payload:
                payload_block = f'''
                <div class="evidence">
                    <div class="evidence-title">Payload</div>
                    <div class="code-block">{html.escape(vuln.payload)}</div>
                </div>'''
            
            card = f'''
            <div class="vuln-card">
                <div class="vuln-header">
                    <div>
                        <span class="vuln-title">{html.escape(vuln.name)}</span>
                        {verified_badge}
                    </div>
                    <span class="severity {vuln.severity.value}">{vuln.severity.value}</span>
                </div>
                <div class="vuln-meta">
                    <div class="meta-item"><strong>ID:</strong> {html.escape(vuln.id)}</div>
                    <div class="meta-item"><strong>Class:</strong> {html.escape(vuln.vulnerability_class)}</div>
                    <div class="meta-item"><strong>Target:</strong> {html.escape(vuln.target)}</div>
                    <div class="meta-item"><strong>Detected by:</strong> {html.escape(vuln.detected_by)}</div>
                </div>
                <div class="description">{html.escape(vuln.description)}</div>
                {payload_block}
            </div>'''
            
            cards.append(card)
        
        return "\n".join(cards)
    
    def _generate_hosts_table_html(self, hosts: list[Host]) -> str:
        """Generate HTML table for hosts."""
        if not hosts:
            return "<p>No hosts discovered.</p>"
        
        rows = []
        for host in hosts:
            ports = ", ".join(str(p.number) for p in host.ports[:8])
            if len(host.ports) > 8:
                ports += f" (+{len(host.ports) - 8})"
            
            techs = ", ".join(t.name for t in host.technologies[:5])
            
            rows.append(f'''
            <tr>
                <td>{html.escape(host.ip)}</td>
                <td>{html.escape(host.hostname or '-')}</td>
                <td>{html.escape(host.os or '-')}</td>
                <td>{ports or '-'}</td>
                <td>{html.escape(techs) or '-'}</td>
            </tr>''')
        
        return f'''
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>OS</th>
                    <th>Open Ports</th>
                    <th>Technologies</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>'''


def generate_all_reports(
    scan_id: str,
    target: str,
    vulnerabilities: list[Vulnerability],
    hosts: list[Host],
    scan_result: ScanResult | None = None,
    output_dir: str = "reports",
) -> dict[str, Path]:
    """
    Generate all report formats at once.
    
    Returns dict of format -> filepath.
    """
    generator = ReportGenerator(output_dir)
    
    return {
        "json": generator.generate_json_report(scan_id, target, vulnerabilities, hosts, scan_result),
        "html": generator.generate_html_report(scan_id, target, vulnerabilities, hosts, scan_result),
        "markdown": generator.generate_markdown_report(scan_id, target, vulnerabilities, hosts, scan_result),
    }
