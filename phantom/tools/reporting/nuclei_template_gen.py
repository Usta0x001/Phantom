"""
Nuclei Template Generator - P2.2

Generates Nuclei YAML templates from discovered vulnerabilities.
These templates can be used to:
- Reproduce findings in future scans
- Share vulnerability fingerprints with the community
- Create regression tests
- Automate validation of fixes
"""

from __future__ import annotations

import re
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


class NucleiTemplateGenerator:
    """Generate Nuclei YAML templates from vulnerability reports."""

    # Map vulnerability classes to Nuclei template types
    VULN_CLASS_TO_TEMPLATE_TYPE = {
        "sqli": "http",
        "xss": "http",
        "xxe": "http",
        "ssrf": "http",
        "ssti": "http",
        "lfi": "http",
        "rfi": "http",
        "rce": "http",
        "cmd_injection": "http",
        "idor": "http",
        "auth_bypass": "http",
        "path_traversal": "http",
        "open_redirect": "http",
        "crlf": "http",
        "csrf": "http",
    }

    # Map vulnerability classes to severity
    VULN_CLASS_TO_DEFAULT_SEVERITY = {
        "sqli": "high",
        "rce": "critical",
        "cmd_injection": "critical",
        "xxe": "high",
        "ssti": "critical",
        "ssrf": "high",
        "lfi": "high",
        "rfi": "critical",
        "xss": "medium",
        "idor": "medium",
        "auth_bypass": "critical",
        "path_traversal": "high",
        "open_redirect": "low",
        "crlf": "medium",
        "csrf": "medium",
    }

    def __init__(self, author: str = "Phantom AI", tags: list[str] | None = None):
        """
        Initialize the template generator.
        
        Args:
            author: Template author name
            tags: Default tags to add to all templates
        """
        self.author = author
        self.default_tags = tags or ["phantom-generated"]

    def generate_from_vulnerability(
        self,
        vuln: Any,
        request_data: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate a Nuclei template from a vulnerability object.
        
        Args:
            vuln: Vulnerability object with id, title, severity, etc.
            request_data: Optional HTTP request details (method, path, headers, body, etc.)
            
        Returns:
            YAML template as string
        """
        # Extract basic info
        vuln_id = getattr(vuln, "id", "unknown")
        title = getattr(vuln, "title", "Unknown Vulnerability")
        severity = self._get_severity(vuln)
        description = getattr(vuln, "description", "")
        evidence = getattr(vuln, "evidence", [])
        metadata = getattr(vuln, "metadata", {})
        
        # Extract vulnerability class from metadata
        vuln_class = metadata.get("vuln_class", "").lower()
        
        # Determine template type
        template_type = self.VULN_CLASS_TO_TEMPLATE_TYPE.get(
            vuln_class, "http"
        )
        
        # Generate template ID from vuln_id
        template_id = self._generate_template_id(vuln_id, vuln_class)
        
        # Build template structure
        template = {
            "id": template_id,
            "info": {
                "name": title,
                "author": self.author,
                "severity": severity,
                "description": description or title,
                "tags": self._generate_tags(vuln_class),
                "metadata": {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "vulnerability_id": vuln_id,
                },
            },
        }
        
        # Add CVE references if available
        if "cve" in metadata:
            template["info"]["reference"] = [metadata["cve"]]
        
        # Generate HTTP request section
        if template_type == "http":
            http_section = self._generate_http_section(
                vuln_class=vuln_class,
                request_data=request_data,
                evidence=evidence,
                metadata=metadata,
            )
            template["http"] = [http_section]
        
        # Convert to YAML
        return self._to_yaml(template)

    def _get_severity(self, vuln: Any) -> str:
        """Extract severity from vulnerability object."""
        severity = getattr(vuln, "severity", None)
        if severity:
            if hasattr(severity, "value"):
                return severity.value
            return str(severity).lower()
        return "medium"

    def _generate_template_id(self, vuln_id: str, vuln_class: str) -> str:
        """Generate a template ID."""
        # Clean vuln_id to make it filename-safe
        clean_id = re.sub(r"[^a-z0-9-]", "-", vuln_id.lower())
        if vuln_class:
            return f"phantom-{vuln_class}-{clean_id}"
        return f"phantom-vuln-{clean_id}"

    def _generate_tags(self, vuln_class: str) -> list[str]:
        """Generate tags for the template."""
        tags = self.default_tags.copy()
        if vuln_class:
            tags.append(vuln_class)
        return tags

    def _generate_http_section(
        self,
        vuln_class: str,
        request_data: dict[str, Any] | None,
        evidence: list[str],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate the HTTP request section of the template."""
        http_section: dict[str, Any] = {}
        
        if request_data:
            # Use actual request data if available
            method = request_data.get("method", "GET")
            path = request_data.get("path", "/")
            headers = request_data.get("headers", {})
            body = request_data.get("body", "")
            
            # Build raw request
            raw_request = self._build_raw_request(method, path, headers, body)
            http_section["raw"] = [raw_request]
        else:
            # Generate generic request based on vuln class
            http_section["method"] = "GET"
            http_section["path"] = ["{{BaseURL}}"]
        
        # Add matchers based on vulnerability class
        matchers = self._generate_matchers(vuln_class, evidence, metadata)
        if matchers:
            http_section["matchers"] = matchers
        
        return http_section

    def _build_raw_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str,
    ) -> str:
        """Build raw HTTP request string."""
        lines = [f"{method} {path} HTTP/1.1"]
        
        # Add headers
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        
        # Add blank line
        lines.append("")
        
        # Add body if present
        if body:
            lines.append(body)
        
        return "\n".join(lines)

    def _generate_matchers(
        self,
        vuln_class: str,
        evidence: list[str],
        metadata: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate matcher conditions based on vulnerability class and evidence."""
        matchers = []
        
        # Common SQL injection patterns
        if vuln_class == "sqli":
            matchers.append({
                "type": "word",
                "words": [
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite",
                    "Microsoft SQL Server",
                ],
                "part": "body",
                "condition": "or",
            })
        
        # Common XSS patterns
        elif vuln_class == "xss":
            matchers.append({
                "type": "word",
                "words": ["<script>", "alert(", "javascript:"],
                "part": "body",
                "condition": "or",
            })
        
        # Common RCE patterns
        elif vuln_class in ["rce", "cmd_injection"]:
            matchers.append({
                "type": "regex",
                "regex": [
                    r"root:.*:0:0:",
                    r"uid=\d+",
                    r"drwxr-xr-x",
                ],
                "part": "body",
                "condition": "or",
            })
        
        # Common SSRF patterns
        elif vuln_class == "ssrf":
            matchers.append({
                "type": "dsl",
                "dsl": [
                    "contains(body, 'metadata.google.internal')",
                    "contains(body, '169.254.169.254')",
                ],
                "condition": "or",
            })
        
        # Common LFI patterns
        elif vuln_class in ["lfi", "path_traversal"]:
            matchers.append({
                "type": "word",
                "words": [
                    "root:x:",
                    "[boot loader]",
                    "bin/bash",
                ],
                "part": "body",
                "condition": "or",
            })
        
        # Extract patterns from evidence
        if evidence:
            evidence_patterns = self._extract_patterns_from_evidence(evidence)
            if evidence_patterns:
                matchers.append({
                    "type": "word",
                    "words": evidence_patterns[:10],  # Limit to 10 patterns
                    "part": "body",
                    "condition": "or",
                })
        
        # Add status code matcher
        expected_status = metadata.get("response_status")
        if expected_status:
            matchers.append({
                "type": "status",
                "status": [expected_status],
            })
        
        return matchers

    def _extract_patterns_from_evidence(self, evidence: list[str]) -> list[str]:
        """Extract unique patterns from evidence list."""
        patterns = []
        for item in evidence:
            if isinstance(item, str):
                # Extract quoted strings or significant substrings
                quoted = re.findall(r'"([^"]+)"', item)
                patterns.extend(quoted[:3])  # Limit per evidence item
        return list(set(patterns))

    def _to_yaml(self, template: dict[str, Any]) -> str:
        """Convert template dict to YAML string."""
        # Use safe_dump with proper formatting
        yaml_str = yaml.dump(
            template,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=100,
        )
        return yaml_str

    def save_template(
        self,
        template_yaml: str,
        output_dir: str | Path,
        template_id: str,
    ) -> Path:
        """
        Save template to file.
        
        Args:
            template_yaml: YAML template string
            output_dir: Output directory
            template_id: Template ID (used for filename)
            
        Returns:
            Path to saved template file
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        filename = f"{template_id}.yaml"
        filepath = output_path / filename
        
        filepath.write_text(template_yaml, encoding="utf-8")
        
        return filepath


def generate_nuclei_templates_from_scan(
    vulnerabilities: list[Any],
    output_dir: str | Path,
    author: str = "Phantom AI",
) -> list[Path]:
    """
    Generate Nuclei templates for all vulnerabilities in a scan.
    
    Args:
        vulnerabilities: List of Vulnerability objects
        output_dir: Directory to save templates
        author: Template author
        
    Returns:
        List of paths to generated template files
    """
    generator = NucleiTemplateGenerator(author=author)
    saved_files = []
    
    for vuln in vulnerabilities:
        try:
            # Generate template
            template_yaml = generator.generate_from_vulnerability(vuln)
            
            # Extract template ID from YAML
            template_data = yaml.safe_load(template_yaml)
            template_id = template_data.get("id", f"unknown-{vuln.id}")
            
            # Save template
            filepath = generator.save_template(template_yaml, output_dir, template_id)
            saved_files.append(filepath)
            
        except Exception as e:
            # Log error but continue with other templates
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to generate template for {vuln.id}: {e}")
    
    return saved_files


def integrate_with_finish_scan(
    vulnerabilities: list[Any],
    run_dir: Path,
) -> dict[str, Any]:
    """
    Generate Nuclei templates as part of scan finalization.
    
    Args:
        vulnerabilities: List of vulnerabilities from the scan
        run_dir: Run directory (phantom_runs/<run_name>/)
        
    Returns:
        Dict with status and generated template paths
    """
    if not vulnerabilities:
        return {
            "nuclei_templates_generated": False,
            "reason": "No vulnerabilities to generate templates for",
        }
    
    try:
        output_dir = run_dir / "nuclei_templates"
        template_files = generate_nuclei_templates_from_scan(
            vulnerabilities=vulnerabilities,
            output_dir=output_dir,
        )
        
        return {
            "nuclei_templates_generated": True,
            "template_count": len(template_files),
            "output_directory": str(output_dir),
            "template_files": [str(f) for f in template_files],
        }
    except Exception as e:
        return {
            "nuclei_templates_generated": False,
            "error": str(e),
        }
