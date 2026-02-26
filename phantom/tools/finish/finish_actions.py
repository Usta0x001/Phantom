from typing import Any

from phantom.tools.registry import register_tool

import logging

_logger = logging.getLogger(__name__)


def _extract_cwe_ids(report: dict[str, Any]) -> list[str]:
    """Extract CWE IDs from a vulnerability report dict."""
    cwe_ids = report.get("cwe_ids", [])
    if cwe_ids:
        return [str(c) for c in cwe_ids if c]
    # Try MITRE enrichment data
    mitre = report.get("mitre")
    if isinstance(mitre, dict):
        cwes = mitre.get("cwes", [])
        return [
            cwe.get("id", "") if isinstance(cwe, dict) else str(cwe)
            for cwe in cwes
            if (cwe.get("id", "") if isinstance(cwe, dict) else str(cwe))
        ]
    return []


def _dict_to_vulnerability(report: dict[str, Any]) -> Any:
    """Convert a vuln report dict (from tracer) to a Vulnerability model object.

    Returns None if conversion fails — caller should handle gracefully.
    """
    try:
        from phantom.models.vulnerability import (
            Vulnerability,
            VulnerabilitySeverity,
            VulnerabilityStatus,
        )

        severity_map = {
            "critical": VulnerabilitySeverity.CRITICAL,
            "high": VulnerabilitySeverity.HIGH,
            "medium": VulnerabilitySeverity.MEDIUM,
            "low": VulnerabilitySeverity.LOW,
            "info": VulnerabilitySeverity.INFO,
        }

        sev_str = str(report.get("severity", "medium")).lower()
        severity = severity_map.get(sev_str, VulnerabilitySeverity.MEDIUM)

        return Vulnerability(
            id=report.get("id", "vuln-unknown"),
            name=report.get("title", "Untitled"),
            vulnerability_class=report.get("vulnerability_class", _guess_vuln_class(report)),
            severity=severity,
            status=VulnerabilityStatus.DETECTED,
            cvss_score=report.get("cvss"),
            target=report.get("target", "unknown"),
            endpoint=report.get("endpoint"),
            parameter=report.get("parameter"),
            method=report.get("method"),
            description=report.get("description", "No description"),
            payload=report.get("poc_script_code"),
            cve_ids=[report["cve"]] if report.get("cve") else [],
            cwe_ids=_extract_cwe_ids(report),
            remediation=report.get("remediation_steps"),
            detected_by="phantom-agent",
        )
    except Exception as e:
        _logger.debug(f"Failed to convert vuln dict to model: {e}")
        return None


def _guess_vuln_class(report: dict[str, Any]) -> str:
    """Guess vulnerability class from title/description."""
    text = f"{report.get('title', '')} {report.get('description', '')}".lower()
    if "sql" in text or "sqli" in text:
        return "sqli"
    if "xss" in text or "cross-site scripting" in text:
        return "xss"
    if "rce" in text or "remote code" in text or "command injection" in text:
        return "rce"
    if "ssrf" in text:
        return "ssrf"
    if "idor" in text or "insecure direct" in text:
        return "idor"
    if "access control" in text or "authorization" in text:
        return "broken_access_control"
    if "disclosure" in text or "exposure" in text or "information leak" in text:
        return "information_disclosure"
    return "other"


def _run_post_scan_enrichment(tracer: Any) -> dict[str, Any]:
    """Run all post-scan enrichment: MITRE, compliance, attack graph, reports."""
    enrichment_results: dict[str, Any] = {}
    vuln_reports = tracer.vulnerability_reports

    if not vuln_reports:
        return {"enrichment": "skipped", "reason": "no vulnerabilities found"}

    run_dir = tracer.get_run_dir()

    # ── 1. MITRE Enrichment ──
    try:
        from phantom.core.mitre_enrichment import MITREEnricher

        enricher = MITREEnricher()
        enriched_count = 0
        for report in vuln_reports:
            finding_dict = {
                "title": report.get("title", ""),
                "description": report.get("description", ""),
                "severity": report.get("severity", "info"),
            }
            result = enricher.enrich_finding(finding_dict)
            if result.get("cwe") or result.get("capec"):
                report["mitre"] = {
                    "cwes": result.get("cwe", []),
                    "capecs": result.get("capec", []),
                    "primary_cwe": result.get("primary_cwe"),
                    "primary_cwe_name": result.get("primary_cwe_name"),
                    "owasp_top10": result.get("owasp_top10"),
                }
                enriched_count += 1
        enrichment_results["mitre"] = {"enriched": enriched_count, "total": len(vuln_reports)}
        _logger.info(f"MITRE enrichment: {enriched_count}/{len(vuln_reports)} findings enriched")
    except Exception as e:
        enrichment_results["mitre"] = {"error": str(e)}
        _logger.warning(f"MITRE enrichment failed: {e}")

    # ── 2. Compliance Mapping ──
    try:
        from phantom.core.compliance_mapper import ComplianceMapper

        mapper = ComplianceMapper()
        findings_for_mapper = []
        for report in vuln_reports:
            finding = {
                "title": report.get("title", ""),
                "description": report.get("description", ""),
                "severity": report.get("severity", "info"),
                "cwes": [],
            }
            if report.get("mitre") and report["mitre"].get("cwes"):
                for cwe in report["mitre"]["cwes"]:
                    cwe_id = cwe.get("id", "") if isinstance(cwe, dict) else str(cwe)
                    if cwe_id:
                        finding["cwes"].append(cwe_id)
            findings_for_mapper.append(finding)

        matches = mapper.map_findings(findings_for_mapper)
        enrichment_results["compliance"] = {
            "matches_found": len(matches) if matches else 0,
            "status": "completed",
        }

        # Save compliance report
        try:
            compliance_md = mapper.to_markdown(findings_for_mapper)
            compliance_file = run_dir / "compliance_report.md"
            compliance_file.write_text(compliance_md, encoding="utf-8")
            enrichment_results["compliance"]["file"] = str(compliance_file)
            _logger.info(f"Compliance report saved to: {compliance_file}")
        except Exception as e:
            _logger.warning(f"Failed to save compliance report: {e}")

    except Exception as e:
        enrichment_results["compliance"] = {"error": str(e)}
        _logger.warning(f"Compliance mapping failed: {e}")

    # ── 3. Attack Graph ──
    try:
        from phantom.core.attack_graph import AttackGraph

        graph = AttackGraph()
        nodes_added = graph.ingest_scan_findings(vuln_reports)

        # Save attack graph
        try:
            graph.export_json(run_dir / "attack_graph.json")
            enrichment_results["attack_graph"] = {
                "nodes": graph.node_count,
                "edges": graph.edge_count,
                "file": str(run_dir / "attack_graph.json"),
            }
            _logger.info(f"Attack graph saved: {graph.node_count} nodes, {graph.edge_count} edges")
        except Exception as e:
            _logger.warning(f"Failed to save attack graph: {e}")

        # Attack path analysis
        try:
            from phantom.core.attack_path_analyzer import AttackPathAnalyzer

            analyzer = AttackPathAnalyzer(graph)
            attack_path_md = analyzer.to_markdown()
            if attack_path_md:
                attack_path_file = run_dir / "attack_paths.md"
                attack_path_file.write_text(attack_path_md, encoding="utf-8")
                report = analyzer.full_analysis()
                enrichment_results["attack_paths"] = {
                    "paths_found": len(report.paths) if hasattr(report, "paths") else 0,
                    "file": str(attack_path_file),
                }
                _logger.info(f"Attack path analysis saved to: {attack_path_file}")
        except Exception as e:
            _logger.warning(f"Attack path analysis failed: {e}")

    except Exception as e:
        enrichment_results["attack_graph"] = {"error": str(e)}
        _logger.warning(f"Attack graph generation failed: {e}")

    # ── 4. Nuclei Templates ──
    try:
        from phantom.core.nuclei_templates import TemplateGenerator

        generator = TemplateGenerator()
        templates_dir = run_dir / "nuclei_templates"
        templates_dir.mkdir(exist_ok=True)

        template_count = 0
        for report in vuln_reports:
            try:
                template_yaml = generator.from_finding(report)
                if template_yaml:
                    safe_id = report.get("id", "unknown").replace("/", "_")
                    template_file = templates_dir / f"{safe_id}.yaml"
                    template_file.write_text(template_yaml, encoding="utf-8")
                    template_count += 1
            except Exception:
                _logger.debug("Failed to generate Nuclei template for finding %s", report.get("id", "?"), exc_info=True)

        enrichment_results["nuclei_templates"] = {"generated": template_count}
        if template_count:
            _logger.info(f"Generated {template_count} Nuclei templates")

    except Exception as e:
        enrichment_results["nuclei_templates"] = {"error": str(e)}
        _logger.warning(f"Nuclei template generation failed: {e}")

    # ── 5. Knowledge Store ──
    try:
        from phantom.core.knowledge_store import get_knowledge_store

        store = get_knowledge_store()
        stored_count = 0
        for report in vuln_reports:
            try:
                vuln_model = _dict_to_vulnerability(report)
                if vuln_model:
                    store.save_vulnerability(vuln_model)
                    stored_count += 1
            except Exception:
                _logger.debug("Failed to store vulnerability %s", report.get("id", "?"), exc_info=True)
        enrichment_results["knowledge_store"] = {"vulnerabilities_stored": stored_count}
        _logger.info(f"Knowledge store updated with {stored_count} vulnerabilities")
    except Exception as e:
        enrichment_results["knowledge_store"] = {"error": str(e)}
        _logger.warning(f"Knowledge store update failed: {e}")

    # ── 6. Notifications ──
    try:
        from phantom.core.notifier import Notifier

        notifier = Notifier.from_env()
        if len(notifier.channels) > 0:
            sent_count = 0
            for report in vuln_reports:
                severity = report.get("severity", "info").lower()
                if severity in ("critical", "high"):
                    delivered = notifier.notify_finding(report)
                    sent_count += delivered
            enrichment_results["notifications"] = {"findings_notified": sent_count}
        else:
            enrichment_results["notifications"] = {"skipped": "no channels configured"}
    except Exception as e:
        enrichment_results["notifications"] = {"skipped": str(e)}

    # ── 7. Generate enhanced reports (JSON/HTML/Markdown) ──
    try:
        from phantom.core.report_generator import ReportGenerator

        gen = ReportGenerator(output_dir=run_dir)
        target_str = ""
        if tracer.scan_config and tracer.scan_config.get("targets"):
            targets = tracer.scan_config["targets"]
            if targets:
                target_str = targets[0].get("original", "") if isinstance(targets[0], dict) else str(targets[0])

        # Convert dict reports to Vulnerability model objects
        vuln_models = []
        for report in vuln_reports:
            model = _dict_to_vulnerability(report)
            if model:
                vuln_models.append(model)

        if vuln_models:
            generated_files = {}
            try:
                generated_files["json"] = str(gen.generate_json_report(
                    scan_id=tracer.run_id,
                    target=target_str,
                    vulnerabilities=vuln_models,
                    hosts=[],
                ))
            except Exception as e:
                _logger.warning(f"JSON report generation failed: {e}")

            try:
                generated_files["html"] = str(gen.generate_html_report(
                    scan_id=tracer.run_id,
                    target=target_str,
                    vulnerabilities=vuln_models,
                    hosts=[],
                ))
            except Exception as e:
                _logger.warning(f"HTML report generation failed: {e}")

            try:
                generated_files["markdown"] = str(gen.generate_markdown_report(
                    scan_id=tracer.run_id,
                    target=target_str,
                    vulnerabilities=vuln_models,
                    hosts=[],
                ))
            except Exception as e:
                _logger.warning(f"Markdown report generation failed: {e}")

            enrichment_results["reports"] = {"files": generated_files}
            _logger.info(f"Enhanced reports generated: {list(generated_files.keys())}")
        else:
            enrichment_results["reports"] = {"skipped": "could not convert vulns to model objects"}
    except Exception as e:
        enrichment_results["reports"] = {"error": str(e)}
        _logger.warning(f"Enhanced report generation failed: {e}")

    return enrichment_results


def _validate_root_agent(agent_state: Any) -> dict[str, Any] | None:
    if agent_state and hasattr(agent_state, "parent_id") and agent_state.parent_id is not None:
        return {
            "success": False,
            "error": "finish_scan_wrong_agent",
            "message": "This tool can only be used by the root/main agent",
            "suggestion": "If you are a subagent, use agent_finish from agents_graph tool instead",
        }
    return None


def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
    try:
        from phantom.tools.agents_graph.agents_graph_actions import _agent_graph

        if agent_state and agent_state.agent_id:
            current_agent_id = agent_state.agent_id
        else:
            return None

        active_agents = []
        stopping_agents = []

        for agent_id, node in _agent_graph["nodes"].items():
            if agent_id == current_agent_id:
                continue

            status = node.get("status", "unknown")
            if status == "running":
                active_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )
            elif status == "stopping":
                stopping_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )

        if active_agents or stopping_agents:
            response: dict[str, Any] = {
                "success": False,
                "error": "agents_still_active",
                "message": "Cannot finish scan: agents are still active",
            }

            if active_agents:
                response["active_agents"] = active_agents

            if stopping_agents:
                response["stopping_agents"] = stopping_agents

            response["suggestions"] = [
                "Use wait_for_message to wait for all agents to complete",
                "Use send_message_to_agent if you need agents to complete immediately",
                "Check agent_status to see current agent states",
            ]

            response["total_active"] = len(active_agents) + len(stopping_agents)

            return response

    except ImportError:
        pass
    except Exception:
        import logging

        logging.exception("Error checking active agents")

    return None


@register_tool(sandbox_execution=False)
def finish_scan(
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    agent_state: Any = None,
) -> dict[str, Any]:
    validation_error = _validate_root_agent(agent_state)
    if validation_error:
        return validation_error

    active_agents_error = _check_active_agents(agent_state)
    if active_agents_error:
        return active_agents_error

    validation_errors = []

    if not executive_summary or not executive_summary.strip():
        validation_errors.append("Executive summary cannot be empty")
    if not methodology or not methodology.strip():
        validation_errors.append("Methodology cannot be empty")
    if not technical_analysis or not technical_analysis.strip():
        validation_errors.append("Technical analysis cannot be empty")
    if not recommendations or not recommendations.strip():
        validation_errors.append("Recommendations cannot be empty")

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    try:
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            tracer.update_scan_final_fields(
                executive_summary=executive_summary.strip(),
                methodology=methodology.strip(),
                technical_analysis=technical_analysis.strip(),
                recommendations=recommendations.strip(),
            )

            vulnerability_count = len(tracer.vulnerability_reports)

            # ── Post-Scan Enrichment Pipeline ──
            enrichment_results = {}
            try:
                enrichment_results = _run_post_scan_enrichment(tracer)
                _logger.info(f"Post-scan enrichment completed: {list(enrichment_results.keys())}")
            except Exception as e:
                _logger.warning(f"Post-scan enrichment pipeline error: {e}")
                enrichment_results = {"error": str(e)}

            # ── Export EnhancedAgentState structured data ──
            enhanced_state_path = None
            try:
                if agent_state and hasattr(agent_state, "to_report_data"):
                    import json
                    report_data = agent_state.to_report_data()
                    run_dir = getattr(tracer, "run_dir", None)
                    if run_dir and report_data:
                        from pathlib import Path
                        state_file = Path(run_dir) / "enhanced_state.json"
                        state_file.write_text(
                            json.dumps(report_data, indent=2, default=str),
                            encoding="utf-8",
                        )
                        enhanced_state_path = str(state_file)
                        _logger.info(f"Enhanced state exported to {enhanced_state_path}")
            except Exception as e:
                _logger.warning(f"Enhanced state export failed: {e}")

            result = {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed successfully",
                "vulnerabilities_found": vulnerability_count,
                "enrichment": enrichment_results,
            }
            if enhanced_state_path:
                result["enhanced_state_file"] = enhanced_state_path
            return result

        import logging

        logging.warning("Current tracer not available - scan results not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}
    else:
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed (not persisted)",
            "warning": "Results could not be persisted - tracer unavailable",
        }
