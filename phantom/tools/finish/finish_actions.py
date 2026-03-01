import re
from typing import Any

from phantom.config import Config
from phantom.tools.registry import register_tool

import logging

_logger = logging.getLogger(__name__)

# H1 FIX: Credential-scrubbing regex for reports
_CREDENTIAL_PATTERNS = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|auth|bearer|cookie|session[_-]?id"
    r"|access[_-]?key|private[_-]?key|jwt|csrf[_-]?token)"
    r"[\s]*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?",
    re.IGNORECASE,
)


def _scrub_credentials(text: str) -> str:
    """Replace credential values in text with [REDACTED]."""
    if not isinstance(text, str):
        return text
    return _CREDENTIAL_PATTERNS.sub(r"\1=[REDACTED]", text)


def _scrub_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub credential values from a dict before report output."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = _scrub_credentials(v)
        elif isinstance(v, dict):
            result[k] = _scrub_dict(v)
        elif isinstance(v, list):
            result[k] = [
                _scrub_dict(item) if isinstance(item, dict)
                else _scrub_credentials(item) if isinstance(item, str)
                else item
                for item in v
            ]
        else:
            result[k] = v
    return result


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
        _logger.debug("Failed to convert vuln dict to model: %s", e)
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


def _run_post_scan_enrichment(tracer: Any, agent_state: Any = None) -> dict[str, Any]:
    """Run all post-scan enrichment: verification, MITRE, compliance, attack graph, reports."""
    enrichment_results: dict[str, Any] = {}
    vuln_reports = tracer.vulnerability_reports

    if not vuln_reports:
        return {"enrichment": "skipped", "reason": "no vulnerabilities found"}

    run_dir = tracer.get_run_dir()

    # ── 0. Verification Engine ──
    # Attempt to auto-verify each vulnerability before finalising the report.
    try:
        import asyncio
        from phantom.core.verification_engine import VerificationEngine

        # Build an http client for verification probes
        http_client = None
        try:
            import httpx  # noqa: F811
            tls_verify = Config.get("phantom_verify_tls") != "false"
            http_client = httpx.AsyncClient(timeout=15.0, verify=tls_verify, follow_redirects=True)
        except ImportError:
            _logger.debug("httpx not available — verification will skip HTTP-based checks")

        engine = VerificationEngine(terminal_execute_fn=None, http_client=http_client)

        # Try to set up InteractshClient for OOB verification
        try:
            from phantom.core.interactsh_client import InteractshClient

            interactsh = InteractshClient(terminal_execute_fn=None)
            # Attempt to start a session (gracefully fails if interactsh-client not available)
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is None:
                asyncio.run(interactsh.start_session())
            else:
                # Event loop already running — schedule session start via ThreadPoolExecutor
                import concurrent.futures as _cf_interactsh
                with _cf_interactsh.ThreadPoolExecutor(max_workers=1) as _pool:
                    _pool.submit(asyncio.run, interactsh.start_session()).result(timeout=15)
            engine.interactsh = interactsh
            _logger.info("InteractshClient attached to verification engine for OOB checks")
        except Exception as e:
            _logger.debug("InteractshClient not available (OOB checks skipped): %s", e)

        vuln_models_for_verify = []
        for report in vuln_reports:
            model = _dict_to_vulnerability(report)
            if model:
                vuln_models_for_verify.append((report, model))

        if vuln_models_for_verify:
            # Run the async verification batch
            async def _verify_all():
                models = [m for _, m in vuln_models_for_verify]
                return await engine.verify_batch(models)

            # Run in a new event loop on a background thread to avoid
            # conflicts with any already-running loop.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                results = pool.submit(asyncio.run, _verify_all()).result(timeout=120)

            verified_count = 0
            for vresult in results:
                if vresult.is_exploitable:
                    verified_count += 1
                    # Update the original report dict with verification data
                    for report, model in vuln_models_for_verify:
                        if model.id == vresult.vulnerability_id:
                            report["verification_status"] = "verified"
                            report["verification_confidence"] = max(
                                (a.confidence for a in vresult.attempts if a.success), default=0.0
                            )
                            report["verification_evidence"] = next(
                                (a.evidence for a in vresult.attempts if a.success), ""
                            )
                            # Also update agent state if available
                            if agent_state and hasattr(agent_state, "mark_vuln_verified"):
                                agent_state.mark_vuln_verified(model.id)
                            break

            enrichment_results["verification"] = {
                "total": len(vuln_models_for_verify),
                "verified": verified_count,
                "unverified": len(vuln_models_for_verify) - verified_count,
                "note": "Unverified does NOT mean false positive — manual review recommended",
            }
            _logger.info(
                f"Verification engine: {verified_count}/{len(vuln_models_for_verify)} auto-verified"
            )
        else:
            enrichment_results["verification"] = {"skipped": "no convertible vuln models"}

        # Cleanup http client
        if http_client:
            try:
                import concurrent.futures as _cf
                with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                    _pool.submit(asyncio.run, http_client.aclose()).result(timeout=10)
            except Exception:
                _logger.debug("HTTP client cleanup error", exc_info=True)

    except Exception as e:
        enrichment_results["verification"] = {"error": str(e)}
        _logger.warning(f"Verification engine failed: {e}")

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
                    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', report.get("id", "unknown"))
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

    # ── 5. Knowledge Store (vulnerabilities + hosts + scan history) ──
    try:
        from phantom.core.knowledge_store import get_knowledge_store

        store = get_knowledge_store()
        stored_count = 0

        # 5a. Save vulnerabilities
        for report in vuln_reports:
            try:
                vuln_model = _dict_to_vulnerability(report)
                if vuln_model:
                    store.save_vulnerability(vuln_model)
                    stored_count += 1
            except Exception:
                _logger.debug("Failed to store vulnerability %s", report.get("id", "?"), exc_info=True)

        # 5b. Save hosts from EnhancedAgentState
        hosts_stored = 0
        if agent_state and hasattr(agent_state, "hosts"):
            for _key, host in agent_state.hosts.items():
                try:
                    store.save_host(host)
                    hosts_stored += 1
                except Exception:
                    _logger.debug("Failed to store host %s", _key, exc_info=True)

        # 5c. Record scan in history
        scan_recorded = False
        try:
            scan_id = getattr(agent_state, "scan_id", None) or getattr(tracer, "run_id", "unknown")
            target_str = ""
            if tracer.scan_config and tracer.scan_config.get("targets"):
                targets = tracer.scan_config["targets"]
                if targets:
                    target_str = (
                        targets[0].get("original", "")
                        if isinstance(targets[0], dict)
                        else str(targets[0])
                    )

            verified_count = sum(
                1 for r in vuln_reports if r.get("verification_status") == "verified"
            )
            duration = None
            if agent_state and hasattr(agent_state, "start_time") and agent_state.start_time:
                try:
                    from datetime import datetime, UTC
                    start = datetime.fromisoformat(str(agent_state.start_time))
                    duration = (datetime.now(UTC) - start).total_seconds()
                except (ValueError, TypeError):
                    pass

            tools_used = []
            if agent_state and hasattr(agent_state, "tools_used"):
                tools_used = list(agent_state.tools_used.keys())

            store.record_scan(
                scan_id=scan_id,
                target=target_str,
                status="completed",
                vulns_found=len(vuln_reports),
                vulns_verified=verified_count,
                hosts_found=hosts_stored,
                duration_seconds=duration,
                tools_used=tools_used,
            )
            scan_recorded = True
        except Exception as e:
            _logger.debug("Failed to record scan history: %s", e)

        enrichment_results["knowledge_store"] = {
            "vulnerabilities_stored": stored_count,
            "hosts_stored": hosts_stored,
            "scan_recorded": scan_recorded,
        }
        _logger.info(
            f"Knowledge store updated: {stored_count} vulns, {hosts_stored} hosts, "
            f"scan_recorded={scan_recorded}"
        )
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
        from phantom.models.scan import ScanResult, ScanStatus

        gen = ReportGenerator(output_dir=run_dir)
        target_str = ""
        if tracer.scan_config and tracer.scan_config.get("targets"):
            targets = tracer.scan_config["targets"]
            if targets:
                target_str = targets[0].get("original", "") if isinstance(targets[0], dict) else str(targets[0])

        # Build ScanResult so reports include timing + status
        scan_result = None
        try:
            from datetime import datetime, UTC
            started_at = datetime.fromisoformat(tracer.start_time) if tracer.start_time else None
            completed_at = datetime.now(UTC)
            scan_result = ScanResult(
                scan_id=tracer.run_id,
                target=target_str,
                started_at=started_at,
                completed_at=completed_at,
                status=ScanStatus.COMPLETED,
            )
        except Exception as e:
            _logger.debug("Could not build ScanResult: %s", e)

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
                    scan_result=scan_result,
                ))
            except Exception as e:
                _logger.warning(f"JSON report generation failed: {e}")

            try:
                generated_files["html"] = str(gen.generate_html_report(
                    scan_id=tracer.run_id,
                    target=target_str,
                    vulnerabilities=vuln_models,
                    hosts=[],
                    scan_result=scan_result,
                ))
            except Exception as e:
                _logger.warning(f"HTML report generation failed: {e}")

            try:
                generated_files["markdown"] = str(gen.generate_markdown_report(
                    scan_id=tracer.run_id,
                    target=target_str,
                    vulnerabilities=vuln_models,
                    hosts=[],
                    scan_result=scan_result,
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

    # ── AUTO-001 FIX: Minimum-work gate ──────────────────────────────────
    # Prevents premature termination (e.g. via indirect prompt injection
    # telling the LLM to call finish_scan immediately).
    MIN_ITERATIONS = 5
    MIN_TOOL_CALLS = 3

    if agent_state is not None:
        current_iteration = getattr(agent_state, "iteration", 0)
        actions_count = len(getattr(agent_state, "actions_taken", []))

        if current_iteration < MIN_ITERATIONS:
            _logger.warning(
                "AUTO-001: finish_scan blocked — iteration %d < minimum %d",
                current_iteration, MIN_ITERATIONS,
            )
            return {
                "success": False,
                "message": (
                    f"Cannot finish scan yet: only {current_iteration}/{MIN_ITERATIONS} "
                    f"iterations completed. You MUST continue scanning — run more "
                    f"reconnaissance and vulnerability testing before finishing."
                ),
                "blocked_by": "AUTO-001_minimum_work_gate",
            }

        if actions_count < MIN_TOOL_CALLS:
            _logger.warning(
                "AUTO-001: finish_scan blocked — %d tool calls < minimum %d",
                actions_count, MIN_TOOL_CALLS,
            )
            return {
                "success": False,
                "message": (
                    f"Cannot finish scan yet: only {actions_count}/{MIN_TOOL_CALLS} "
                    f"tools invoked. You MUST run more security tools before finishing."
                ),
                "blocked_by": "AUTO-001_minimum_work_gate",
            }

        _logger.info(
            "AUTO-001: finish_scan allowed — iteration=%d, tools=%d",
            current_iteration, actions_count,
        )
    # ── END AUTO-001 ─────────────────────────────────────────────────────

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

            # ── ARCH-003 FIX: Verification summary for HIGH/CRITICAL findings ──
            verification_summary = {"total_unverified": 0, "details": []}
            try:
                if agent_state and hasattr(agent_state, "unverified_findings"):
                    unverified = getattr(agent_state, "unverified_findings", [])
                    verified_count = 0
                    # Check which findings were later verified via create_vulnerability_report
                    ledger = getattr(agent_state, "findings_ledger", [])
                    for uf in unverified:
                        url = uf.get("url", "")
                        name = uf.get("name", "")
                        # A finding is considered verified if a vuln report was created for it
                        is_verified = any(
                            "[vuln/report]" in entry and (url in entry or name in entry)
                            for entry in ledger
                        )
                        if is_verified:
                            verified_count += 1
                        else:
                            verification_summary["details"].append(
                                f"{uf.get('severity', '').upper()} {name} at {url} — NOT VERIFIED"
                            )
                    verification_summary["total_unverified"] = len(unverified) - verified_count
                    verification_summary["total_queued"] = len(unverified)
                    verification_summary["verified_count"] = verified_count
                    if verification_summary["total_unverified"] > 0:
                        _logger.warning(
                            "ARCH-003: %d HIGH/CRITICAL findings were NOT verified before finish",
                            verification_summary["total_unverified"],
                        )
            except Exception as e:
                _logger.warning(f"ARCH-003 verification summary error: {e}")
            # ── END ARCH-003 ──

            # ── Post-Scan Enrichment Pipeline ──
            enrichment_results = {}
            try:
                enrichment_results = _run_post_scan_enrichment(tracer, agent_state=agent_state)
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
                "verification_summary": verification_summary,
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
