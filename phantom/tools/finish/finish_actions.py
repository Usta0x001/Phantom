from typing import Any

from phantom.tools.registry import register_tool


def _post_scan_hooks(tracer: Any) -> None:
    """Run post-scan enrichment: compliance mapping, attack graph, SARIF export."""
    import json
    import logging

    run_dir = tracer.get_run_dir()
    vulns = tracer.vulnerability_reports

    # ── 1. Compliance Mapping ──
    try:
        from phantom.core.compliance_mapper import ComplianceMapper

        mapper = ComplianceMapper()
        md = mapper.to_markdown(vulns)
        (run_dir / "compliance_report.md").write_text(md, encoding="utf-8")
        logging.getLogger(__name__).info("Saved compliance report to %s", run_dir / "compliance_report.md")
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).debug("Compliance mapping skipped", exc_info=True)

    # ── 2. Attack Graph + Path Analysis ──
    try:
        from phantom.core.attack_graph import AttackGraph
        from phantom.core.attack_path_analyzer import AttackPathAnalyzer

        graph = AttackGraph()
        graph.ingest_scan_findings(vulns)
        graph.export_json(run_dir / "attack_graph.json")

        analyzer = AttackPathAnalyzer(graph)
        md = analyzer.to_markdown()
        (run_dir / "attack_paths.md").write_text(md, encoding="utf-8")
        logging.getLogger(__name__).info("Saved attack graph & paths to %s", run_dir)
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).debug("Attack graph generation skipped", exc_info=True)

    # ── 3. SARIF Export ──
    try:
        from phantom.interface.formatters.sarif_formatter import SARIFFormatter

        formatter = SARIFFormatter()
        scan_data = {
            "vulnerabilities": vulns,
            "scan_id": tracer.run_id,
            "targets": [t.get("original", "") for t in (tracer.scan_config or {}).get("targets", [])],
        }
        sarif = formatter.format(scan_data)
        (run_dir / "results.sarif").write_text(
            json.dumps(sarif, indent=2, default=str), encoding="utf-8"
        )
        logging.getLogger(__name__).info("Saved SARIF report to %s", run_dir / "results.sarif")
    except Exception:  # noqa: BLE001
        logging.getLogger(__name__).debug("SARIF export skipped", exc_info=True)

    # ── 4. Audit log scan completion ──
    try:
        from datetime import datetime, timezone
        from phantom.core.audit_logger import get_global_audit_logger

        _audit = get_global_audit_logger()
        if _audit:
            # Calculate duration from start_time to now (end_time may not be set yet)
            _duration = 0.0
            if hasattr(tracer, "start_time") and tracer.start_time:
                try:
                    _start = datetime.fromisoformat(
                        tracer.start_time.replace("Z", "+00:00")
                    )
                    _duration = (datetime.now(timezone.utc) - _start).total_seconds()
                except (ValueError, TypeError):
                    pass
            _audit.log_scan_end(
                scan_id=tracer.run_id,
                success=True,
                findings_count=len(vulns),
                duration_seconds=_duration,
            )
    except Exception:  # noqa: BLE001
        pass


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

            # ── Post-scan enrichment hooks ──
            _post_scan_hooks(tracer)

            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed successfully",
                "vulnerabilities_found": vulnerability_count,
            }

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
