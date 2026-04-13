"""Generate a compact system audit report for Phantom."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phantom.agents.hypothesis_ledger import HypothesisLedger
from phantom.agents.correlation_engine import CorrelationEngine
from phantom.checkpoint.models import CheckpointData
from phantom.telemetry.tracer import get_global_tracer
from phantom.tools.registry import get_tool_names, tools
from phantom.tools.scan_status.scan_status_actions import get_scan_status


def _schema_drift() -> list[str]:
    missing = []
    for tool in tools:
        schema = str(tool.get("xml_schema", ""))
        if "Schema not found for tool" in schema:
            missing.append(str(tool.get("name", "unknown")))
    return missing


def _tool_contract_summary() -> dict[str, Any]:
    return {
        "registered_tools": len(get_tool_names()),
        "schema_drift_count": len(_schema_drift()),
        "schema_drift_tools": _schema_drift()[:20],
    }


def _scan_state_summary() -> dict[str, Any]:
    try:
        status = get_scan_status(include_recommendations=True)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    return {
        "iteration": status.get("scan_progress", {}).get("iteration", 0),
        "phase": status.get("scan_progress", {}).get("phase", "UNKNOWN"),
        "findings": status.get("findings", {}),
        "coverage": status.get("coverage", {}),
        "recommended_next_action": status.get("recommended_next_action"),
        "warnings": status.get("warnings", []),
    }


def _learning_summary() -> dict[str, Any]:
    tracer = get_global_tracer()
    ledger = getattr(tracer, "_agent_state", None)
    hyp_summary = None
    corr_metrics = None

    # Best-effort only: audit mode should not fail if runtime context isn't attached.
    try:
        if hasattr(ledger, "hypothesis_ledger") and isinstance(ledger.hypothesis_ledger, HypothesisLedger):
            hyp_summary = ledger.hypothesis_ledger.get_summary()
    except Exception:
        hyp_summary = None

    try:
        if hasattr(ledger, "correlation_engine") and isinstance(ledger.correlation_engine, CorrelationEngine):
            corr_metrics = ledger.correlation_engine.get_learning_metrics(top_n=5)
    except Exception:
        corr_metrics = None

    return {
        "hypothesis_summary": hyp_summary,
        "correlation_learning": corr_metrics,
    }


def _top_risks_from_checkpoint(cp: CheckpointData | None) -> list[dict[str, Any]]:
    if cp is None:
        return []

    ledger = HypothesisLedger.from_dict({
        "counter": len(cp.hypothesis_ledger_state),
        "hypotheses": cp.hypothesis_ledger_state,
    })
    risks = ledger.get_stale_hypothesis_summary(iteration_threshold=max(10, cp.iteration // 10 or 10))
    return risks[:10]


def ingest_trace_ablation(run_dir: Path) -> dict[str, Any]:
    """Best-effort ingestion from actual trace artifacts.

    Falls back gracefully when the expected files are absent.
    """
    events_file = run_dir / "events.jsonl"
    if not events_file.exists():
        return {"success": False, "reason": "events_missing"}

    vuln_count = 0
    findings_count = 0
    tool_exec = 0
    error_events = 0
    compression_events = 0
    event_types: dict[str, int] = {}
    try:
        for line in events_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            event_type = str(record.get("event_type", "unknown"))
            event_types[event_type] = event_types.get(event_type, 0) + 1

            if event_type == "vulnerability.report.created":
                vuln_count += 1
            if event_type in {"tool.executed", "tool.execution"}:
                tool_exec += 1
            if event_type.startswith("compression."):
                compression_events += 1
            if str(record.get("status", "")).lower() == "error":
                error_events += 1
            if event_type in {"tool.executed", "tool.execution"} and str(record.get("payload", "")).find("hypothesis") >= 0:
                findings_count += 1
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "reason": str(exc)}

    return {
        "success": True,
        "events_file": str(events_file),
        "vulnerability_reports": vuln_count,
        "hypothesis_related_events": findings_count,
        "tool_executions": tool_exec,
        "compression_events": compression_events,
        "error_events": error_events,
        "event_type_counts": event_types,
    }


def ingest_checkpoint_artifacts(run_dir: Path) -> dict[str, Any]:
    """Best-effort ingestion from checkpoint artifacts if present."""
    cp_path = run_dir / "checkpoint.json"
    if not cp_path.exists():
        return {"success": False, "reason": "checkpoint_missing"}

    try:
        cp = CheckpointData.model_validate_json(cp_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "reason": str(exc)}

    return {
        "success": True,
        "iteration": cp.iteration,
        "status": cp.status,
        "vulnerability_reports": len(cp.vulnerability_reports),
        "hypotheses": len(cp.hypothesis_ledger_state),
        "correlation_models": len(cp.correlation_engine_state.get("surface_outcomes", {})),
        "payload_family_models": len(cp.correlation_engine_state.get("payload_family_outcomes", {})),
        "sub_agents": len(cp.sub_agent_states),
    }


def _load_checkpoint(run_dir: Path) -> CheckpointData | None:
    cp_path = run_dir / "checkpoint.json"
    if not cp_path.exists():
        return None
    try:
        return CheckpointData.model_validate_json(cp_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def compare_runs(base_run_dir: Path, compare_run_dir: Path) -> dict[str, Any]:
    base_cp = _load_checkpoint(base_run_dir)
    compare_cp = _load_checkpoint(compare_run_dir)
    base_trace = ingest_trace_ablation(base_run_dir)
    compare_trace = ingest_trace_ablation(compare_run_dir)

    def _safe_count(cp: CheckpointData | None, field: str) -> int:
        return int(getattr(cp, field, []) and len(getattr(cp, field, [])) or 0)

    base_vulns = _safe_count(base_cp, "vulnerability_reports")
    compare_vulns = _safe_count(compare_cp, "vulnerability_reports")
    base_hyp = _safe_count(base_cp, "hypothesis_ledger_state")
    compare_hyp = _safe_count(compare_cp, "hypothesis_ledger_state")

    base_checkpoint = ingest_checkpoint_artifacts(base_run_dir)
    compare_checkpoint = ingest_checkpoint_artifacts(compare_run_dir)

    comparison = {
        "base_run_dir": str(base_run_dir),
        "compare_run_dir": str(compare_run_dir),
        "vulnerability_delta": compare_vulns - base_vulns,
        "hypothesis_delta": compare_hyp - base_hyp,
        "tool_executions_delta": int((compare_trace.get("tool_executions", 0) if compare_trace else 0) - (base_trace.get("tool_executions", 0) if base_trace else 0)),
        "compression_events_delta": int((compare_trace.get("compression_events", 0) if compare_trace else 0) - (base_trace.get("compression_events", 0) if base_trace else 0)),
        "error_events_delta": int((compare_trace.get("error_events", 0) if compare_trace else 0) - (base_trace.get("error_events", 0) if base_trace else 0)),
    }

    compare_iteration = int(compare_cp.iteration) if compare_cp is not None else 0
    compare_status = str(compare_cp.status) if compare_cp is not None else "COMPARE"

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "state_health": {"has_tracer": False, "has_scan_status": True},
        "schema_drift": _schema_drift(),
        "tool_contract": _tool_contract_summary(),
        "scan_state": {
            "iteration": compare_iteration,
            "phase": compare_status,
            "findings": {
                "base_vulnerability_reports": base_vulns,
                "compare_vulnerability_reports": compare_vulns,
                "vulnerability_delta": comparison["vulnerability_delta"],
                "base_hypotheses": base_hyp,
                "compare_hypotheses": compare_hyp,
                "hypothesis_delta": comparison["hypothesis_delta"],
            },
            "coverage": {},
            "recommended_next_action": "Compare run artifacts",
            "warnings": [],
        },
        "learning": _learning_summary(),
        "trace_ingestion": {"base": base_trace, "compare": compare_trace},
        "checkpoint_ingestion": {"base": base_checkpoint, "compare": compare_checkpoint},
        "top_risks": _top_risks_from_checkpoint(compare_cp),
        "stale_hypotheses": _top_risks_from_checkpoint(compare_cp),
        "comparison": comparison,
        "base_top_risks": _top_risks_from_checkpoint(base_cp),
    }


def generate_audit_report(run_dir: Path | None = None) -> dict[str, Any]:
    tracer = get_global_tracer()
    trace_ingestion = None
    checkpoint_ingestion = None
    if run_dir is not None:
        trace_ingestion = ingest_trace_ablation(run_dir)
        checkpoint_ingestion = ingest_checkpoint_artifacts(run_dir)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "state_health": {
            "has_tracer": tracer is not None,
            "has_scan_status": True,
        },
        "schema_drift": _schema_drift(),
        "tool_contract": _tool_contract_summary(),
        "scan_state": _scan_state_summary(),
        "learning": _learning_summary(),
        "trace_ingestion": trace_ingestion,
        "checkpoint_ingestion": checkpoint_ingestion,
        "top_risks": _top_risks_from_checkpoint(_load_checkpoint(run_dir)) if run_dir is not None else [],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# Phantom Audit Report", ""]
    lines.append(f"Generated at: `{report['generated_at']}`")
    lines.append("")
    lines.append("## State Health")
    for key, value in report.get("state_health", {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    lines.append("## Tool Contract")
    for key, value in report.get("tool_contract", {}).items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    lines.append("## Schema Drift")
    drift = report.get("schema_drift", [])
    if drift:
        for tool_name in drift:
            lines.append(f"- `{tool_name}`")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Scan State")
    scan = report.get("scan_state", {})
    for key, value in scan.items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    lines.append("## Learning")
    learning = report.get("learning", {})
    lines.append(f"- hypothesis_summary: `{learning.get('hypothesis_summary')}`")
    lines.append(f"- correlation_learning: `{learning.get('correlation_learning')}`")
    lines.append("")
    lines.append("## Trace Ingestion")
    trace = report.get("trace_ingestion")
    if trace:
        for key, value in trace.items():
            lines.append(f"- {key}: `{value}`")
    else:
        lines.append("- not provided")
    lines.append("")
    lines.append("## Checkpoint Ingestion")
    checkpoint = report.get("checkpoint_ingestion")
    if checkpoint:
        for key, value in checkpoint.items():
            lines.append(f"- {key}: `{value}`")
    else:
        lines.append("- not provided")
    lines.append("")
    lines.append("## Top Risks")
    top_risks = report.get("top_risks", [])
    if top_risks:
        for item in top_risks[:10]:
            lines.append(
                f"- {item.get('hypothesis_id')} | {item.get('vuln_class')} | {item.get('surface')} | "
                f"conf={item.get('confidence')} action={item.get('recommended_action')}"
            )
    else:
        lines.append("- none")
    lines.append("")
    if report.get("comparison"):
        lines.append("## Comparison")
        comparison = report.get("comparison", {})
        for key, value in comparison.items():
            lines.append(f"- {key}: `{value}`")
        lines.append("")
    lines.append("")
    return "\n".join(lines)


def write_report(output_dir: Path, run_dir: Path | None = None) -> tuple[Path, Path, dict[str, Any]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report = generate_audit_report(run_dir=run_dir)
    json_path = output_dir / "audit_report.json"
    md_path = output_dir / "audit_report.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path, report


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Phantom audit report")
    parser.add_argument("--output-dir", default="thesis_output/audit", help="Output directory")
    parser.add_argument("--run-dir", default=None, help="Optional phantom run directory for trace ingestion")
    parser.add_argument("--compare-run-dir", default=None, help="Optional second run directory to compare against --run-dir")
    args = parser.parse_args()

    run_dir = Path(args.run_dir) if args.run_dir else None
    if args.compare_run_dir and not run_dir:
        raise SystemExit("--compare-run-dir requires --run-dir")
    if args.compare_run_dir and run_dir:
        report = compare_runs(run_dir, Path(args.compare_run_dir))
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "audit_compare.json"
        md_path = output_dir / "audit_compare.md"
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        md_path.write_text(
            render_markdown(
                {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "state_health": {"has_tracer": False, "has_scan_status": True},
                    "schema_drift": [],
                    "tool_contract": {"registered_tools": 0, "schema_drift_count": 0, "schema_drift_tools": []},
                    "scan_state": {
                        "iteration": 0,
                        "phase": "COMPARE",
                        "findings": {},
                        "coverage": {},
                        "recommended_next_action": "Compare run artifacts",
                        "warnings": [],
                    },
                    "learning": {"hypothesis_summary": None, "correlation_learning": None},
                    "trace_ingestion": {"base": report.get("base_trace"), "compare": report.get("compare_trace")},
                    "checkpoint_ingestion": {"base": report.get("base_checkpoint"), "compare": report.get("compare_checkpoint")},
                    "top_risks": report.get("compare_top_risks", []),
                }
            ),
            encoding="utf-8",
        )
    else:
        json_path, md_path, report = write_report(Path(args.output_dir), run_dir=run_dir)
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    print(json.dumps({"schema_drift": len(report["schema_drift"]), "registered_tools": report["tool_contract"]["registered_tools"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
