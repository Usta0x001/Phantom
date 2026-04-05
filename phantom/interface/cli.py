import atexit
import logging
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from phantom.agents.PhantomAgent import PhantomAgent
from phantom.llm.config import LLMConfig
from phantom.telemetry.tracer import Tracer, set_global_tracer

from .utils import (
    build_live_stats_text,
    format_vulnerability_report,
)

logger = logging.getLogger(__name__)


def _build_resume_diff_text(cp: Any) -> str:
    """Format a human-readable summary of a loaded checkpoint for display at resume time."""
    from datetime import UTC, datetime

    lines = [
        f"  Resuming run  {cp.run_name}",
        f"  Status        {cp.status}",
        f"  Iterations    {cp.iteration}",
        f"  Vulns found   {len(cp.vulnerability_reports)}",
    ]
    if cp.interruption_reason:
        lines.append(f"  Interrupted   {cp.interruption_reason}")
    if cp.llm_stats_at_checkpoint:
        cost = cp.llm_stats_at_checkpoint.get("total", {}).get("cost", 0)
        reqs = cp.llm_stats_at_checkpoint.get("total", {}).get("requests", 0)
        lines.append(f"  LLM cost      ${cost:.4f}  ({reqs} requests)")
    return "\n".join(lines)


async def run_cli(args: Any) -> None:  # noqa: PLR0912, PLR0915
    console = Console()
    
    # FIX: Check for quiet/JSON mode
    quiet_mode = getattr(args, "quiet", False)
    json_mode = getattr(args, "json_output", False)
    
    # FIX: TTY detection - auto-enable quiet mode if piped
    if not quiet_mode and not json_mode and not sys.stdout.isatty():
        quiet_mode = True

    # ── Resume: load checkpoint and restore state ──────────────────────────
    resume_run: str | None = getattr(args, "resume_run", None)
    checkpoint_mgr = None
    restored_state = None

    if resume_run:
        from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
        from phantom.agents.state import AgentState
        from phantom.config import Config

        interval = int(Config.get("phantom_checkpoint_interval") or str(CHECKPOINT_INTERVAL))
        run_dir = Path("phantom_runs") / resume_run
        checkpoint_mgr = CheckpointManager(run_dir, interval=interval)
        cp = checkpoint_mgr.load()

        if cp is None:
            console.print(
                f"[bold red]Cannot resume:[/] no checkpoint found in phantom_runs/{resume_run}/"
            )
            sys.exit(1)

        diff_text = _build_resume_diff_text(cp)
        
        # FIX: Skip rich panels in quiet/json mode
        if not quiet_mode and not json_mode:
            resume_panel = Panel(
                diff_text,
                title="[bold yellow]PHANTOM ─ RESUMING SCAN",
                title_align="left",
                border_style="yellow",
                padding=(1, 2),
            )
            console.print("\n")
            console.print(resume_panel)
            console.print()
        elif not json_mode:
            console.print(diff_text)  # Plain text in quiet mode

        # Restore agent state
        restored_state = AgentState.model_validate(cp.root_agent_state)
        # BUG FIX 1: clear stale sandbox container fields so the resumed scan
        # creates a fresh container instead of trying to connect to a dead one.
        restored_state.clear_sandbox()
        
        # P1.2 CRITICAL FIX: Restore hypothesis ledger, coverage tracker, and correlation engine
        # Without this, resumed scans lose all testing progress and vulnerability chains
        restored_hypothesis_ledger = None
        restored_coverage_tracker = None
        restored_correlation_engine = None
        
        if cp.hypothesis_ledger_state:
            try:
                from phantom.agents.hypothesis_ledger import HypothesisLedger
                restored_hypothesis_ledger = HypothesisLedger.from_dict({
                    "counter": max(int(k.split("-")[1]) for k in cp.hypothesis_ledger_state.keys()) if cp.hypothesis_ledger_state else 0,
                    "hypotheses": cp.hypothesis_ledger_state,
                })
                logger.info("Restored %d hypotheses from checkpoint", len(cp.hypothesis_ledger_state))
            except Exception as e:
                logger.warning("Failed to restore hypothesis ledger: %s", e)
        
        if cp.coverage_tracker_state:
            try:
                from phantom.agents.coverage_tracker import CoverageTracker
                restored_coverage_tracker = CoverageTracker.from_dict(cp.coverage_tracker_state)
                logger.info("Restored coverage tracker from checkpoint")
            except Exception as e:
                logger.warning("Failed to restore coverage tracker: %s", e)
        
        if cp.correlation_engine_state:
            try:
                from phantom.agents.correlation_engine import CorrelationEngine
                restored_correlation_engine = CorrelationEngine.from_dict(cp.correlation_engine_state)
                logger.info("Restored correlation engine from checkpoint")
            except Exception as e:
                logger.warning("Failed to restore correlation engine: %s", e)
        
        # Store restored components in args to pass to agent config
        args._restored_hypothesis_ledger = restored_hypothesis_ledger  # type: ignore[attr-defined]
        args._restored_coverage_tracker = restored_coverage_tracker  # type: ignore[attr-defined]
        args._restored_correlation_engine = restored_correlation_engine  # type: ignore[attr-defined]
        
        # Inject resume notice so agent knows context was restored
        restored_state.add_message(
            "user",
            f"[SCAN RESUMED] Your previous execution was interrupted at iteration "
            f"{cp.iteration}. You have already found {len(cp.vulnerability_reports)} "
            f"vulnerability report(s). Continue the penetration test from where you "
            f"left off. Do NOT repeat scans you have already completed.",
        )
        # Override run_name from checkpoint (already set in cli_app.py but being safe)
        args.run_name = cp.run_name  # type: ignore[attr-defined]
        # Restore scan_mode from checkpoint so LLMConfig uses the original mode.
        stored_mode = cp.scan_config.get("scan_mode")
        if stored_mode and not getattr(args, "scan_mode_overridden", False):
            args.scan_mode = stored_mode  # type: ignore[attr-defined]
        # Un-set waiting/stop flags so the resumed loop doesn't stall.
        restored_state.waiting_for_input = False
        restored_state.stop_requested = False
        restored_state.completed = False
    else:
        from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
        from phantom.config import Config

        interval = int(Config.get("phantom_checkpoint_interval") or str(CHECKPOINT_INTERVAL))

    # ── Build startup panel ────────────────────────────────────────────────
    # BUG FIX A: start_text was accidentally dropped in a prior patch; restored.
    start_text = Text()
    start_text.append("Penetration test initiated", style="bold #dc2626")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    results_text = Text()
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(f"phantom_runs/{args.run_name}", style="#60a5fa")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("Vulnerabilities will be displayed in real-time.", style="dim")

    # FIX: Skip rich panels in quiet/json mode
    if not quiet_mode and not json_mode:
        startup_panel = Panel(
            Text.assemble(
                start_text,
                "\n\n",
                target_text,
                "\n",
                results_text,
                note_text,
            ),
            title="[bold white]PHANTOM",
            title_align="left",
            border_style="#dc2626",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(startup_panel)
        console.print()
    elif not json_mode:
        # Quiet mode: minimal plain text
        console.print(f"Phantom scan started: {args.run_name}")

    scan_mode = getattr(args, "scan_mode", "deep")

    scan_config = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
        "scan_mode": scan_mode,  # stored so resume can use the original mode
    }

    llm_config = LLMConfig(scan_mode=scan_mode)
    base_max_iter = getattr(args, "profile_max_iterations", None) or 300
    # Hard absolute cap: at most 5× base across all resume cycles so a scan
    # that gets interrupted and resumed repeatedly cannot grow unboundedly.
    _abs_iter_cap = base_max_iter * 5
    agent_config: dict[str, Any] = {
        "llm_config": llm_config,
        "max_iterations": base_max_iter,
        "non_interactive": True,
    }

    if getattr(args, "local_sources", None):
        agent_config["local_sources"] = args.local_sources
    
    # P1.2 CRITICAL FIX: Pass restored components to agent config
    if getattr(args, "_restored_hypothesis_ledger", None):
        agent_config["hypothesis_ledger"] = args._restored_hypothesis_ledger
    if getattr(args, "_restored_coverage_tracker", None):
        agent_config["coverage_tracker"] = args._restored_coverage_tracker
    if getattr(args, "_restored_correlation_engine", None):
        agent_config["correlation_engine"] = args._restored_correlation_engine

    # Attach checkpoint manager to agent config so BaseAgent can save periodically
    if checkpoint_mgr is None:
        run_dir = Path("phantom_runs") / args.run_name
        checkpoint_mgr = CheckpointManager(run_dir, interval=interval)
    agent_config["_checkpoint_manager"] = checkpoint_mgr
    agent_config["_run_name"] = args.run_name

    # Restore prior agent state if resuming
    if restored_state is not None:
        # Extend iterations: give a full fresh budget on top of what was used,
        # but never exceed the absolute cap (5× base_max_iter).
        extended = restored_state.iteration + base_max_iter
        restored_state.max_iterations = min(extended, _abs_iter_cap)
        # Reset the warning flag so the agent gets a new approaching-limit warning
        # at 85% of the extended budget, not never (flag was True from prior run).
        restored_state.max_iterations_warning_sent = False

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    # Restore previously found vulnerabilities into tracer so they show in live view
    if resume_run and cp is not None:
        tracer.vulnerability_reports.extend(cp.vulnerability_reports)
        # ── BUG FIX 5: seed _saved_vuln_ids so old vulns are NOT re-written ──
        for v in cp.vulnerability_reports:
            tracer._saved_vuln_ids.add(v["id"])

    def display_vulnerability(report: dict[str, Any]) -> None:
        report_id = report.get("id", "unknown")

        vuln_text = format_vulnerability_report(report)

        vuln_panel = Panel(
            vuln_text,
            title=f"[bold red]{report_id.upper()}",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    tracer.vulnerability_found_callback = display_vulnerability

    # Mutable containers so signal handler closure can access the live agent ref
    _agent_holder: list[Any] = [None]

    def _save_interrupt_checkpoint(reason: str) -> None:
        agent = _agent_holder[0]
        if agent is None or checkpoint_mgr is None:
            return
        try:
            from phantom.checkpoint.checkpoint import CheckpointManager as CM

            cp_data = CM.build(
                run_name=args.run_name,
                state=agent.state,
                tracer=tracer,
                scan_config=scan_config,
                status="interrupted",
                interruption_reason=reason,
            )
            checkpoint_mgr.save(cp_data)
            console.print(f"[dim]Checkpoint saved → phantom_runs/{args.run_name}/checkpoint.json[/]")
        except Exception:  # noqa: BLE001
            pass

    def cleanup_on_exit() -> None:
        from phantom.runtime import cleanup_runtime

        tracer.cleanup()
        cleanup_runtime()

    def signal_handler(_signum: int, _frame: Any) -> None:
        _save_interrupt_checkpoint("SIGINT/SIGTERM")
        tracer.cleanup()
        # BUG FIX: Use blocking cleanup to ensure containers are stopped before exit
        from phantom.runtime import cleanup_runtime
        cleanup_runtime(wait=True)
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("Penetration test in progress", style="bold #dc2626")
        status_text.append("\n\n")

        stats_text = build_live_stats_text(tracer, agent_config)
        if stats_text:
            status_text.append(stats_text)

        return Panel(
            status_text,
            title="[bold white]PHANTOM",
            title_align="left",
            border_style="#dc2626",
            padding=(1, 2),
        )

    try:
        # FIX: Skip Live panel in quiet/json mode
        if quiet_mode or json_mode:
            # Run without live updates
            agent = PhantomAgent(agent_config)
            _agent_holder[0] = agent
            result = await agent.execute_scan(scan_config)
            
            if isinstance(result, dict) and not result.get("success", True):
                error_msg = result.get("error", "Unknown error")
                if not json_mode:
                    console.print(f"Error: {error_msg}")
                sys.exit(1)
            
            if checkpoint_mgr and isinstance(result, dict) and result.get("success"):
                checkpoint_mgr.mark_completed()
        else:
            # Normal mode with live panel
            console.print()

            with Live(
                create_live_status(), console=console, refresh_per_second=2, transient=False
            ) as live:
                stop_updates = threading.Event()

                def update_status() -> None:
                    while not stop_updates.is_set():
                        try:
                            live.update(create_live_status())
                            time.sleep(2)
                        except Exception:  # noqa: BLE001
                            break

                update_thread = threading.Thread(target=update_status, daemon=True)
                update_thread.start()

                try:
                    agent = PhantomAgent(agent_config)
                    _agent_holder[0] = agent  # allow signal handler to save checkpoint
                    result = await agent.execute_scan(scan_config)

                    if isinstance(result, dict) and not result.get("success", True):
                        error_msg = result.get("error", "Unknown error")
                        error_details = result.get("details")
                        console.print()
                        console.print(f"[bold red]Penetration test failed:[/] {error_msg}")
                        if error_details:
                            console.print(f"[dim]{error_details}[/]")
                        console.print()
                        sys.exit(1)

                    # Mark scan completed in checkpoint — only on actual success
                    if checkpoint_mgr and isinstance(result, dict) and result.get("success"):
                        checkpoint_mgr.mark_completed()
                finally:
                    stop_updates.set()
                    update_thread.join(timeout=1)

    except Exception as e:
        console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if tracer.final_scan_result:
        # FIX: JSON output mode for scripting
        if json_mode:
            import json
            output = {
                "run_name": args.run_name,
                "status": "completed",
                "vulnerabilities": tracer.vulnerability_reports,
                "stats": {
                    "vuln_count": len(tracer.vulnerability_reports),
                    "messages": len(tracer.chat_messages),
                    "tool_executions": len(tracer.tool_executions),
                }
            }
            print(json.dumps(output, indent=2))
        elif quiet_mode:
            # Quiet mode: just print vuln count
            console.print(f"\nScan complete: {len(tracer.vulnerability_reports)} vulnerabilities found")
        else:
            # Normal rich output
            console.print()

            final_report_text = Text()
            final_report_text.append("Penetration test summary", style="bold #60a5fa")

            final_report_panel = Panel(
                Text.assemble(
                    final_report_text,
                    "\n\n",
                    tracer.final_scan_result,
                ),
                title="[bold white]PHANTOM",
                title_align="left",
                border_style="#60a5fa",
                padding=(1, 2),
            )

            console.print(final_report_panel)
            console.print()
