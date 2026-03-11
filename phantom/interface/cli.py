import atexit
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
        checkpoint_mgr = CheckpointManager(run_dir)
        cp = checkpoint_mgr.load()

        if cp is None:
            console.print(
                f"[bold red]Cannot resume:[/] no checkpoint found in phantom_runs/{resume_run}/"
            )
            sys.exit(1)

        diff_text = _build_resume_diff_text(cp)
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

        # Restore agent state
        restored_state = AgentState.model_validate(cp.root_agent_state)
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
    else:
        from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL
        from phantom.config import Config

        interval = int(Config.get("phantom_checkpoint_interval") or str(CHECKPOINT_INTERVAL))

    # ── Build startup panel ────────────────────────────────────────────────
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

    scan_mode = getattr(args, "scan_mode", "deep")

    scan_config = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
    }

    llm_config = LLMConfig(scan_mode=scan_mode)
    agent_config: dict[str, Any] = {
        "llm_config": llm_config,
        "max_iterations": 300,
        "non_interactive": True,
    }

    if getattr(args, "local_sources", None):
        agent_config["local_sources"] = args.local_sources

    # Attach checkpoint manager to agent config so BaseAgent can save periodically
    if checkpoint_mgr is None:
        run_dir = Path("phantom_runs") / args.run_name
        checkpoint_mgr = CheckpointManager(run_dir)
    agent_config["_checkpoint_manager"] = checkpoint_mgr
    agent_config["_run_name"] = args.run_name

    # Restore prior agent state if resuming
    if restored_state is not None:
        agent_config["state"] = restored_state

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    # Restore previously found vulnerabilities into tracer so they show in live view
    if resume_run and cp is not None:
        tracer.vulnerability_reports.extend(cp.vulnerability_reports)

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

                # Mark scan completed in checkpoint
                if checkpoint_mgr:
                    checkpoint_mgr.mark_completed()
            finally:
                stop_updates.set()
                update_thread.join(timeout=1)

    except Exception as e:
        console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if tracer.final_scan_result:
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
