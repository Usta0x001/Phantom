import atexit
import signal
import sys
import threading
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from phantom.agents.PhantomAgent import PhantomAgent
from phantom.core.audit_logger import AuditLogger, set_global_audit_logger
from phantom.core.scan_profiles import ScanProfile, get_profile
from phantom.core.scope_validator import ScopeValidator
from phantom.llm.config import LLMConfig
from phantom.telemetry.tracer import Tracer, set_global_tracer

from .utils import (
    build_live_stats_text,
    format_vulnerability_report,
)

# ── Phantom Identity ──
_PHANTOM_COLOR = "#dc2626"
_ACCENT_COLOR = "#f59e0b"
_PHANTOM_TITLE = f"[bold {_PHANTOM_COLOR}]☠ PHANTOM[/]"
_PHANTOM_SUBTITLE = f"[italic {_ACCENT_COLOR}]\" The Ghost in the Machine \"[/]"


def _phantom_panel(content: Text | str, *, border: str = _PHANTOM_COLOR, **kw: Any) -> Panel:
    """Create a consistently-branded Phantom panel."""
    return Panel(
        content,
        title=_PHANTOM_TITLE,
        title_align="left",
        subtitle=_PHANTOM_SUBTITLE,
        subtitle_align="right",
        border_style=border,
        padding=(1, 2),
        **kw,
    )


async def run_cli(args: Any) -> None:  # noqa: PLR0915
    console = Console()

    # ── Phantom Banner ──
    banner = Text()
    banner.append("\n  ☠ PHANTOM", style="bold #dc2626")
    banner.append("  —  ", style="dim")
    banner.append("Autonomous Adversary Simulation Platform", style="dim white")
    banner.append("\n", style="")

    console.print(Panel(banner, border_style="#dc2626", padding=(0, 2)))

    start_text = Text()
    start_text.append("▶ Scan initiated", style="bold #dc2626")

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

    scan_mode = getattr(args, "scan_mode", "deep")

    # ── Load Scan Profile ──
    try:
        profile: ScanProfile = get_profile(scan_mode)
    except KeyError:
        console.print(f"[yellow]Unknown scan mode '{scan_mode}', falling back to 'deep'[/]")
        profile = get_profile("deep")

    profile_text = Text()
    profile_text.append("Profile", style="dim")
    profile_text.append(" ")
    profile_text.append(f"{profile.name}", style="bold #f59e0b")
    profile_text.append(f"  (max {profile.max_iterations} iterations, {profile.reasoning_effort} effort)", style="dim")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("Vulnerabilities will be displayed in real-time.", style="dim")

    startup_panel = _phantom_panel(
        Text.assemble(
            start_text,
            "\n\n",
            target_text,
            "\n",
            results_text,
            "\n",
            profile_text,
            note_text,
        ),
    )

    console.print("\n")
    console.print(startup_panel)
    console.print()

    scan_config = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
        "scan_mode": scan_mode,
        "profile": profile.to_dict(),
    }

    # ── Authenticated Scanning ──
    auth_headers = getattr(args, "auth_headers", [])
    if auth_headers:
        parsed_headers = {}
        for h in auth_headers:
            if ":" in h:
                key, value = h.split(":", 1)
                parsed_headers[key.strip()] = value.strip()
        if parsed_headers:
            scan_config["auth_headers"] = parsed_headers

    llm_config = LLMConfig(scan_mode=scan_mode)
    agent_config = {
        "llm_config": llm_config,
        "max_iterations": profile.max_iterations,
        "non_interactive": True,
        "scan_profile": profile,
    }

    if getattr(args, "local_sources", None):
        agent_config["local_sources"] = args.local_sources

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    # ── Scope Validator ──
    target_urls = [t["original"] for t in args.targets_info]
    scope_validator = ScopeValidator.from_targets(target_urls)
    tracer.scope_validator = scope_validator  # attach for downstream access

    # ── Audit Logger ──
    audit_log_path = tracer.get_run_dir() / "audit.jsonl"
    audit_logger = AuditLogger(audit_log_path)
    set_global_audit_logger(audit_logger)
    tracer.audit_logger = audit_logger  # attach for downstream access
    audit_logger.log_scan_start(
        scan_id=args.run_name,
        targets=target_urls,
        scan_mode=scan_mode,
    )

    # ── Knowledge Store — load past findings for this target ──
    try:
        from phantom.core.knowledge_store import get_knowledge_store

        knowledge_store = get_knowledge_store()
        known_vulns = knowledge_store.get_all_vulnerabilities()
        target_lower = target_urls[0].lower() if target_urls else ""
        past_findings = [
            v for v in known_vulns
            if target_lower and target_lower in (v.target or "").lower()
        ]
        if past_findings:
            scan_config["known_vulnerabilities"] = len(past_findings)
            console.print(
                f"  [dim]Knowledge Store:[/] {len(past_findings)} previously known"
                f" vulnerabilities for this target"
            )
    except Exception:
        pass  # Knowledge store is optional enhancement

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

    _cleanup_done = False

    def cleanup_on_exit() -> None:
        nonlocal _cleanup_done
        if _cleanup_done:
            return
        _cleanup_done = True
        from phantom.runtime import cleanup_runtime

        tracer.cleanup()
        cleanup_runtime()

    def signal_handler(_signum: int, _frame: Any) -> None:
        # Only set flag — let atexit handle actual cleanup to avoid I/O in signal handler
        nonlocal _cleanup_done
        if not _cleanup_done:
            _cleanup_done = True
            # Schedule cleanup via atexit (already registered)
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("▶ Scan in progress", style="bold #dc2626")
        status_text.append("\n\n")

        stats_text = build_live_stats_text(tracer, agent_config)
        if stats_text:
            status_text.append(stats_text)

        return _phantom_panel(status_text)

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
                result = await agent.execute_scan(scan_config)

                if isinstance(result, dict) and not result.get("success", True):
                    error_msg = result.get("error", "Unknown error")
                    error_details = result.get("details")
                    # Store error on tracer so completion message can display it
                    tracer.scan_error = error_msg
                    tracer.scan_error_details = error_details

                    # ── Attempt partial finish_scan on crash ──
                    # Even when the LLM dies, try to generate a summary report
                    # from whatever vulnerabilities were found so far.
                    try:
                        from phantom.tools.finish.finish_actions import finish_scan
                        from phantom.agents.state import AgentState

                        # Build a minimal agent_state for finish_scan
                        partial_state = agent.state
                        partial_history = partial_state.get_conversation_history()
                        finish_result = await finish_scan(
                            summary=f"PARTIAL SCAN (LLM Error: {error_msg[:100]})",
                            conversation_history=partial_history,
                            agent_state=partial_state,
                        )
                        if finish_result.get("success"):
                            tracer.final_scan_result = finish_result.get("report_summary", "")
                    except Exception:  # noqa: BLE001
                        pass  # Best-effort; crash_summary.json already saved by base_agent
            finally:
                stop_updates.set()
                update_thread.join(timeout=1)

        # Print error AFTER Live context closes so it's visible to user
        if hasattr(tracer, "scan_error") and tracer.scan_error:
            error_text = Text()
            error_text.append("☠ Scan Failed", style="bold red")
            error_text.append("\n\n")
            error_text.append(str(tracer.scan_error), style="white")
            if hasattr(tracer, "scan_error_details") and tracer.scan_error_details:
                error_text.append(f"\n{tracer.scan_error_details}", style="dim")

            # Detect rate limiting and add helpful guidance
            err_lower = str(tracer.scan_error).lower()
            if "ratelimit" in err_lower or "rate_limit" in err_lower or "quota" in err_lower or "429" in err_lower:
                error_text.append("\n\n")
                error_text.append("💡 Tip: ", style="bold yellow")
                error_text.append("Your API key hit a rate limit. Options:\n", style="yellow")
                error_text.append("   • Wait for the rate limit window to reset\n", style="dim")
                error_text.append("   • Use a paid API key with higher quotas\n", style="dim")
                error_text.append("   • Switch to a different LLM provider\n", style="dim")
                error_text.append("   • Set PHANTOM_LLM to a different model", style="dim")

            error_panel = _phantom_panel(
                error_text,
                border="red",
            )
            console.print()
            console.print(error_panel)
            console.print()

    except Exception as e:
        console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if tracer.final_scan_result:
        console.print()

        final_report_text = Text()
        final_report_text.append("☠ Scan Complete", style="bold #dc2626")

        final_report_panel = _phantom_panel(
            Text.assemble(
                final_report_text,
                "\n\n",
                tracer.final_scan_result,
            ),
        )

        console.print(final_report_panel)
        console.print()
