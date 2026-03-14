"""
Phantom CLI — Typer-based command-line interface.

Subcommands:
    scan     Run a penetration test against target(s)
    config   Manage configuration (show, set, reset)
    report   View or export scan reports
    version  Show version info
"""

from __future__ import annotations

import asyncio
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

# Silence litellm noise — must be set before any litellm import
os.environ.setdefault("LITELLM_LOG", "ERROR")
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")  # prevent network fetch at import

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

app = typer.Typer(
    name="phantom",
    help=(
        "[bold #dc2626]☠ PHANTOM[/] — Autonomous Adversary Simulation Platform\n\n"
        '[italic #f59e0b]" The Ghost in the Machine "[/]\n\n'
        "[dim]Quick start:[/]\n"
        "  [bold]phantom scan -t https://example.com[/]\n"
        "  [bold]phantom scan -t https://example.com -i 'test SQLi and XSS'[/]\n\n"
        "[dim]Run [bold]phantom scan --help[/] to see all scan options including [bold]--instruction[/], "
        "[bold]--scan-mode[/], [bold]--model[/], [bold]--output-format[/], and more.[/]"
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        import importlib.metadata
        try:
            ver = importlib.metadata.version("phantom-agent")
        except importlib.metadata.PackageNotFoundError:
            ver = "dev"
        console.print(f"[bold #dc2626]Phantom[/] [white]{ver}[/]")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", "-V",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Phantom — autonomous AI penetration testing agent."""


def _auto_install_completion() -> None:
    """Silently install shell completion on first run (never nags the user)."""
    marker = Path.home() / ".phantom" / ".completion_installed"
    if marker.exists():
        return
    try:
        import os
        import shellingham  # type: ignore[import]
        shell, _ = shellingham.detect_shell()
        # Use click's built-in completion install (typer wraps click)
        import click
        from click.shell_completion import add_completion_class  # noqa: F401
        # Build a minimal env-var name used by click for completion
        prog_name = "phantom"
        complete_var = f"_{prog_name.upper().replace('-', '_')}_COMPLETE"
        # Locate and write the completion script
        from typer._completion_shared import install as _install  # type: ignore[import]
        _install(shell=shell, prog_name=prog_name, complete_var=complete_var, echo=False)
    except Exception:
        # Completion install is best-effort; never crash the CLI for this.
        pass
    finally:
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
        except Exception:
            pass


# ──────────────────────────── Enums ────────────────────────────


class ScanMode(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"
    stealth = "stealth"
    api_only = "api_only"


class OutputFormat(str, Enum):
    json = "json"
    sarif = "sarif"
    markdown = "markdown"
    html = "html"


class UiVariant(str, Enum):
    auto = "auto"
    v1 = "v1"
    v2 = "v2"


# ──────────────────────────── scan ────────────────────────────


@app.command()
def scan(
    target: Annotated[
        list[str],
        typer.Option(
            "-t",
            "--target",
            help="Target to test (URL, repo, local path, domain, or IP). Repeatable.",
        ),
    ],
    instruction: Annotated[
        Optional[str],
        typer.Option(
            "--instruction",
            "-i",
            help="Custom instructions for the penetration test.",
        ),
    ] = None,
    instruction_file: Annotated[
        Optional[Path],
        typer.Option(
            "--instruction-file",
            help="Path to a file containing custom instructions.",
            exists=True,
            readable=True,
        ),
    ] = None,
    non_interactive: Annotated[
        bool,
        typer.Option(
            "-n",
            "--non-interactive",
            help="Run without TUI (exits on completion).",
        ),
    ] = False,
    scan_mode: Annotated[
        ScanMode,
        typer.Option(
            "-m",
            "--scan-mode",
            help="Scan depth: quick (CI/CD), standard, deep (default).",
        ),
    ] = ScanMode.deep,
    timeout: Annotated[
        Optional[int],
        typer.Option(
            "--timeout",
            help="Global scan timeout in seconds (0 = unlimited).",
        ),
    ] = None,
    output_format: Annotated[
        Optional[OutputFormat],
        typer.Option(
            "--output-format",
            "-o",
            help="Output format for the report.",
        ),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option(
            "--model",
            help="Override LLM model (e.g., 'groq/llama-3.3-70b-versatile').",
        ),
    ] = None,
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            help="Path to custom config file (JSON).",
            exists=True,
            readable=True,
        ),
    ] = None,
    auth_header: Annotated[
        Optional[list[str]],
        typer.Option(
            "--auth-header",
            "-H",
            help="Auth header for authenticated scanning (e.g. 'Authorization: Bearer TOKEN'). Repeatable.",
        ),
    ] = None,
    resume: Annotated[
        Optional[str],
        typer.Option(
            "--resume",
            help="Resume a previously interrupted scan by run name (e.g. 'example-com_a1b2').",
        ),
    ] = None,
    profile: Annotated[
        Optional[str],
        typer.Option(
            "--profile",
            "--preset",
            "-p",
            help="Scan profile preset: quick, standard, deep, stealth, api_only. "
                 "Applies scan-mode, max-iterations, timeout and other tuning knobs in one flag.",
        ),
    ] = None,
    ui: Annotated[
        UiVariant,
        typer.Option(
            "--ui",
            help="TUI variant: auto (from config), v1 (legacy), v2 (modular).",
        ),
    ] = UiVariant.auto,
) -> None:
    """
    Run a penetration test against one or more targets.

    Examples:
        phantom scan -t https://example.com
        phantom scan -t https://example.com -t 192.168.1.1 -m quick
        phantom scan -t ./my-project --non-interactive --output-format sarif
        phantom scan -t example.com --model groq/llama-3.3-70b-versatile --timeout 3600
        phantom scan -t example.com --profile deep
        phantom scan -t example.com --profile quick -n
    """
    import argparse

    # ── Apply profile preset (before any explicit overrides) ─────────────
    if profile is not None:
        try:
            from phantom.core.scan_profiles import get_profile as _get_profile
            _p = _get_profile(profile)
            # Only override scan_mode if the user didn't supply --scan-mode explicitly.
            # Typer doesn't expose "was this set by user?", so we check via the param.
            # Profile wins unless user also passed -m / --scan-mode (use profile default).
            scan_mode = ScanMode(_p.scan_mode)
            if timeout is None and _p.sandbox_timeout_s:
                timeout = _p.sandbox_timeout_s
        except KeyError:
            available = "quick, standard, deep, stealth, api_only"
            console.print(f"[red]Unknown profile '{profile}'. Available: {available}[/]")
            raise typer.Exit(1)
    # ─────────────────────────────────────────────────────────────────────

    if instruction and instruction_file:
        console.print("[red]Cannot specify both --instruction and --instruction-file[/]")
        raise typer.Exit(1)

    if instruction_file:
        instruction = instruction_file.read_text(encoding="utf-8").strip()
        if not instruction:
            console.print(f"[red]Instruction file '{instruction_file}' is empty[/]")
            raise typer.Exit(1)

    # If a profile was specified, also carry its max_iterations into the Namespace
    # so cli.py / tui.py can pick it up.
    _profile_max_iter: int | None = None
    if profile is not None:
        try:
            from phantom.core.scan_profiles import get_profile as _get_profile2
            _profile_max_iter = _get_profile2(profile).max_iterations
        except Exception:  # noqa: BLE001
            pass

    # Build a legacy argparse.Namespace for backward compatibility
    args = argparse.Namespace(
        target=target,
        instruction=instruction,
        instruction_file=None,  # Already read above
        non_interactive=non_interactive,
        scan_mode=scan_mode.value,
        config=str(config_file) if config_file else None,
        output_format=output_format.value if output_format else None,
        timeout=timeout,
        auth_headers=auth_header or [],
        resume_run=resume,
        ui_variant=ui.value,
        profile_max_iterations=_profile_max_iter,  # None if no profile
    )

    # Delegate to existing main logic
    from phantom.config import Config, apply_saved_config, save_current_config
    from phantom.interface.main import (
        apply_config_override,
        check_docker_installed,
        display_completion_message,
        persist_config,
        pull_docker_image,
        validate_environment,
    )
    from phantom.interface.utils import (
        assign_workspace_subdirs,
        collect_local_sources,
        generate_run_name,
        infer_target_type,
        rewrite_localhost_targets,
    )
    from phantom.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME

    # Apply UTF-8 output and silently install shell completion (background, non-blocking)
    import threading

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    threading.Thread(target=_auto_install_completion, daemon=True).start()

    # Force-apply saved config so `phantom config set ...` reliably affects scans
    # even if the current shell inherited stale env values.
    apply_saved_config(force=True)

    if ui == UiVariant.auto:
        args.ui_variant = (Config.get("phantom_tui_variant") or "v2").strip().lower()
    elif ui in (UiVariant.v1, UiVariant.v2):
        args.ui_variant = ui.value
    else:
        args.ui_variant = "v2"

    # Explicit CLI overrides must win over saved config for this run.
    if model:
        import os

        os.environ["PHANTOM_LLM"] = model

    if timeout is not None:
        import os

        os.environ["PHANTOM_SANDBOX_EXECUTION_TIMEOUT"] = str(timeout)
    import os
    os.environ["PHANTOM_TUI_VARIANT"] = args.ui_variant

    if args.config:
        apply_config_override(args.config)

    # Process targets
    args.targets_info = []
    for t in args.target:
        try:
            target_type, target_dict = infer_target_type(t)
            display_target = (
                target_dict.get("target_path", t) if target_type == "local_code" else t
            )
            args.targets_info.append(
                {"type": target_type, "details": target_dict, "original": display_target}
            )
        except ValueError:
            console.print(f"[red]Invalid target: '{t}'[/]")
            raise typer.Exit(1)

    assign_workspace_subdirs(args.targets_info)
    rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

    check_docker_installed()
    pull_docker_image()
    validate_environment()

    try:
        asyncio.run(_async_scan(args))
    except KeyboardInterrupt:
        pass
    except Exception:
        raise

    results_path = Path("phantom_runs") / args.run_name
    display_completion_message(args, results_path)

    if non_interactive:
        from phantom.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            raise typer.Exit(2)


async def _async_scan(args: object) -> None:
    """Run warm-up + scan in a single event loop."""
    from phantom.interface.main import persist_config, warm_up_llm
    from phantom.interface.utils import clone_repository, collect_local_sources, generate_run_name

    await warm_up_llm()
    persist_config()

    # Use checkpoint run_name if resuming; otherwise generate a fresh one
    resume_run = getattr(args, "resume_run", None)
    if resume_run:
        args.run_name = resume_run  # type: ignore[attr-defined]
    else:
        args.run_name = generate_run_name(args.targets_info)  # type: ignore[attr-defined]

    for target_info in args.targets_info:  # type: ignore[attr-defined]
        if target_info["type"] == "repository":
            repo_url = target_info["details"]["target_repo"]
            dest_name = target_info["details"].get("workspace_subdir")
            cloned_path = clone_repository(repo_url, args.run_name, dest_name)  # type: ignore[attr-defined]
            target_info["details"]["cloned_repo_path"] = cloned_path

    args.local_sources = collect_local_sources(args.targets_info)  # type: ignore[attr-defined]

    if args.non_interactive:  # type: ignore[attr-defined]
        from phantom.interface.cli import run_cli

        await run_cli(args)
    else:
        from phantom.interface.tui import run_tui

        await run_tui(args)


# ──────────────────────────── resume helpers ────────────────────────────


def _list_resumable_runs() -> list:
    """Return resumable run dirs sorted by mtime descending (newest first).

    This is the single source of truth for numeric ID assignment so that
    ``phantom resume 2`` and ``phantom resumes-delete 2`` always refer to
    the same run as row #2 in ``phantom resumes``.
    """
    import datetime
    from pathlib import Path
    from phantom.checkpoint.checkpoint import CheckpointManager

    runs_dir = Path("phantom_runs")
    if not runs_dir.exists():
        return []

    rows: list[tuple[float, Path]] = []
    for run_dir in runs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        cp_file = run_dir / "checkpoint.json"
        if not cp_file.exists():
            continue
        try:
            cp_mgr = CheckpointManager(run_dir)
            cp = cp_mgr.load()
            if cp is None or cp.status == "completed":
                continue
            rows.append((cp_file.stat().st_mtime, run_dir))
        except Exception:  # noqa: BLE001
            continue

    rows.sort(key=lambda r: r[0], reverse=True)  # newest first
    return [run_dir for _ts, run_dir in rows]


def _resolve_run_name(target: str) -> "Path | None":
    """Resolve a numeric ID or exact run name to a run directory.

    Returns the ``Path`` for the run directory, or ``None`` if not found.
    """
    from pathlib import Path

    resumable = _list_resumable_runs()

    if target.isdigit():
        idx = int(target) - 1  # 1-based → 0-based
        if 0 <= idx < len(resumable):
            return resumable[idx]
        return None

    runs_dir = Path("phantom_runs")
    candidate = runs_dir / target
    if candidate.is_dir() and (candidate / "checkpoint.json").exists():
        return candidate
    return None


# ──────────────────────────── resume ────────────────────────────


@app.command()
def resume(
    run_name: Annotated[
        str,
        typer.Argument(
            help="Run name or #ID (from 'phantom resumes') to resume. E.g. 'example-com_a1b2' or '2'."
        ),
    ],
    non_interactive: Annotated[
        bool,
        typer.Option(
            "-n",
            "--non-interactive",
            help="Run without TUI (exits on completion).",
        ),
    ] = False,
    scan_mode: Annotated[
        ScanMode,
        typer.Option(
            "-m",
            "--scan-mode",
            help="Scan depth mode.",
        ),
    ] = ScanMode.deep,
    model: Annotated[
        Optional[str],
        typer.Option(
            "--model",
            help="Override LLM model.",
        ),
    ] = None,
) -> None:
    """
    Resume an interrupted or in-progress scan.

    Examples:
        phantom resume example-com_a1b2
        phantom resumes    # list all resumable runs first
    """
    import argparse

    from pathlib import Path
    from phantom.checkpoint.checkpoint import CheckpointManager, CHECKPOINT_INTERVAL

    # Resolve numeric ID (e.g. "2") to an actual run name.
    resolved = _resolve_run_name(run_name)
    if resolved is None:
        if run_name.isdigit():
            console.print(
                f"[bold red]Cannot resume:[/] no resumable run with ID [cyan]{run_name}[/]."
            )
        else:
            console.print(
                f"[bold red]Cannot resume:[/] no checkpoint found for run [cyan]{run_name}[/]."
            )
        console.print("[dim]Use [bold]phantom resumes[/] to list all available runs.[/]")
        raise typer.Exit(1)

    # If the user passed a numeric ID, tell them which run it resolved to.
    if run_name.isdigit():
        console.print(f"[dim]Resolved #{run_name} → [cyan]{resolved.name}[/][/]")

    run_name = resolved.name
    run_dir = resolved
    cp_mgr = CheckpointManager(run_dir)
    cp = cp_mgr.load()

    if cp is None:
        console.print(f"[bold red]Cannot resume:[/] no checkpoint found for run [cyan]{run_name}[/].")
        console.print("[dim]Use [bold]phantom resumes[/] to list all available runs.[/]")
        raise typer.Exit(1)

    if cp.status == "completed":
        console.print(
            f"[yellow]Run [cyan]{run_name}[/] is already [bold]completed[/]. Nothing to resume.[/]"
        )
        raise typer.Exit(0)

    targets_info = cp.scan_config.get("targets", [])
    if not targets_info:
        console.print(
            f"[red]Checkpoint for [cyan]{run_name}[/] has no target info — cannot auto-resume.[/]\n"
            "[dim]Please re-run [bold]phantom scan -t <target>[/] manually.[/]"
        )
        raise typer.Exit(1)

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    import threading
    threading.Thread(target=_auto_install_completion, daemon=True).start()

    from phantom.config import apply_saved_config
    from phantom.interface.main import (
        check_docker_installed,
        display_completion_message,
        pull_docker_image,
        validate_environment,
    )
    from phantom.interface.utils import collect_local_sources, rewrite_localhost_targets
    from phantom.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME

    # Same precedence policy as `scan`: saved config first, explicit --model after.
    apply_saved_config(force=True)
    if model:
        import os
        os.environ["PHANTOM_LLM"] = model
    check_docker_installed()
    pull_docker_image()
    validate_environment()

    # Restore targets from checkpoint and rewrite localhost refs
    rewrite_localhost_targets(targets_info, HOST_GATEWAY_HOSTNAME)
    local_sources = collect_local_sources(targets_info)

    args = argparse.Namespace(
        target=[t.get("original", "") for t in targets_info],
        instruction=cp.scan_config.get("user_instructions") or None,
        instruction_file=None,
        non_interactive=non_interactive,
        scan_mode=scan_mode.value,
        config=None,
        output_format=None,
        timeout=None,
        auth_headers=[],
        resume_run=run_name,
        targets_info=targets_info,
        local_sources=local_sources,
    )

    try:
        asyncio.run(_async_scan(args))
    except KeyboardInterrupt:
        pass
    except Exception:
        raise

    results_path = Path("phantom_runs") / run_name
    display_completion_message(args, results_path)

    if non_interactive:
        from phantom.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            raise typer.Exit(2)


# ──────────────────────────── resumes ────────────────────────────


@app.command()
def resumes(
    sort: Annotated[
        str,
        typer.Option(
            "--sort",
            help="Sort order: 'newest' (default), 'oldest', 'vulns' (most vulns first), 'target'.",
        ),
    ] = "newest",
) -> None:
    """
    List all scan runs that can be resumed (interrupted or in-progress).

    Examples:
        phantom resumes
        phantom resumes --sort vulns
        phantom resumes --sort target
        phantom resume <run-name>
        phantom resumes-delete <id>      # remove a checkpoint by number
    """
    import datetime
    from pathlib import Path

    from rich.table import Table

    from phantom.checkpoint.checkpoint import CheckpointManager

    runs_dir = Path("phantom_runs")
    if not runs_dir.exists():
        console.print("[dim]No scan runs found. Run [bold]phantom scan[/] first.[/]")
        return

    table = Table(
        title="[bold]Resumable Scans",
        show_lines=False,
        header_style="bold dim",
    )
    table.add_column("#", style="bold dim", justify="right", no_wrap=True)
    table.add_column("Run Name", style="cyan")
    table.add_column("Status", no_wrap=True)
    table.add_column("Target")
    table.add_column("Iters", style="dim", justify="right")
    table.add_column("Vulns", style="green", justify="right")
    table.add_column("Last Saved", style="dim")

    _STATUS_STYLE: dict[str, str] = {
        "in_progress": "[bold yellow]in_progress[/]",
        "interrupted": "[bold red]interrupted[/]",
        "crashed": "[bold red]crashed[/]",
    }

    # Collect all resumable runs first so we can apply --sort.
    _rows: list[tuple] = []
    for run_dir in runs_dir.iterdir():
        if not run_dir.is_dir():
            continue
        cp_file = run_dir / "checkpoint.json"
        if not cp_file.exists():
            continue
        try:
            cp_mgr = CheckpointManager(run_dir)
            cp = cp_mgr.load()
            if cp is None or cp.status == "completed":
                continue

            targets = cp.scan_config.get("targets", [])
            target_strs = [t.get("original", "?") for t in targets[:2]]
            target_display = ", ".join(target_strs)
            if len(targets) > 2:
                target_display += f" (+{len(targets) - 2} more)"

            mtime_ts = cp_file.stat().st_mtime
            mtime = datetime.datetime.fromtimestamp(
                mtime_ts, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M")

            status_display = _STATUS_STYLE.get(cp.status, cp.status)
            vuln_count = len(cp.vulnerability_reports)

            _rows.append((run_dir.name, status_display, target_display or "?", cp.iteration, vuln_count, mtime, mtime_ts))
        except Exception:  # noqa: BLE001
            continue

    # Apply sort.
    sort_key = sort.lower()
    if sort_key == "oldest":
        _rows.sort(key=lambda r: r[6])  # mtime_ts ascending
    elif sort_key == "vulns":
        _rows.sort(key=lambda r: r[4], reverse=True)  # vuln_count descending
    elif sort_key == "target":
        _rows.sort(key=lambda r: r[2].lower())  # target_display alphabetical
    else:  # "newest" default
        _rows.sort(key=lambda r: r[6], reverse=True)

    found_any = False
    row_num = 1
    for (run_name_r, status_display, target_display, iteration, vuln_count, mtime, _ts) in _rows:
        table.add_row(
            str(row_num),
            run_name_r,
            status_display,
            target_display,
            str(iteration),
            str(vuln_count),
            mtime,
        )
        found_any = True
        row_num += 1

    if not found_any:
        console.print("[dim]No resumable scans found (all scans are completed or no checkpoints).[/]")
        return

    console.print(table)
    console.print(
        "\n[dim]Resume a scan with:[/] [bold]phantom resume [cyan]<run-name>[/][/]"
    )
    console.print(
        "[dim]Delete a checkpoint with:[/] [bold]phantom resumes-delete [cyan]<#id or run-name>[/][/]"
    )


@app.command("resumes-delete")
def resumes_delete(
    target: Annotated[
        str,
        typer.Argument(
            help="ID number (from 'phantom resumes') or exact run name to delete."
        ),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """
    Delete a checkpoint / resume entry.

    Use the # ID shown by 'phantom resumes', or the exact run name.

    Examples:
        phantom resumes-delete 1
        phantom resumes-delete example-com_a1b2
        phantom resumes-delete 3 --yes
    """
    import shutil
    from pathlib import Path

    runs_dir = Path("phantom_runs")
    if not runs_dir.exists():
        console.print("[dim]No scan runs found.[/]")
        raise typer.Exit(0)

    # Resolve target → run directory (shared logic, mtime-sorted to match 'phantom resumes').
    run_dir_to_delete = _resolve_run_name(target)
    if run_dir_to_delete is None:
        if target.isdigit():
            console.print(f"[red]No resumable run with ID {target}. Run 'phantom resumes' to see IDs.[/]")
        else:
            console.print(f"[red]Run '{target}' not found or has no checkpoint.[/]")
        raise typer.Exit(1)


    # Confirm before deleting
    if not yes:
        confirm = typer.confirm(
            f"Delete checkpoint for run '[cyan]{run_dir_to_delete.name}[/]'? "
            "This cannot be undone."
        )
        if not confirm:
            console.print("[dim]Aborted.[/]")
            raise typer.Exit(0)

    shutil.rmtree(run_dir_to_delete)
    console.print(f"[green]Deleted checkpoint:[/] {run_dir_to_delete.name}")


# ──────────────────────────── Report Renderers ────────────────────────────


def _render_markdown_report(run_name: str, data: dict) -> str:
    """Render scan data as a Markdown report."""
    import datetime

    vulns = data.get("vulnerabilities", [])
    target = data.get("target", data.get("targets", [run_name])[0] if data.get("targets") else run_name)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns_sorted = sorted(vulns, key=lambda v: sev_order.get(str(v.get("severity", "info")).lower(), 5))

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns_sorted:
        sev = str(v.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    lines = [
        f"# Phantom Security Report: `{target}`",
        f"",
        f"> **Run:** `{run_name}`  ",
        f"> **Generated:** {now}  ",
        f"> **Total Findings:** {len(vulns)}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| Critical | {counts['critical']} |",
        f"| High     | {counts['high']} |",
        f"| Medium   | {counts['medium']} |",
        f"| Low      | {counts['low']} |",
        f"| Info     | {counts['info']} |",
        f"",
    ]

    if vulns_sorted:
        lines += ["## Findings", ""]
        for i, v in enumerate(vulns_sorted, 1):
            name = v.get("name", v.get("title", "Unknown"))
            sev = str(v.get("severity", "info")).upper()
            endpoint = v.get("endpoint", v.get("url", ""))
            desc = v.get("description", "")
            payload = v.get("payload", "")
            remediation = v.get("remediation", "")

            lines += [
                f"### {i}. {name}",
                f"",
                f"**Severity:** `{sev}`  ",
                f"**Endpoint:** `{endpoint}`  ",
                f"",
                f"{desc}",
                f"",
            ]
            if payload:
                lines += [f"**Payload:**", f"```", f"{payload}", f"```", f""]
            if remediation:
                lines += [f"**Remediation:** {remediation}", f""]
            lines.append("---")
            lines.append("")
    else:
        lines += ["## Findings", "", "_No vulnerabilities found._", ""]

    return "\n".join(lines)


def _render_html_report(run_name: str, data: dict) -> str:
    """Render scan data as a self-contained HTML report."""
    import datetime
    import html as html_lib

    vulns = data.get("vulnerabilities", [])
    target = data.get("target", run_name)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns_sorted = sorted(vulns, key=lambda v: sev_order.get(str(v.get("severity", "info")).lower(), 5))

    sev_colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#65a30d", "info": "#2563eb"}
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns_sorted:
        sev = str(v.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    vuln_rows = ""
    for i, v in enumerate(vulns_sorted, 1):
        name = html_lib.escape(str(v.get("name", "Unknown")))
        sev = str(v.get("severity", "info")).lower()
        color = sev_colors.get(sev, "#64748b")
        endpoint = html_lib.escape(str(v.get("endpoint", "")))
        desc = html_lib.escape(str(v.get("description", "")))
        payload = html_lib.escape(str(v.get("payload", "")))
        remediation = html_lib.escape(str(v.get("remediation", "")))

        vuln_rows += f"""
        <div class="finding" id="finding-{i}">
          <h3><span class="badge" style="background:{color}">{sev.upper()}</span> {i}. {name}</h3>
          <p><strong>Endpoint:</strong> <code>{endpoint}</code></p>
          <p>{desc}</p>
          {"<p><strong>Payload:</strong> <code>" + payload + "</code></p>" if payload else ""}
          {"<p><strong>Remediation:</strong> " + remediation + "</p>" if remediation else ""}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Report: {html_lib.escape(target)}</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }}
  h1 {{ color: #dc2626; border-bottom: 2px solid #dc2626; padding-bottom: .5rem; }}
  h2 {{ color: #a78bfa; margin-top: 2rem; }}
  h3 {{ color: #e2e8f0; }}
  .meta {{ color: #94a3b8; font-size: .9rem; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .sev-card {{ padding: .75rem 1.5rem; border-radius: .5rem; text-align:center; }}
  .finding {{ background: #1e293b; border-radius: .5rem; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid #dc2626; }}
  .badge {{ display: inline-block; padding: .2rem .6rem; border-radius: .25rem; color: white; font-size:.8rem; font-weight:700; margin-right:.5rem; }}
  code {{ background: #0f172a; padding: .1rem .4rem; border-radius:.25rem; font-size:.9em; }}
  footer {{ color: #475569; font-size: .8rem; margin-top: 3rem; text-align: center; }}
</style>
</head>
<body>
<h1>☠ PHANTOM — Security Report</h1>
<div class="meta">
  <strong>Target:</strong> {html_lib.escape(target)} &nbsp;|&nbsp;
  <strong>Run:</strong> {html_lib.escape(run_name)} &nbsp;|&nbsp;
  <strong>Generated:</strong> {now}
</div>
<h2>Summary</h2>
<div class="summary">
  <div class="sev-card" style="background:#dc262622;border:1px solid #dc2626"><div style="font-size:2rem;font-weight:700;color:#dc2626">{counts["critical"]}</div>Critical</div>
  <div class="sev-card" style="background:#ea580c22;border:1px solid #ea580c"><div style="font-size:2rem;font-weight:700;color:#ea580c">{counts["high"]}</div>High</div>
  <div class="sev-card" style="background:#d9770622;border:1px solid #d97706"><div style="font-size:2rem;font-weight:700;color:#d97706">{counts["medium"]}</div>Medium</div>
  <div class="sev-card" style="background:#65a30d22;border:1px solid #65a30d"><div style="font-size:2rem;font-weight:700;color:#65a30d">{counts["low"]}</div>Low</div>
  <div class="sev-card" style="background:#2563eb22;border:1px solid #2563eb"><div style="font-size:2rem;font-weight:700;color:#2563eb">{counts["info"]}</div>Info</div>
</div>
<h2>Findings ({len(vulns_sorted)})</h2>
{"".join(["<p><em>No vulnerabilities found.</em></p>"]) if not vulns_sorted else vuln_rows}
<footer>Generated by <strong>Phantom</strong> — Autonomous Adversary Simulation Platform | <a href="https://github.com/Usta0x001/Phantom" style="color:#dc2626">github.com/Usta0x001/Phantom</a></footer>
</body>
</html>"""


# ──────────────────────────── config ────────────────────────────

config_app = typer.Typer(help="Manage Phantom configuration.", no_args_is_help=True)
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(
    include_env: Annotated[
        bool,
        typer.Option(
            "--include-env",
            help="Include current process environment variables in the output.",
        ),
    ] = False,
) -> None:
    """Display current configuration.

    By default, this shows Phantom's saved config file values plus built-in defaults.
    Use --include-env to also include current environment variable overrides.
    """
    import os
    from phantom.config import Config

    saved = Config.load()
    saved_vars: dict[str, str] = saved.get("env", {}) or {}

    # Build the full active configuration:
    # 1. Start with all tracked variables that have non-None values (env or default)
    # 2. Mark each row with its source: [env] set in environment, [saved] from config
    #    file, [default] from built-in defaults
    from rich.table import Table

    table = Table(title="Phantom Configuration", show_lines=True)
    table.add_column("Variable", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Source", style="dim")

    rows: dict[str, tuple[str, str]] = {}  # key → (value, source)

    # Walk every tracked var in the Config class
    for attr_name in Config._tracked_names():
        key = attr_name.upper()
        default = getattr(Config, attr_name, None)
        env_val = os.environ.get(key) if include_env else None
        saved_val = saved_vars.get(key)

        if env_val is not None:
            # Source is "saved" only when the active env value equals what was saved
            # (meaning apply_saved() loaded it). If they differ, env overrides saved.
            if saved_val is not None and saved_val == env_val:
                source = "saved"
            else:
                source = "env"
            rows[key] = (env_val, source)
        elif saved_val is not None:
            rows[key] = (saved_val, "saved")
        elif default is not None:
            rows[key] = (default, "default")
        # else: skip — completely unset with no default

    if not rows:
        console.print("[dim]No configuration found. Use 'phantom config set KEY VALUE' to configure.[/]")
        return

    _source_style = {"env": "bold green", "saved": "yellow", "default": "dim"}
    for key, (value, source) in sorted(rows.items()):
        # Mask secrets
        display_value = value
        if any(s in key.lower() for s in ("key", "token", "secret", "password")):
            display_value = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
        style = _source_style.get(source, "")
        table.add_row(key, display_value, f"[{style}]{source}[/]")

    console.print(table)
    if include_env:
        console.print(
            f"[dim]Showing {len(rows)} variables  "
            "[bold green]env[/][dim]=active in env  "
            "[yellow]saved[/][dim]=saved config  "
            "default=built-in default[/]"
        )
    else:
        console.print(
            f"[dim]Showing {len(rows)} variables  "
            "[yellow]saved[/][dim]=saved config  "
            "default=built-in default  "
            "(use --include-env to display env overrides)[/]"
        )


@config_app.command("set")
def config_set(
    key: Annotated[str, typer.Argument(help="Configuration variable name (e.g., PHANTOM_LLM)")],
    value: Annotated[str, typer.Argument(help="Value to set")],
) -> None:
    """Set a configuration variable."""
    import os

    from phantom.config import Config

    key_upper = key.upper()
    if key_upper not in Config.tracked_vars():
        console.print(f"[yellow]Warning: '{key_upper}' is not a known config variable.[/]")
        console.print(f"[dim]Known variables: {', '.join(sorted(Config.tracked_vars()))}[/]")

    # Write directly to the config JSON so that even _NON_PERSISTENT keys are
    # saved when the user explicitly requests it via `phantom config set`.
    os.environ[key_upper] = value
    existing = Config.load().get("env", {})
    existing[key_upper] = value
    Config.save({"env": existing})

    # Keep configuration local to Phantom only.
    # Do NOT write system/user environment variables (e.g., `setx` on Windows).
    console.print(f"[green]Set {key_upper}[/] [dim](saved in Phantom config only)[/]")


@config_app.command("reset")
def config_reset() -> None:
    """Reset all saved configuration."""
    from phantom.config import Config

    Config.save({"env": {}})
    console.print("[green]Configuration reset to defaults.[/]")


# ──────────────────────────── report ────────────────────────────

report_app = typer.Typer(help="View and export scan reports.", no_args_is_help=True)
app.add_typer(report_app, name="report")


@report_app.command("list")
def report_list() -> None:
    """List all scan reports (completed and in-progress)."""
    import datetime
    from pathlib import Path

    from rich.table import Table

    from phantom.checkpoint.checkpoint import CheckpointManager

    runs_dir = Path("phantom_runs")
    if not runs_dir.exists():
        console.print("[dim]No scan reports found. Run 'phantom scan' first.[/]")
        return

    run_dirs = [d for d in sorted(runs_dir.iterdir(), reverse=True) if d.is_dir()]
    if not run_dirs:
        console.print("[dim]No scan reports found.[/]")
        return

    _STATUS_STYLE: dict[str, str] = {
        "completed": "[bold green]completed[/]",
        "in_progress": "[bold yellow]in_progress[/]",
        "interrupted": "[bold red]interrupted[/]",
        "crashed": "[bold red]crashed[/]",
    }

    table = Table(
        title="[bold]Phantom Scan Reports",
        show_lines=False,
        header_style="bold dim",
    )
    table.add_column("#", style="bold dim", justify="right", no_wrap=True)
    table.add_column("Run Name", style="cyan")
    table.add_column("Status", no_wrap=True)
    table.add_column("Target")
    table.add_column("Vulns", style="green", justify="right")
    table.add_column("Iters", style="dim", justify="right")
    table.add_column("Created", style="dim")

    for idx, run_dir in enumerate(run_dirs, 1):
        cp_file = run_dir / "checkpoint.json"
        stat = run_dir.stat()
        created = datetime.datetime.fromtimestamp(
            stat.st_mtime, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M")

        status_str = "[dim]no checkpoint[/]"
        target_str = "[dim]unknown[/]"
        vuln_str = "-"
        iter_str = "-"

        if cp_file.exists():
            try:
                cp_mgr = CheckpointManager(run_dir)
                cp = cp_mgr.load()
                if cp is not None:
                    status_str = _STATUS_STYLE.get(cp.status, cp.status)
                    targets = cp.scan_config.get("targets", [])
                    target_strs = [t.get("original", "?") for t in targets[:2]]
                    target_str = ", ".join(target_strs)
                    if len(targets) > 2:
                        target_str += f" (+{len(targets) - 2})"
                    vuln_str = str(len(cp.vulnerability_reports))
                    iter_str = str(cp.iteration)
            except Exception:  # noqa: BLE001
                pass

        table.add_row(
            str(idx),
            run_dir.name,
            status_str,
            target_str,
            vuln_str,
            iter_str,
            created,
        )

    console.print(table)
    console.print(
        "\n[dim]Export a report:[/] [bold]phantom report export [cyan]<run-name>[/] --format markdown[/]"
    )
    console.print(
        "[dim]Delete a report:[/] [bold]phantom report delete [cyan]<#id or run-name>[/][/]"
    )


@report_app.command("delete")
def report_delete(
    target: Annotated[
        str,
        typer.Argument(
            help="ID number (from 'phantom report list') or exact run name to delete."
        ),
    ],
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompt."),
    ] = False,
) -> None:
    """
    Permanently delete a scan run directory (checkpoint + all reports).

    Use the # ID shown by 'phantom report list', or the exact run name.

    Examples:
        phantom report delete 1
        phantom report delete example-com_a1b2
        phantom report delete 3 --yes
    """
    import shutil
    from pathlib import Path

    runs_dir = Path("phantom_runs")
    if not runs_dir.exists():
        console.print("[dim]No scan reports found.[/]")
        raise typer.Exit(0)

    run_dirs = [d for d in sorted(runs_dir.iterdir(), reverse=True) if d.is_dir()]

    run_dir_to_delete: Path | None = None
    if target.isdigit():
        idx = int(target) - 1  # 1-based → 0-based
        if 0 <= idx < len(run_dirs):
            run_dir_to_delete = run_dirs[idx]
        else:
            console.print(
                f"[red]No report with ID {target}. "
                "Run 'phantom report list' to see IDs.[/]"
            )
            raise typer.Exit(1)
    else:
        candidate = runs_dir / target
        if candidate.is_dir():
            run_dir_to_delete = candidate
        else:
            console.print(f"[red]Run '{target}' not found in phantom_runs/.[/]")
            raise typer.Exit(1)

    if not yes:
        confirm = typer.confirm(
            f"Permanently delete ALL data for run '{run_dir_to_delete.name}'? "
            "This cannot be undone."
        )
        if not confirm:
            console.print("[dim]Aborted.[/]")
            raise typer.Exit(0)

    shutil.rmtree(run_dir_to_delete)
    console.print(f"[green]Deleted:[/] {run_dir_to_delete.name}")


@report_app.command("export")
def report_export(
    run_name: Annotated[str, typer.Argument(help="Name of the scan run to export")],
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Export format"),
    ] = OutputFormat.json,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
) -> None:
    """Export a scan report in the specified format."""
    runs_dir = Path("phantom_runs") / run_name
    if not runs_dir.exists():
        console.print(f"[red]Run '{run_name}' not found in phantom_runs/[/]")
        raise typer.Exit(1)

    console.print(f"[dim]Exporting {run_name} as {fmt.value}...[/]")

    # Find the report JSON
    report_files = list(runs_dir.glob("**/*.json"))
    if not report_files:
        console.print("[red]No report data found in this run.[/]")
        raise typer.Exit(1)

    if fmt == OutputFormat.sarif:
        try:
            from phantom.interface.formatters.sarif_formatter import SARIFFormatter

            formatter = SARIFFormatter()
            import json

            data = json.loads(report_files[0].read_text(encoding="utf-8"))
            sarif_output = formatter.format(data)
            out_path = output or (runs_dir / f"{run_name}.sarif.json")
            out_path.write_text(json.dumps(sarif_output, indent=2), encoding="utf-8")
            console.print(f"[green]SARIF report written to {out_path}[/]")
        except ImportError:
            console.print("[red]SARIF formatter not available.[/]")
            raise typer.Exit(1)
    elif fmt == OutputFormat.json:
        import json
        import shutil

        out_path = output or (runs_dir / f"{run_name}_export.json")
        shutil.copy2(report_files[0], out_path)
        console.print(f"[green]JSON report written to {out_path}[/]")
    elif fmt == OutputFormat.markdown:
        import json

        data = json.loads(report_files[0].read_text(encoding="utf-8"))
        md_content = _render_markdown_report(run_name, data)
        out_path = output or (runs_dir / f"{run_name}.md")
        out_path.write_text(md_content, encoding="utf-8")
        console.print(f"[green]Markdown report written to {out_path}[/]")
    elif fmt == OutputFormat.html:
        import json

        data = json.loads(report_files[0].read_text(encoding="utf-8"))
        html_content = _render_html_report(run_name, data)
        out_path = output or (runs_dir / f"{run_name}.html")
        out_path.write_text(html_content, encoding="utf-8")
        console.print(f"[green]HTML report written to {out_path}[/]")
    else:
        console.print(f"[yellow]Unknown export format: '{fmt.value}'[/]")


# ──────────────────────────── version ────────────────────────────


@app.command()
def version() -> None:
    """Show Phantom version and system info."""
    try:
        from importlib.metadata import version as get_version

        ver = get_version("phantom-agent")
    except Exception:
        ver = "development"

    import platform
    import shutil

    has_docker = shutil.which("docker") is not None

    info = Text()
    info.append(f"☠ PHANTOM v{ver}\n", style="bold #dc2626")
    info.append('" The Ghost in the Machine "\n', style="italic #f59e0b")
    info.append(f"Python {platform.python_version()}\n", style="dim")
    info.append(f"Platform {platform.system()} {platform.machine()}\n", style="dim")
    info.append(f"Docker {'available' if has_docker else 'NOT FOUND'}", style="green" if has_docker else "red")

    console.print(
        Panel(info, title="[bold #dc2626]☠ PHANTOM", border_style="#dc2626", padding=(1, 2))
    )


# ──────────────────────────── profiles ────────────────────────────


@app.command()
def profiles() -> None:
    """Show available scan profiles and their settings."""
    from rich.table import Table

    from phantom.core.scan_profiles import list_profiles, get_profile

    table = Table(
        title="[bold #dc2626]☠ Phantom Scan Profiles[/]",
        show_lines=True,
        border_style="#dc2626",
    )
    table.add_column("Profile", style="bold #f59e0b")
    table.add_column("Max Iterations", justify="center")
    table.add_column("Timeout (s)", justify="center")
    table.add_column("Effort", justify="center")
    table.add_column("Browser", justify="center")
    table.add_column("Priority Tools", style="dim")
    table.add_column("Skip Tools", style="red dim")

    for p_info in list_profiles():
        p = get_profile(p_info["name"])
        table.add_row(
            p.name,
            str(p.max_iterations),
            str(p.sandbox_timeout_s),
            p.reasoning_effort,
            "✓" if p.enable_browser else "✗",
            ", ".join(p.priority_tools[:3]) + ("..." if len(p.priority_tools) > 3 else "") if p.priority_tools else "-",
            ", ".join(p.skip_tools) if p.skip_tools else "-",
        )

    console.print(table)


@app.command("doctor")
def doctor() -> None:
    """Show quick diagnostics and discovery hints for the CLI experience."""
    from phantom.config import Config

    configured_model = Config.get("phantom_llm") or "(not set)"
    ui_variant = Config.get("phantom_tui_variant") or "v2"
    info = Text()
    info.append("CLI Doctor\n", style="bold #dc2626")
    info.append("Configured model: ", style="dim")
    info.append(f"{configured_model}\n")
    info.append("Default UI variant: ", style="dim")
    info.append(f"{ui_variant}\n")
    info.append("\nHelpful commands:\n", style="bold")
    info.append("  phantom profiles\n", style="#f59e0b")
    info.append("  phantom scan --preset deep -t https://example.com\n", style="#f59e0b")
    info.append("  phantom scan --ui v2 -t https://example.com\n", style="#f59e0b")
    info.append("  phantom config show --include-env\n", style="#f59e0b")
    console.print(Panel(info, border_style="#dc2626", padding=(1, 2)))


# ──────────────────────────── diff ────────────────────────────


@app.command()
def diff(
    run1: Annotated[str, typer.Argument(help="First scan run name (baseline)")],
    run2: Annotated[str, typer.Argument(help="Second scan run name (current)")],
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output file for diff report"),
    ] = None,
    open_browser: Annotated[
        bool,
        typer.Option(
            "--open",
            help="Auto-open the output file in the default browser / viewer after writing.",
        ),
    ] = False,
) -> None:
    """Compare two scan runs and show new, fixed, and persistent vulnerabilities."""
    from phantom.core.diff_scanner import DiffScanner

    runs_dir = Path("phantom_runs")
    dir1 = runs_dir / run1
    dir2 = runs_dir / run2

    if not dir1.exists():
        console.print(f"[red]Run '{run1}' not found in phantom_runs/[/]")
        raise typer.Exit(1)
    if not dir2.exists():
        console.print(f"[red]Run '{run2}' not found in phantom_runs/[/]")
        raise typer.Exit(1)

    scanner = DiffScanner()
    report = scanner.compare(str(dir1), str(dir2))

    if hasattr(report, "to_markdown"):
        diff_content = report.to_markdown()
    else:
        diff_content = str(report)

    if output:
        output.write_text(diff_content, encoding="utf-8")
        console.print(f"[green]Diff report written to {output}[/]")
        if open_browser:
            import webbrowser
            webbrowser.open(output.resolve().as_uri())
            console.print(f"[dim]Opened {output.resolve()} in browser.[/]")
    else:
        console.print(diff_content)


# ──────────────────────────── entry point ────────────────────────────


def cli_main() -> None:
    """Entry point for the Phantom CLI."""
    # Ensure UTF-8 output on Windows (handles emoji/unicode in banner & help text)
    if sys.platform == "win32":
        import io

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        else:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        else:
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    app()


if __name__ == "__main__":
    cli_main()
