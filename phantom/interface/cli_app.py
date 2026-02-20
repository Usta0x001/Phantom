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
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

app = typer.Typer(
    name="phantom",
    help='☠ PHANTOM — Autonomous Offensive Security Intelligence\n\n" Why So Serious ?! "',
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=True,
)


# ──────────────────────────── Enums ────────────────────────────


class ScanMode(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


class OutputFormat(str, Enum):
    json = "json"
    sarif = "sarif"
    markdown = "markdown"
    html = "html"


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
) -> None:
    """
    Run a penetration test against one or more targets.

    Examples:
        phantom scan -t https://example.com
        phantom scan -t https://example.com -t 192.168.1.1 -m quick
        phantom scan -t ./my-project --non-interactive --output-format sarif
        phantom scan -t example.com --model groq/llama-3.3-70b-versatile --timeout 3600
    """
    import argparse

    if instruction and instruction_file:
        console.print("[red]Cannot specify both --instruction and --instruction-file[/]")
        raise typer.Exit(1)

    if instruction_file:
        instruction = instruction_file.read_text(encoding="utf-8").strip()
        if not instruction:
            console.print(f"[red]Instruction file '{instruction_file}' is empty[/]")
            raise typer.Exit(1)

    # Override model if specified
    if model:
        import os

        os.environ["PHANTOM_LLM"] = model

    # Override timeout if specified
    if timeout is not None:
        import os

        os.environ["PHANTOM_SANDBOX_EXECUTION_TIMEOUT"] = str(timeout)

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

    # Ensure UTF-8 output on Windows
    import io

    if sys.platform == "win32":
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    apply_saved_config()

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

    asyncio.run(_async_scan(args))

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


# ──────────────────────────── config ────────────────────────────

config_app = typer.Typer(help="Manage Phantom configuration.", no_args_is_help=True)
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show() -> None:
    """Display current configuration."""
    from phantom.config import Config, apply_saved_config

    apply_saved_config()
    saved = Config.load()
    env_vars = saved.get("env", {})

    if not env_vars:
        console.print("[dim]No saved configuration found.[/]")
        console.print("[dim]Use 'phantom config set KEY VALUE' to configure.[/]")
        return

    from rich.table import Table

    table = Table(title="Phantom Configuration", show_lines=True)
    table.add_column("Variable", style="cyan")
    table.add_column("Value", style="green")

    for key, value in sorted(env_vars.items()):
        # Mask API keys
        display_value = value
        if "key" in key.lower() or "token" in key.lower():
            display_value = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
        table.add_row(key, display_value)

    console.print(table)


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

    os.environ[key_upper] = value
    Config.save_current()
    console.print(f"[green]Set {key_upper}[/]")


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
    """List all scan reports."""
    runs_dir = Path("phantom_runs")
    if not runs_dir.exists():
        console.print("[dim]No scan reports found. Run 'phantom scan' first.[/]")
        return

    from rich.table import Table

    table = Table(title="Scan Reports")
    table.add_column("Run Name", style="cyan")
    table.add_column("Created", style="dim")

    import datetime

    for run_dir in sorted(runs_dir.iterdir(), reverse=True):
        if run_dir.is_dir():
            stat = run_dir.stat()
            created = datetime.datetime.fromtimestamp(
                stat.st_mtime, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M")
            table.add_row(run_dir.name, created)

    console.print(table)


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
    else:
        console.print(f"[yellow]Export format '{fmt.value}' will be available soon.[/]")


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
    info.append(f"☠ PHANTOM v{ver}\n", style="bold #9b59b6")
    info.append('" Why So Serious ?! "\n', style="italic #e74c3c")
    info.append(f"Python {platform.python_version()}\n", style="dim")
    info.append(f"Platform {platform.system()} {platform.machine()}\n", style="dim")
    info.append(f"Docker {'available' if has_docker else 'NOT FOUND'}", style="green" if has_docker else "red")

    console.print(
        Panel(info, title="[bold #9b59b6]☠ PHANTOM", border_style="#9b59b6", padding=(1, 2))
    )


# ──────────────────────────── entry point ────────────────────────────


def cli_main() -> None:
    """Entry point for the Phantom CLI."""
    app()


if __name__ == "__main__":
    cli_main()
