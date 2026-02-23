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
    help=(
        "[bold #9b59b6]☠ PHANTOM[/] — Autonomous Offensive Security Intelligence\n\n"
        '[italic #e74c3c]" Why So Serious ?! "[/]\n\n'
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
        console.print(f"[bold #9b59b6]Phantom[/] [white]{ver}[/]")
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
    _auto_install_completion()


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
  h1 {{ color: #9b59b6; border-bottom: 2px solid #9b59b6; padding-bottom: .5rem; }}
  h2 {{ color: #a78bfa; margin-top: 2rem; }}
  h3 {{ color: #e2e8f0; }}
  .meta {{ color: #94a3b8; font-size: .9rem; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .sev-card {{ padding: .75rem 1.5rem; border-radius: .5rem; text-align:center; }}
  .finding {{ background: #1e293b; border-radius: .5rem; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid #9b59b6; }}
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
<footer>Generated by <strong>Phantom</strong> — Autonomous Offensive Security Intelligence | <a href="https://github.com/Usta0x001/Phantom" style="color:#9b59b6">github.com/Usta0x001/Phantom</a></footer>
</body>
</html>"""


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

    # Write directly to the config JSON so that even _NON_PERSISTENT keys are
    # saved when the user explicitly requests it via `phantom config set`.
    os.environ[key_upper] = value
    existing = Config.load().get("env", {})
    existing[key_upper] = value
    Config.save({"env": existing})
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
