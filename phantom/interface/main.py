#!/usr/bin/env python3
"""
phantom Agent Interface
"""

import argparse
import asyncio
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any

# Silence litellm noise and prevent network fetch at import — must be before any litellm import
os.environ.setdefault("LITELLM_LOG", "ERROR")
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from phantom.config import Config, apply_saved_config, save_current_config


from phantom.interface.cli import run_cli  # noqa: E402
from phantom.interface.tui import run_tui  # noqa: E402
from phantom.interface.utils import (  # noqa: E402
    assign_workspace_subdirs,
    build_final_stats_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    generate_run_name,
    image_exists,
    infer_target_type,
    process_pull_line,
    rewrite_localhost_targets,
    validate_config_file,
    validate_llm_response,
)
from phantom.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME  # noqa: E402
from phantom.telemetry.tracer import get_global_tracer  # noqa: E402


logging.getLogger().setLevel(logging.ERROR)


def validate_environment() -> None:  # noqa: PLR0912, PLR0915
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    if not Config.get("phantom_llm"):
        missing_required_vars.append("PHANTOM_LLM")

    has_base_url = any(
        [
            Config.get("llm_api_base"),
            Config.get("openai_api_base"),
            Config.get("litellm_base_url"),
            Config.get("ollama_api_base"),
        ]
    )

    if not Config.get("llm_api_key"):
        missing_optional_vars.append("LLM_API_KEY")

    if not has_base_url:
        missing_optional_vars.append("LLM_API_BASE")

    if not Config.get("perplexity_api_key"):
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if not Config.get("phantom_reasoning_effort"):
        missing_optional_vars.append("PHANTOM_REASONING_EFFORT")

    if missing_required_vars:
        error_text = Text()
        error_text.append("MISSING REQUIRED ENVIRONMENT VARIABLES", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" is not set\n", style="white")

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" is not set\n", style="dim white")

        error_text.append("\nRequired environment variables:\n", style="white")
        for var in missing_required_vars:
            if var == "PHANTOM_LLM":
                error_text.append("• ", style="white")
                error_text.append("PHANTOM_LLM", style="bold cyan")
                error_text.append(
                    " - Model name to use with litellm (e.g., 'openai/gpt-5')\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\nOptional environment variables:\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for the LLM provider "
                        "(not needed for local models, Vertex AI, AWS, etc.)\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - Custom API base URL if using local models (e.g., Ollama, LMStudio)\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - API key for Perplexity AI web search (enables real-time research)\n",
                        style="white",
                    )
                elif var == "PHANTOM_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("PHANTOM_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - Reasoning effort level: none, minimal, low, medium, high, xhigh "
                        "(default: high)\n",
                        style="white",
                    )

        error_text.append("\nQuick setup (persistent — recommended):\n", style="white")
        error_text.append("  phantom config set PHANTOM_LLM 'openai/gpt-4o'\n", style="bold green")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "  phantom config set LLM_API_KEY 'your-api-key-here'\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "  phantom config set LLM_API_BASE 'http://localhost:11434'"
                        "  # local models only\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "  phantom config set PERPLEXITY_API_KEY 'your-perplexity-key-here'\n",
                        style="dim white",
                    )
                elif var == "PHANTOM_REASONING_EFFORT":
                    error_text.append(
                        "  phantom config set PHANTOM_REASONING_EFFORT 'high'\n",
                        style="dim white",
                    )

        error_text.append("\nOr export for current session only:\n", style="dim white")
        error_text.append("  export PHANTOM_LLM='openai/gpt-4o'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "  export LLM_API_KEY='your-api-key-here'\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "  export LLM_API_BASE='http://localhost:11434'\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "  export PERPLEXITY_API_KEY='your-perplexity-key-here'\n",
                        style="dim white",
                    )
                elif var == "PHANTOM_REASONING_EFFORT":
                    error_text.append(
                        "  export PHANTOM_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold #9b59b6]☠ PHANTOM",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        console = Console()
        error_text = Text()
        error_text.append("DOCKER NOT INSTALLED", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("The 'docker' CLI was not found in your PATH.\n", style="white")
        error_text.append(
            "Please install Docker and ensure the 'docker' command is available.\n\n", style="white"
        )

        panel = Panel(
            error_text,
            title="[bold #9b59b6]☠ PHANTOM",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)


async def warm_up_llm() -> None:
    console = Console()

    try:
        model_name = Config.get("phantom_llm")
        api_key = Config.get("llm_api_key")
        # Support comma-separated keys for rotation: use first key for warm-up
        if api_key and "," in api_key:
            api_key = api_key.split(",")[0].strip()
        api_base = (
            Config.get("llm_api_base")
            or Config.get("openai_api_base")
            or Config.get("litellm_base_url")
            or Config.get("ollama_api_base")
        )

        test_messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Reply with just 'OK'."},
        ]

        llm_timeout = int(Config.get("llm_timeout") or "300")

        completion_kwargs: dict[str, Any] = {
            "model": model_name,
            "messages": test_messages,
            "timeout": llm_timeout,
        }
        if api_key:
            completion_kwargs["api_key"] = api_key
        if api_base:
            completion_kwargs["api_base"] = api_base

        import litellm  # lazy import — saves ~10s startup

        response = await litellm.acompletion(**completion_kwargs)

        validate_llm_response(response)

    except Exception as e:  # noqa: BLE001
        error_text = Text()

        # Detect rate limiting specifically
        err_str = str(e).lower()
        is_rate_limited = any(k in err_str for k in ["ratelimit", "rate_limit", "quota", "429", "resource_exhausted"])

        if is_rate_limited:
            error_text.append("API RATE LIMITED", style="bold #eab308")
            error_text.append("\n\n", style="white")
            error_text.append("Your API key has hit its rate limit or quota.\n", style="white")
            error_text.append("The LLM provider is rejecting requests.\n\n", style="white")
            error_text.append("Options:\n", style="bold white")
            error_text.append("  • Wait for the rate limit window to reset\n", style="white")
            error_text.append("  • Use a paid API key with higher quotas\n", style="white")
            error_text.append("  • Switch to a different model/provider\n", style="white")
            error_text.append(f"\nDetails: {e}", style="dim white")
        else:
            error_text.append("LLM CONNECTION FAILED", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append("Could not establish connection to the language model.\n", style="white")
            error_text.append("Please check your configuration and try again.\n", style="white")
            error_text.append(f"\nError: {e}", style="dim white")

        panel = Panel(
            error_text,
            title="[bold #9b59b6]☠ PHANTOM",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("phantom-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="☠ PHANTOM — Autonomous Offensive Security Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
\" Why So Serious ?! \"

Examples:
  # Web application penetration test
  phantom --target https://example.com

  # GitHub repository analysis
  phantom --target https://github.com/user/repo
  phantom --target git@github.com:user/repo.git

  # Local code analysis
  phantom --target ./my-project

  # Domain penetration test
  phantom --target example.com

  # IP address penetration test
  phantom --target 192.168.1.42

  # Multiple targets (e.g., white-box testing with source and deployed app)
  phantom --target https://github.com/user/repo --target https://example.com
  phantom --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # Custom instructions (inline)
  phantom --target example.com --instruction "Focus on authentication vulnerabilities"

  # Custom instructions (from file)
  phantom --target example.com --instruction-file ./instructions.txt
  phantom --target https://app.com --instruction-file /path/to/detailed_instructions.md
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"phantom {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        required=True,
        action="append",
        help="Target to test (URL, repository, local directory path, domain name, or IP address). "
        "Can be specified multiple times for multi-target scans.",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="Custom instructions for the penetration test. This can be "
        "specific vulnerability types to focus on (e.g., 'Focus on IDOR and XSS'), "
        "testing approaches (e.g., 'Perform thorough authentication testing'), "
        "test credentials (e.g., 'Use the following credentials to access the app: "
        "admin:password123'), "
        "or areas of interest (e.g., 'Check login API endpoint for security issues').",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="Path to a file containing detailed custom instructions for the penetration test. "
        "Use this option when you have lengthy or complex instructions saved in a file "
        "(e.g., '--instruction-file ./detailed_instructions.txt').",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help=(
            "Run in non-interactive mode (no TUI, exits on completion). "
            "Default is interactive mode with TUI."
        ),
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "Scan mode: "
            "'quick' for fast CI/CD checks, "
            "'standard' for routine testing, "
            "'deep' for thorough security reviews (default). "
            "Default: deep."
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="Path to a custom config file (JSON) to use instead of ~/.phantom/cli-config.json",
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"Instruction file '{instruction_path}' is empty")
        except Exception as e:  # noqa: BLE001
            parser.error(f"Failed to read instruction file '{instruction_path}': {e}")

    args.targets_info = []
    for target in args.target:
        try:
            target_type, target_dict = infer_target_type(target)

            if target_type == "local_code":
                display_target = target_dict.get("target_path", target)
            else:
                display_target = target

            args.targets_info.append(
                {"type": target_type, "details": target_dict, "original": display_target}
            )
        except ValueError:
            parser.error(f"Invalid target '{target}'")

    assign_workspace_subdirs(args.targets_info)
    rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

    return args


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    console = Console()
    tracer = get_global_tracer()

    scan_completed = False
    if tracer and tracer.scan_results:
        scan_completed = tracer.scan_results.get("scan_completed", False)

    has_vulnerabilities = tracer and len(tracer.vulnerability_reports) > 0

    completion_text = Text()
    if scan_completed:
        completion_text.append("☠ Scan completed", style="bold #9b59b6")
    else:
        completion_text.append("⚠ Session ended", style="bold #eab308")
        # Show error reason if available
        if tracer and hasattr(tracer, "scan_error") and tracer.scan_error:
            completion_text.append(f"\n  {tracer.scan_error}", style="dim red")

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

    stats_text = build_final_stats_text(tracer)

    panel_parts = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    if scan_completed or has_vulnerabilities:
        results_text = Text()
        results_text.append("\n")
        results_text.append("Output", style="dim")
        results_text.append("  ")
        results_text.append(str(results_path), style="#60a5fa")
        panel_parts.extend(["\n", results_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#9b59b6" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold #9b59b6]☠ PHANTOM",
        title_align="left",
        subtitle='[italic #e74c3c]" Why So Serious ?! "',
        subtitle_align="right",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print('[bold #9b59b6]☠ PHANTOM[/]  [dim]·[/]  [italic #e74c3c]" Why So Serious ?! "[/]  [dim]·[/]  [dim]Autonomous Offensive Security Intelligence[/]')
    console.print()


# The canonical default image – always works as a last-resort fallback.
_DEFAULT_SANDBOX_IMAGE = "ghcr.io/usta0x001/phantom-sandbox:latest"


def _pull_single_image(client: object, image: str) -> None:
    """Pull *image* from the registry, streaming progress. Raises DockerException on failure."""
    console = Console()
    console.print()
    console.print(f"[dim]Pulling image[/] [bold]{image}[/]")
    console.print("[dim yellow]This only happens on first run and may take a few minutes...[/]")
    console.print()
    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        layers_info: dict[str, str] = {}
        last_update = ""
        for line in client.api.pull(image, stream=True, decode=True):  # type: ignore[union-attr]
            last_update = process_pull_line(line, layers_info, status, last_update)


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    configured_image: str = Config.get("phantom_image") or _DEFAULT_SANDBOX_IMAGE  # type: ignore[assignment]

    if image_exists(client, configured_image):  # type: ignore[arg-type]
        return

    # --- Attempt 1: configured image ---
    try:
        _pull_single_image(client, configured_image)
        success_text = Text()
        success_text.append("Docker image ready", style="#9b59b6")
        console.print(success_text)
        console.print()
        return
    except DockerException as primary_err:
        if configured_image == _DEFAULT_SANDBOX_IMAGE:
            # No fallback available – bail out.
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n")
            error_text.append(f"Could not download: {configured_image}\n", style="white")
            error_text.append(str(primary_err), style="dim red")
            console.print(Panel(error_text, title="[bold #9b59b6]☠ PHANTOM",
                                title_align="left", border_style="red", padding=(1, 2)))
            console.print()
            sys.exit(1)

        # Configured image is non-default and failed – warn and try the default.
        console.print(f"[yellow]Warning:[/] Could not pull [bold]{configured_image}[/]: {primary_err}")
        console.print(f"[dim]Falling back to default image: {_DEFAULT_SANDBOX_IMAGE}[/]")
        # Reset config to the known-good default so it persists correctly.
        import os
        os.environ["PHANTOM_IMAGE"] = _DEFAULT_SANDBOX_IMAGE

        if image_exists(client, _DEFAULT_SANDBOX_IMAGE):  # type: ignore[arg-type]
            console.print("[dim]Default image already cached locally — using it.[/]")
            return

        try:
            _pull_single_image(client, _DEFAULT_SANDBOX_IMAGE)
            success_text = Text()
            success_text.append("Docker image ready (default fallback)", style="#9b59b6")
            console.print(success_text)
            console.print()
        except DockerException as fallback_err:
            console.print()
            error_text = Text()
            error_text.append("FAILED TO PULL IMAGE", style="bold red")
            error_text.append("\n\n")
            error_text.append(f"Could not download: {_DEFAULT_SANDBOX_IMAGE}\n", style="white")
            error_text.append(str(fallback_err), style="dim red")
            error_text.append("\n\nTip: pre-pull manually with:\n", style="dim")
            error_text.append(f"  docker pull {_DEFAULT_SANDBOX_IMAGE}", style="bold")
            console.print(Panel(error_text, title="[bold #9b59b6]☠ PHANTOM",
                                title_align="left", border_style="red", padding=(1, 2)))
            console.print()
            sys.exit(1)


def apply_config_override(config_path: str) -> None:
    Config._config_file_override = validate_config_file(config_path)
    apply_saved_config(force=True)


def persist_config() -> None:
    if Config._config_file_override is None:
        save_current_config()


async def _async_main(args: argparse.Namespace) -> None:
    """Single event loop for warm-up + scan."""
    await warm_up_llm()

    persist_config()

    args.run_name = generate_run_name(args.targets_info)

    for target_info in args.targets_info:
        if target_info["type"] == "repository":
            repo_url = target_info["details"]["target_repo"]
            dest_name = target_info["details"].get("workspace_subdir")
            cloned_path = clone_repository(repo_url, args.run_name, dest_name)
            target_info["details"]["cloned_repo_path"] = cloned_path

    args.local_sources = collect_local_sources(args.targets_info)

    if args.non_interactive:
        await run_cli(args)
    else:
        await run_tui(args)


def main() -> None:
    # Windows: use SelectorEventLoop to avoid ProactorEventLoop issues
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        # Ensure UTF-8 output on Windows to support Unicode symbols
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    apply_saved_config()

    args = parse_arguments()

    if args.config:
        apply_config_override(args.config)

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(_async_main(args))

    results_path = Path("phantom_runs") / args.run_name
    display_completion_message(args, results_path)

    if args.non_interactive:
        tracer = get_global_tracer()
        if tracer and tracer.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
