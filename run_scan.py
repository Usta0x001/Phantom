"""Headless scan runner — bypasses Rich Live display for non-TTY terminals."""
import sys
import os
import asyncio
import logging

# Configure logging to file + stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("scan_debug.log", mode="w", encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("phantom.headless")

# Ensure env vars are set
os.environ.setdefault("PHANTOM_LLM", "openrouter/deepseek/deepseek-v3.2")
os.environ.setdefault(
    "LLM_API_KEY",
    os.environ.get("OPENROUTER_API_KEY", ""),
)

from phantom.config import Config, apply_saved_config
from phantom.interface.main import warm_up_llm, persist_config
from phantom.interface.utils import (
    infer_target_type,
    assign_workspace_subdirs,
    rewrite_localhost_targets,
    generate_run_name,
    collect_local_sources,
)
from phantom.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME
from phantom.core.scan_profiles import get_profile
from phantom.llm.config import LLMConfig
from phantom.telemetry.tracer import Tracer, set_global_tracer
from phantom.core.audit_logger import AuditLogger, set_global_audit_logger
from phantom.core.scope_validator import ScopeValidator


async def run_headless_scan(target_url: str, scan_mode: str = "quick", resume_dir: str | None = None) -> str:
    apply_saved_config()

    target_type, target_dict = infer_target_type(target_url)
    targets_info = [{"type": target_type, "details": target_dict, "original": target_url}]
    assign_workspace_subdirs(targets_info)
    rewrite_localhost_targets(targets_info, HOST_GATEWAY_HOSTNAME)

    # Register scan targets with the SSRF check so send_request won't block them
    from phantom.tools.proxy.proxy_manager import allow_ssrf_host
    for t in targets_info:
        try:
            from urllib.parse import urlparse as _urlparse
            h = _urlparse(t["original"]).hostname
            if h:
                allow_ssrf_host(h)
        except Exception:
            pass

    # ── Resume from checkpoint? ──
    resumed_state = None
    if resume_dir:
        from pathlib import Path as _Path
        checkpoint_path = _Path(resume_dir) / "checkpoint.json"
        if checkpoint_path.exists():
            from phantom.agents.enhanced_state import EnhancedAgentState
            resumed_state = EnhancedAgentState.from_checkpoint(checkpoint_path)
            print(f"[*] Resuming from checkpoint: iteration {resumed_state.iteration}, "
                  f"{len(resumed_state.vulnerabilities)} vulns")
        else:
            print(f"[!] No checkpoint.json in {resume_dir}, starting fresh")

    print("[1/6] Warming up LLM...")
    await warm_up_llm()
    persist_config()
    print("[2/6] LLM connection verified")

    run_name = generate_run_name(targets_info)
    # If resuming, use the same run directory
    if resume_dir:
        from pathlib import Path as _Path2
        run_name = _Path2(resume_dir).name
    local_sources = collect_local_sources(targets_info)
    profile = get_profile(scan_mode)

    scan_config = {
        "scan_id": run_name,
        "targets": targets_info,
        "user_instructions": "",
        "run_name": run_name,
        "scan_mode": scan_mode,
        "profile": profile.to_dict(),
    }

    llm_config = LLMConfig(scan_mode=scan_mode)
    os.environ.setdefault("PHANTOM_SANDBOX_EXECUTION_TIMEOUT", str(profile.sandbox_timeout_s))

    agent_config = {
        "llm_config": llm_config,
        "max_iterations": profile.max_iterations,
        "non_interactive": True,
        "scan_profile": profile,
    }
    if local_sources:
        agent_config["local_sources"] = local_sources
    if resumed_state:
        # Override max_iterations to remaining iterations from checkpoint
        remaining = profile.max_iterations - resumed_state.iteration
        resumed_state.max_iterations = profile.max_iterations
        agent_config["state"] = resumed_state
        print(f"       Resuming at iteration {resumed_state.iteration}, {remaining} remaining")

    tracer = Tracer(run_name)
    tracer.set_scan_config(scan_config)

    target_urls = [t["original"] for t in targets_info]
    scope_validator = ScopeValidator.from_targets(target_urls)
    tracer.scope_validator = scope_validator

    audit_log_path = tracer.get_run_dir() / "audit.jsonl"
    audit_logger = AuditLogger(audit_log_path)
    set_global_audit_logger(audit_logger)
    tracer.audit_logger = audit_logger
    audit_logger.log_scan_start(scan_id=run_name, targets=target_urls, scan_mode=scan_mode)

    set_global_tracer(tracer)

    vuln_count = 0

    def display_vuln(report):
        nonlocal vuln_count
        vuln_count += 1
        vid = report.get("id", "?")
        sev = report.get("severity", "?")
        name = report.get("name", "?")[:70]
        print(f"  [VULN #{vuln_count}] {sev.upper():8} | {vid} | {name}", flush=True)

    tracer.vulnerability_found_callback = display_vuln

    print(f"[3/6] Starting scan: {run_name}")
    print(f"       Target: {target_url}")
    print(f"       Profile: {scan_mode} (max {profile.max_iterations} iterations)")

    from phantom.agents import PhantomAgent

    agent = PhantomAgent(agent_config)

    try:
        result = await agent.execute_scan(scan_config)
        success = isinstance(result, dict) and result.get("success", False)
        print(f"[4/6] Scan finished — success={success}")
        if isinstance(result, dict):
            for k, v in result.items():
                if k != "success":
                    print(f"       {k}: {str(v)[:200]}")
    except Exception as e:
        logger.error("Scan failed: %s", e, exc_info=True)
        print(f"[4/6] Scan error: {type(e).__name__}: {e}")
        result = {"success": False, "error": str(e)}

    print("[5/6] Cleaning up...")
    tracer.cleanup()
    from phantom.runtime import cleanup_runtime
    cleanup_runtime()

    run_dir = tracer.get_run_dir()
    print(f"[6/6] Results in: {run_dir}")
    for f in sorted(run_dir.iterdir()):
        if f.is_file():
            print(f"       {f.name:40s} {f.stat().st_size:>8,} bytes")

    print(f"\n=== SCAN SUMMARY ===")
    print(f"Run: {run_name}")
    print(f"Vulnerabilities found: {vuln_count}")
    print(f"Output directory: {run_dir}")

    # Print LLM cost stats if available
    stats_file = run_dir / "scan_stats.json"
    if stats_file.exists():
        import json as _json
        stats = _json.loads(stats_file.read_text())
        llm = stats.get("llm_usage", {}).get("total", {})
        duration = stats.get("duration_seconds", 0)
        print(f"\n=== LLM COST ===")
        print(f"Duration: {duration:.0f}s ({duration/60:.1f} min)")
        print(f"LLM requests: {llm.get('requests', '?')}")
        print(f"Input tokens: {llm.get('input_tokens', '?'):,}")
        print(f"Output tokens: {llm.get('output_tokens', '?'):,}")
        print(f"Cached tokens: {llm.get('cached_tokens', '?'):,}")
        print(f"Estimated cost: ${llm.get('cost', 0):.4f}")

    return run_name


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://host.docker.internal:3000"
    mode = sys.argv[2] if len(sys.argv) > 2 else "quick"

    # Parse --resume flag
    _resume_dir = None
    for i, arg in enumerate(sys.argv):
        if arg == "--resume" and i + 1 < len(sys.argv):
            _resume_dir = sys.argv[i + 1]
            break

    if _resume_dir:
        print(f"PHANTOM Headless Scanner — RESUME from {_resume_dir}")
    else:
        print(f"PHANTOM Headless Scanner — target={target}, mode={mode}")

    # Suppress litellm LoggingWorker "Event loop is closed" noise at shutdown.
    # This is a known litellm issue: background coroutines reference a closed loop
    # during Python GC. It's harmless — all logs are already written.
    _default_unraisablehook = sys.unraisablehook

    def _suppress_loop_closed(unraisable):
        if isinstance(unraisable.exc_value, RuntimeError) and "Event loop is closed" in str(
            unraisable.exc_value
        ):
            return
        _default_unraisablehook(unraisable)

    sys.unraisablehook = _suppress_loop_closed

    asyncio.run(run_headless_scan(target, mode, resume_dir=_resume_dir))
