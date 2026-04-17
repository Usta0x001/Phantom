from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from threading import Thread
from typing import BinaryIO


def _pump(src: BinaryIO | None, out_path: Path) -> None:
    if src is None:
        return
    with out_path.open("a", encoding="utf-8", errors="ignore") as f:
        for chunk in iter(src.readline, b""):
            try:
                line = chunk.decode("utf-8", errors="replace")
            except Exception:
                line = str(chunk)
            f.write(line)
            f.flush()


def _scan_new_audit_lines(path: Path, seen: int, issues: dict[str, int]) -> int:
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    new = lines[seen:]
    seen = len(lines)

    for ln in new:
        try:
            rec = json.loads(ln)
        except Exception:
            continue

        ev = rec.get("event_type")
        payload = rec.get("payload") or {}
        if ev == "llm.response":
            txt = str(payload.get("response_text", "") or "")
            if "Tool call malformed and NOT executed" in txt:
                issues["malformed_notice"] += 1
            for inv in payload.get("tool_invocations") or []:
                if str(inv.get("toolName", "")) == "tool_name":
                    issues["placeholder_tool_name"] += 1

        if ev == "tool.result":
            prev = str(payload.get("result_preview", "") or "")
            if "Blocked: URL targets a private/internal address" in prev:
                issues["private_addr_block"] += 1
            if "Invalid glob patterns" in prev:
                issues["invalid_glob"] += 1
            if "Unsupported action:" in prev:
                issues["unsupported_action"] += 1
    return seen


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    runs = root / "phantom_runs"
    start_ts = time.time()

    env = os.environ.copy()
    env["PHANTOM_AUDIT_LOG"] = "true"
    env["PHANTOM_TOOL_SUBSET"] = "full"
    env.setdefault("PHANTOM_PROXY_DIRECT_FALLBACK", "false")

    target_url = env.get("PHANTOM_E2E_TARGET_URL", "http://127.0.0.1:3000")

    cmd = [
        sys.executable,
        "-m",
        "phantom.interface.cli_app",
        "scan",
        "-t",
        target_url,
        "--non-interactive",
        "--profile",
        "quick",
        "--quiet",
    ]

    stdout_log = root / "e2e_live_stdout.log"
    stderr_log = root / "e2e_live_stderr.log"
    stdout_log.write_text("", encoding="utf-8")
    stderr_log.write_text("", encoding="utf-8")

    proc = subprocess.Popen(
        cmd,
        cwd=str(root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
    )

    threads = [
        Thread(target=_pump, args=(proc.stdout, stdout_log), daemon=True),
        Thread(target=_pump, args=(proc.stderr, stderr_log), daemon=True),
    ]
    for t in threads:
        t.start()

    run_dir: Path | None = None
    audit_path: Path | None = None
    seen_audit_lines = 0

    issues = {
        "malformed_notice": 0,
        "placeholder_tool_name": 0,
        "private_addr_block": 0,
        "invalid_glob": 0,
        "unsupported_action": 0,
    }

    max_seconds = 420
    critical = False
    critical_reason = ""

    while True:
        if run_dir is None:
            candidates = [
                p for p in runs.iterdir() if p.is_dir() and p.stat().st_mtime >= start_ts - 2
            ]
            if candidates:
                run_dir = max(candidates, key=lambda p: p.stat().st_mtime)
                cand_audit = run_dir / "audit.jsonl"
                if cand_audit.exists():
                    audit_path = cand_audit
        else:
            cand_audit = run_dir / "audit.jsonl"
            if cand_audit.exists():
                audit_path = cand_audit

        if audit_path and audit_path.exists():
            seen_audit_lines = _scan_new_audit_lines(audit_path, seen_audit_lines, issues)

        if issues["placeholder_tool_name"] > 0:
            critical = True
            critical_reason = "placeholder tool_name emitted"
        elif issues["malformed_notice"] >= 2:
            critical = True
            critical_reason = "repeated malformed tool-call loop"

        if critical:
            proc.terminate()
            break

        if proc.poll() is not None:
            break

        if (time.time() - start_ts) > max_seconds:
            proc.terminate()
            critical = True
            critical_reason = "time budget reached"
            break

        time.sleep(1.0)

    try:
        rc = proc.wait(timeout=20)
    except Exception:
        proc.kill()
        rc = proc.wait(timeout=10)

    summary = {
        "command": cmd,
        "returncode": rc,
        "run_dir": str(run_dir) if run_dir else None,
        "audit_path": str(audit_path) if audit_path else None,
        "issues": issues,
        "critical_stopped": critical,
        "critical_reason": critical_reason,
        "stdout_log": str(stdout_log),
        "stderr_log": str(stderr_log),
        "elapsed_seconds": round(time.time() - start_ts, 1),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
