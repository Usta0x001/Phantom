"""
watch_scan.py — Watched scan runner for Phantom vs OWASP Juice Shop.

Launches Phantom in non-interactive mode with PHANTOM_AUDIT_LOG=true,
then follows the audit.jsonl in real-time and prints a live dashboard.
After the scan ends, produces a full analysis report with:
  - every LLM request/response (model, tokens, cost, duration)
  - every tool call (name, duration, success/error, result preview)
  - every agent created/completed/failed
  - every rate-limit hit and quarantine block
  - all anomalies, delays, errors, and potential bugs

Usage:
    python watch_scan.py [--max-iter N] [--model MODEL]

PHANTOM_AUDIT_LOG is set automatically. The scan uses quick mode by default.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
TARGET       = "estin.dz"
SCAN_MODE    = "quick"           # safest for credit budget
SCAN_TIMEOUT = 240               # 4-minute hard cap (seconds)
INSTRUCTION  = (
    "Perform a quick reconnaissance and vulnerability assessment of the target web application. "
    "Focus on: information disclosure, misconfigured headers, exposed admin panels, "
    "directory traversal, SQL injection, XSS, broken access control, "
    "outdated software versions, and open redirects. "
    "Document every finding with a proof-of-concept."
)
RUNS_DIR     = Path("phantom_runs")
HARD_TIMEOUT = 270               # 4.5-minute absolute max for watcher
# ─────────────────────────────────────────────────────────────────────────────

# ANSI helpers
R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"
C = "\033[36m"; B = "\033[1m";  D = "\033[2m"; E = "\033[0m"

def clr(text: object, *codes: str) -> str:
    return "".join(codes) + str(text) + E


# ─────────────────────────────────────────────────────────────────────────────
class LiveWatcher:
    """Follows audit.jsonl and prints every event as it arrives."""

    def __init__(self, known_dirs: set[str] | None = None) -> None:
        self.path: Path | None = None
        self._known_dirs: set[str] = known_dirs or set()  # dirs to SKIP when auto-discovering
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

        # Stats
        self.events:           list[dict]              = []
        self.token_in          = 0
        self.token_out         = 0
        self.cost              = 0.0
        self.llm_calls         = 0
        self.llm_errors        = 0
        self.tool_calls        = 0
        self.tool_errors       = 0
        self.agents_created:   list[str]               = []
        self.agents_completed: list[str]               = []
        self.agents_failed:    list[str]               = []
        self.rl_hits           = 0
        self.quar_blocks       = 0
        self.slow_tools:       list[tuple[str, float]] = []
        self.slow_llm:         list[tuple[str, float]] = []

    def set_path(self, path: Path) -> None:
        # Signal the run thread to switch to the new file.
        self.path = path
        self._file_changed = True

    def start(self) -> None:
        self._file_changed = False
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    # ── background tail thread ────────────────────────────────────────────
    def _run(self) -> None:
        # Wait until we have a valid path that is NOT from a known-old run.
        waited = 0
        while True:
            if self._stop.is_set():
                return
            self._try_discover_path()
            if self.path and self.path.exists():
                break
            time.sleep(0.5)
            waited += 1
            if waited > 120:   # 60-second startup window
                print(clr("\n[WATCH] audit.jsonl never appeared — no events to show", Y))
                return

        current_path = self.path
        print(clr(f"\n[WATCH] Opening audit log: {current_path}", G))

        while not self._stop.is_set():
            # Re-open if set_path() was called with a different file.
            if self._file_changed and self.path != current_path:
                self._file_changed = False
                current_path = self.path
                print(clr(f"\n[WATCH] Switched to new audit log: {current_path}", G))

            if not current_path or not current_path.exists():
                time.sleep(0.3)
                continue

            with open(current_path, encoding="utf-8") as f:
                while not self._stop.is_set():
                    # Check if caller asked us to switch files.
                    if self._file_changed and self.path != current_path:
                        break  # break inner loop → outer loop will re-open

                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._process(json.loads(line))
                    except json.JSONDecodeError:
                        print(clr(f"[WATCH] bad JSON: {line[:60]!r}", Y))

    def _try_discover_path(self) -> None:
        if self.path and self.path.exists():
            return
        if not RUNS_DIR.exists():
            return
        candidates = sorted(
            (d / "audit.jsonl" for d in RUNS_DIR.iterdir()
             if d.is_dir() and d.name not in self._known_dirs),  # skip old runs
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )
        for p in candidates:
            if p.exists():
                self.path = p
                print(clr(f"\n[WATCH] Discovered audit log: {p}", G))
                return

    # ── event display ─────────────────────────────────────────────────────
    def _process(self, rec: dict) -> None:
        self.events.append(rec)
        ev    = rec.get("event_type", "?")
        p     = rec.get("payload") or {}
        actor = rec.get("actor") or {}
        aid   = (actor.get("agent_id") or "?")[:8] if isinstance(actor, dict) else "?"
        ts    = rec.get("timestamp", "")[:19].replace("T", " ")

        if ev == "run.started":
            print()
            print(clr("◆ AUDIT SESSION STARTED", B, G))
            print(f"  run_id : {p.get('run_id','?')}")
            print(f"  file   : {p.get('jsonl_path','?')}")
            print(f"  pid    : {p.get('pid','?')}")

        elif ev == "agent.created":
            self.agents_created.append(aid)
            task = str(p.get("task", ""))[:80]
            print(f"{clr('[AGENT]', C)} [{ts}] {clr(p.get('name','?'), B)} "
                  f"({p.get('agent_type','?')}) id={aid} task={task!r}")

        elif ev == "agent.iteration":
            it = p.get("iteration", 0);  mx = p.get("max_iterations", 1)
            n_done = int(20 * it / max(mx, 1))
            bar = "█" * n_done + "░" * (20 - n_done)
            print(f"{clr('[ITER]', D)} [{ts}] id={aid} |{bar}| {it}/{mx}")

        elif ev == "llm.request":
            self.llm_calls += 1
            print(f"{clr('[LLM→]', Y)} [{ts}] {p.get('model','?')} "
                  f"msgs={p.get('message_count',0)} chars={p.get('input_chars',0):,} "
                  f"(#{self.llm_calls})")

        elif ev == "llm.response":
            ti = p.get("tokens_in", 0); to = p.get("tokens_out", 0)
            cost = p.get("cost_usd", 0.0); dur = p.get("duration_ms", 0.0)
            self.token_in += ti; self.token_out += to; self.cost += cost
            flag = clr(f" ⚠ SLOW {dur/1000:.1f}s", R) if dur > 15_000 else ""
            if dur > 15_000:
                self.slow_llm.append((p.get("model", "?"), dur))
            print(f"{clr('[LLM←]', G)} [{ts}] in={ti} out={to} "
                  f"cost=${cost:.4f} dur={dur:.0f}ms "
                  f"tools={len(p.get('tool_invocations') or [])}{flag}")

        elif ev == "llm.error":
            self.llm_errors += 1
            print(f"{clr('[LLM!]', R)} [{ts}] id={aid} "
                  f"attempt={p.get('attempt',0)} {str(p.get('error',''))[:120]}")

        elif ev == "llm.compression":
            print(f"{clr('[COMP]', Y)} [{ts}] "
                  f"model={p.get('model','?')} "
                  f"msgs {p.get('messages_in',0)}→{p.get('messages_out',0)} "
                  f"tokens_before={p.get('tokens_before',0):,} "
                  f"dur={p.get('duration_ms',0):.0f}ms")
        elif ev == "tool.start":
            self.tool_calls += 1
            print(f"{clr('[TOOL→]', C)} [{ts}] id={aid} "
                  f"{clr(p.get('tool_name','?'), B)} (#{self.tool_calls})")

        elif ev == "tool.result":
            dur = p.get("duration_ms", 0.0); name = p.get("tool_name", "?")
            flag = clr(f" ⚠ SLOW {dur/1000:.1f}s", R) if dur > 10_000 else ""
            if dur > 10_000:
                self.slow_tools.append((name, dur))
            print(f"{clr('[TOOL←]', G)} [{ts}] id={aid} {name} "
                  f"dur={dur:.0f}ms chars={p.get('result_chars',0):,}{flag}")

        elif ev == "tool.error":
            self.tool_errors += 1
            print(f"{clr('[TOOL!]', R)} [{ts}] id={aid} "
                  f"{clr(p.get('tool_name','?'), B)} {str(p.get('error',''))[:120]}")

        elif ev == "agent.completed":
            self.agents_completed.append(aid)
            print(f"{clr('[DONE]', B, G)} [{ts}] {clr(p.get('name','?'), B)} "
                  f"id={aid} iters={p.get('iterations',0)} "
                  f"dur={p.get('duration_ms',0):.0f}ms ✓")

        elif ev == "agent.failed":
            self.agents_failed.append(aid)
            print(f"{clr('[FAIL]', R)} [{ts}] {clr(p.get('name','?'), B)} "
                  f"id={aid} {str(p.get('error',''))[:120]}")

        elif ev == "rate_limit.hit":
            self.rl_hits += 1
            print(f"{clr('[RL!]', Y)} [{ts}] id={aid} "
                  f"hit#{p.get('consecutive',0)} backoff={p.get('backoff_s',0):.0f}s")

        elif ev == "rate_limit.abort":
            print(f"{clr('[RL ABORT]', R, B)} [{ts}] id={aid} "
                  f"aborted after {p.get('consecutive',0)} hits")

        elif ev == "quarantine.block":
            self.quar_blocks += 1
            print(f"{clr('[QUAR]', R)} [{ts}] "
                  f"cmd={str(p.get('command',''))[:60]!r} "
                  f"chars={p.get('blocked_chars',[])}")

        elif ev == "checkpoint.saved":
            print(f"{clr('[CKPT]', D)} [{ts}] iter={p.get('iteration',0)}")

        elif ev == "security.event":
            print(f"{clr('[SEC!]', R, B)} [{ts}] {json.dumps(p)[:120]}")

    # ── final report ──────────────────────────────────────────────────────
    def summary(self, elapsed: float = 0.0) -> str:
        hr = "=" * 72
        lines: list[str] = ["", hr, clr("  PHANTOM WATCH LAYER — POST-SCAN ANALYSIS", B), hr]

        lines += [
            f"  Scan elapsed          : {elapsed:.0f}s",
            f"  Total events          : {len(self.events)}",
            f"  LLM requests          : {self.llm_calls}",
            f"  LLM errors            : {clr(self.llm_errors, R) if self.llm_errors else self.llm_errors}",
            f"  Tokens  in / out      : {self.token_in:,} / {self.token_out:,}",
            f"  Estimated cost (USD)  : ${self.cost:.4f}",
            f"  Tool calls            : {self.tool_calls}",
            f"  Tool errors           : {clr(self.tool_errors, R) if self.tool_errors else self.tool_errors}",
            f"  Agents created        : {len(self.agents_created)}",
            f"  Agents completed      : {len(self.agents_completed)}",
            f"  Agents failed         : {clr(len(self.agents_failed), R) if self.agents_failed else len(self.agents_failed)}",
            f"  Rate-limit hits       : {clr(self.rl_hits, Y) if self.rl_hits else self.rl_hits}",
            f"  Quarantine blocks     : {self.quar_blocks}",
            "",
        ]

        if self.slow_tools:
            lines.append(clr("  ⚠ SLOW TOOLS (>10s):", Y))
            for name, ms in self.slow_tools:
                lines.append(f"    {name}: {ms/1000:.1f}s")
            lines.append("")

        if self.slow_llm:
            lines.append(clr("  ⚠ SLOW LLM RESPONSES (>15s):", Y))
            for model, ms in self.slow_llm:
                lines.append(f"    {model}: {ms/1000:.1f}s")
            lines.append("")

        # ── event breakdown ────────────────────────────────────────────────
        ev_counts: dict[str, int]         = {}
        tool_freq: dict[str, int]         = {}
        tool_durs: dict[str, list[float]] = {}
        tool_errs: dict[str, int]         = {}
        for rec in self.events:
            et = rec.get("event_type", "?")
            ev_counts[et] = ev_counts.get(et, 0) + 1
            p = rec.get("payload") or {}
            if et == "tool.start":
                n = p.get("tool_name", "?")
                tool_freq[n] = tool_freq.get(n, 0) + 1
            elif et == "tool.result":
                n = p.get("tool_name", "?")
                tool_durs.setdefault(n, []).append(p.get("duration_ms", 0.0))
            elif et == "tool.error":
                n = p.get("tool_name", "?")
                tool_errs[n] = tool_errs.get(n, 0) + 1

        lines.append("  Event breakdown:")
        for et, cnt in sorted(ev_counts.items(), key=lambda x: -x[1]):
            lines.append(f"    {et:40s} {cnt}")
        lines.append("")

        if tool_freq:
            lines.append("  Tool usage  (calls / avg dur / errors):")
            for name in sorted(tool_freq, key=lambda n: -tool_freq[n]):
                durs = tool_durs.get(name, [])
                avg  = sum(durs) / len(durs) if durs else 0.0
                errs = tool_errs.get(name, 0)
                etag = clr(f"  [{errs} err]", R) if errs else ""
                lines.append(f"    {name:40s}  {tool_freq[name]:3d} calls  "
                              f"avg={avg:.0f}ms{etag}")
            lines.append("")

        # ── anomaly detection ──────────────────────────────────────────────
        issues: list[str] = []

        for aid in self.agents_created:
            if aid not in self.agents_completed and aid not in self.agents_failed:
                issues.append(f"Agent {aid} created but never completed/failed — event leak?")

        if self.llm_calls > 0 and self.llm_errors / self.llm_calls > 0.2:
            issues.append(
                f"High LLM error rate: {self.llm_errors}/{self.llm_calls} "
                f"({100*self.llm_errors/self.llm_calls:.0f}%)"
            )
        if self.tool_calls > 0 and self.tool_errors / self.tool_calls > 0.2:
            issues.append(
                f"High tool error rate: {self.tool_errors}/{self.tool_calls} "
                f"({100*self.tool_errors/self.tool_calls:.0f}%)"
            )
        for name, cnt in tool_freq.items():
            if cnt > 25:
                issues.append(f"Tool '{name}' called {cnt} times — possible infinite loop")
        if not [e for e in self.events if e.get("event_type") == "agent.iteration"]:
            issues.append("Zero agent.iteration events — agent may have crashed at startup")
        if self.rl_hits > 3:
            issues.append(f"Rate-limit hit {self.rl_hits} times — API key throttled?")
        for name, durs in tool_durs.items():
            if durs:
                p99 = sorted(durs)[max(0, int(0.99 * len(durs)) - 1)]
                if p99 > 30_000:
                    issues.append(f"Tool '{name}' P99 = {p99/1000:.1f}s — timeout risk")
        if elapsed > 60 and self.llm_calls == 0:
            issues.append("Zero LLM calls — audit wiring may be broken")
        if len(self.events) < 5 and elapsed > 60:
            issues.append(
                f"Only {len(self.events)} events in {elapsed:.0f}s — "
                "audit log may not be flushing"
            )

        if issues:
            lines.append(clr("  ⚠ ISSUES / ANOMALIES:", R, B))
            for iss in issues:
                lines.append(f"    • {clr(iss, R)}")
            lines.append("")
        else:
            lines.append(clr("  ✓ No anomalies detected", G))
            lines.append("")

        # ── vulnerability signal scan ──────────────────────────────────────
        SIGS = [
            "sql injection", "xss", "traversal", "bypass",
            "unauthori", "admin", "jwt", "idor", "vulnerability",
            "500", "sqlmap", "exploit",
        ]
        signals: list[str] = []
        for rec in self.events:
            if rec.get("event_type") == "tool.result":
                p   = rec.get("payload") or {}
                prv = str(p.get("result_preview", "")).lower()
                for sig in SIGS:
                    if sig in prv:
                        signals.append(f"[{p.get('tool_name','?')}] keyword={sig!r}")
                        break
        if signals:
            lines.append("  Vulnerability signals in tool results:")
            for s in signals[:20]:
                lines.append(f"    • {s}")
            lines.append("")

        lines.append(hr)
        return "\n".join(str(x) for x in lines)


# ─────────────────────────────────────────────────────────────────────────────
def _known_dirs() -> set[str]:
    if not RUNS_DIR.exists():
        return set()
    return {d.name for d in RUNS_DIR.iterdir() if d.is_dir()}


def _wait_for_new_dir(before: set[str], timeout: float = 60.0) -> Path | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.5)
        if not RUNS_DIR.exists():
            continue
        for d in RUNS_DIR.iterdir():
            if d.is_dir() and d.name not in before:
                return d
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-iter", type=int, default=30,
                    help="Max agent iterations (default: 30, keep low to save credits)")
    ap.add_argument("--model", type=str, default=None,
                    help="Override PHANTOM_LLM model")
    args = ap.parse_args()

    env = os.environ.copy()
    env["PHANTOM_AUDIT_LOG"] = "true"
    # Explicit context-window budget so the MemoryCompressor uses the correct
    # threshold even when the model is not in litellm's model registry.
    # Without this, litellm falls back to 20K → compression fires every ~4 iters.
    # 80K gives 40K headroom for system prompt + output tokens while fitting any
    # 128K frontier model (Kimi-K2.5, GPT-4o, Claude-3.x, etc.)
    if not env.get("PHANTOM_MAX_INPUT_TOKENS"):
        env["PHANTOM_MAX_INPUT_TOKENS"] = "80000"
    # Cost rates for Kimi-K2.5 on Azure (does not return billing metadata in responses).
    # These activate the budget guard (PHANTOM_MAX_COST) and cost display in watch_scan.
    # Kimi-K2.5 pricing: $0.15/1M input, $0.60/1M output.
    if not env.get("PHANTOM_COST_PER_1M_INPUT"):
        env["PHANTOM_COST_PER_1M_INPUT"] = "0.15"
    if not env.get("PHANTOM_COST_PER_1M_OUTPUT"):
        env["PHANTOM_COST_PER_1M_OUTPUT"] = "0.60"
    # Hard cost cap for a single watch_scan run.  Override via env before launch:
    #   PHANTOM_MAX_COST=2.00 python watch_scan.py
    # The budget guard fires an LLM error + aborts the agent loop when exceeded.
    if not env.get("PHANTOM_MAX_COST"):
        env["PHANTOM_MAX_COST"] = "5.00"
    if args.model:
        env["PHANTOM_LLM"] = args.model

    print(clr("\n" + "="*72, B))
    print(clr("  PHANTOM LIVE-WATCH SCAN — OWASP JUICE SHOP", B))
    print(clr("="*72, B))
    print(f"  Target        : {TARGET}")
    print(f"  Scan mode     : {SCAN_MODE}, max-iter={args.max_iter}")
    print(f"  Model         : {env.get('PHANTOM_LLM','(inherits PHANTOM_LLM env)')}")
    print(f"  Audit logging : PHANTOM_AUDIT_LOG=true")
    print(clr("="*72, B)); print()

    before_dirs = _known_dirs()

    # Use the installed `phantom` CLI binary
    cmd = [
        "phantom", "scan",
        "-t", TARGET,
        "--instruction", INSTRUCTION,
        "--scan-mode", SCAN_MODE,
        "--timeout", str(SCAN_TIMEOUT),
        "-n",
    ]
    print(clr(f"CMD: {' '.join(cmd[:6])} ...", D)); print()

    watcher = LiveWatcher(known_dirs=before_dirs)
    watcher.start()

    start_t = time.monotonic()
    proc: subprocess.Popen | None = None
    elapsed = 0.0

    try:
        proc = subprocess.Popen(cmd, env=env)

        # Try to locate the new run directory quickly so we can prime the watcher
        new_dir = _wait_for_new_dir(before_dirs, timeout=45.0)
        if new_dir:
            audit_path = new_dir / "audit.jsonl"
            watcher.set_path(audit_path)
            print(clr(f"[WATCH] Run dir → {new_dir.name}", G))
        else:
            print(clr("[WATCH] No new run dir in 45s — watcher will self-discover", Y))

        proc.wait(timeout=HARD_TIMEOUT)
        elapsed = time.monotonic() - start_t
        print(f"\n{clr('Scan process exited', D)} "
              f"rc={proc.returncode} elapsed={elapsed:.0f}s")

    except FileNotFoundError:
        # `phantom` not on PATH — fall back to python -m invocation
        elapsed = time.monotonic() - start_t
        print(clr("[WARN] 'phantom' binary not found — trying python -m ...", Y))
        try:
            cmd2 = [
                sys.executable, "-m", "phantom.interface.cli_app", "scan",
                "-t", TARGET, "--instruction", INSTRUCTION,
                "--scan-mode", SCAN_MODE, "-n",
            ]
            proc2 = subprocess.Popen(cmd2, env=env)
            new_dir2 = _wait_for_new_dir(before_dirs, timeout=45.0)
            if new_dir2:
                watcher.set_path(new_dir2 / "audit.jsonl")
            proc2.wait(timeout=HARD_TIMEOUT)
            elapsed = time.monotonic() - start_t
        except Exception as ex:
            print(clr(f"[ERROR] Fallback also failed: {ex}", R))

    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
        elapsed = HARD_TIMEOUT
        print(clr(f"\nScan TIMED OUT after {HARD_TIMEOUT//60} min", R))

    except KeyboardInterrupt:
        if proc:
            proc.terminate()
        elapsed = time.monotonic() - start_t
        print(clr("\nInterrupted by user", Y))

    finally:
        time.sleep(1.5)
        watcher.stop()

    report = watcher.summary(elapsed)
    print(report)

    # ── save clean report (no ANSI) ────────────────────────────────────────
    ansi_re  = re.compile(r"\x1b\[[0-9;]*m")
    clean    = ansi_re.sub("", report)
    run_dir  = watcher.path.parent if watcher.path else (RUNS_DIR / "unknown_run")
    run_dir.mkdir(parents=True, exist_ok=True)
    rpt_file = run_dir / "watch_report.txt"
    rpt_file.write_text(
        "PHANTOM LIVE-WATCH SCAN REPORT\n"
        f"Generated : {datetime.now().isoformat()}\n"
        f"Target    : {TARGET}\n"
        f"Elapsed   : {elapsed:.0f}s\n"
        f"Audit log : {watcher.path}\n\n"
        + clean,
        encoding="utf-8",
    )
    print(clr(f"\nReport saved → {rpt_file}", D))


if __name__ == "__main__":
    main()
