#!/usr/bin/env python3
"""analyze_audit_logs.py — Extract all bugs and patterns from Phantom audit logs."""
import json
import pathlib

runs_dir = pathlib.Path("phantom_runs")
jsonl_files = sorted(
    runs_dir.rglob("audit.jsonl"),
    key=lambda p: p.stat().st_mtime,
    reverse=True,
)[:8]

total_cost   = 0.0
all_fails    = []
all_slow     = []
all_errors   = []

for jf in jsonl_files:
    data = []
    with open(jf, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                try:
                    data.append(json.loads(raw))
                except json.JSONDecodeError:
                    all_errors.append(f"JSON parse error in {jf.name}: {raw[:60]!r}")

    print(f"\n=== {jf.parent.name} ({len(data)} events) ===")

    for d in data:
        et = d.get("event_type", "?")

        # ── OLD FORMAT ────────────────────────────────────────────────────
        td = d.get("data") or {}
        if et == "tool_call":
            tn  = td.get("tool_name", "?")
            dur = td.get("duration_ms", 0)
            ok  = td.get("success", True)
            rs  = str(td.get("result_summary") or "")[:200]

            if not ok:
                all_fails.append((tn, rs))
                print(f"  FAIL  {tn}: {rs!r}")
            if dur > 8000:
                all_slow.append((tn, dur))
                print(f"  SLOW  {tn}: {dur:.0f}ms")

        if et == "scan_completed":
            cost = td.get("llm_usage", {}).get("total", {}).get("cost", 0)
            total_cost += cost
            vulns = td.get("vulnerabilities_found", 0)
            tools = td.get("tool_executions", 0)
            tok_in  = td.get("llm_usage", {}).get("total", {}).get("input_tokens", 0)
            tok_out = td.get("llm_usage", {}).get("total", {}).get("output_tokens", 0)
            print(
                f"  DONE  vulns={vulns} tools={tools} "
                f"tokens_in={tok_in:,} tokens_out={tok_out:,} "
                f"cost=${cost:.4f}"
            )

        # ── NEW FORMAT ────────────────────────────────────────────────────
        p = d.get("payload") or {}
        if et == "tool.error":
            tn  = p.get("tool_name", "?")
            err = str(p.get("error", ""))[:200]
            dur = p.get("duration_ms", 0)
            all_fails.append((tn, err))
            print(f"  FAIL  {tn}: {err!r}")
        if et in ("tool.result", "tool.start") and p.get("duration_ms", 0) > 8000:
            tn  = p.get("tool_name", "?")
            dur = p.get("duration_ms", 0)
            all_slow.append((tn, dur))
            print(f"  SLOW  {tn}: {dur:.0f}ms")
        if et == "llm.error":
            err = str(p.get("error", ""))[:200]
            all_errors.append(f"llm.error: {err}")
            print(f"  LLM_ERR attempt={p.get('attempt',0)} {err!r}")
        if et == "agent.failed":
            err = str(p.get("error", ""))[:200]
            all_errors.append(f"agent.failed: {err}")
            print(f"  AGENT_FAIL {p.get('name','?')}: {err!r}")

print("\n" + "="*70)
print("SUMMARY")
print("="*70)
print(f"  Total LLM cost across runs: ${total_cost:.4f}")
print(f"  Unique failure patterns:")
seen: set[tuple[str, str]] = set()
for tn, rs in all_fails:
    key = (tn, rs[:60])
    if key not in seen:
        seen.add(key)
        print(f"    - {tn}: {rs[:100]!r}")
print(f"\n  Slow operations:")
for tn, ms in sorted(set(all_slow), key=lambda x: -x[1]):
    print(f"    - {tn}: {ms/1000:.1f}s")
if all_errors:
    print(f"\n  Errors/anomalies:")
    for e in all_errors[:20]:
        print(f"    - {e}")
