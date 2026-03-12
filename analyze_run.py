import json
from pathlib import Path

log = Path("phantom_runs/estin-dz_d484/audit.jsonl")
events = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]

llm_req  = [e for e in events if e["event_type"] == "llm.request"]
llm_resp = [e for e in events if e["event_type"] == "llm.response"]
t_start  = [e for e in events if e["event_type"] == "tool.start"]
t_result = [e for e in events if e["event_type"] == "tool.result"]
t_error  = [e for e in events if e["event_type"] == "tool.error"]
iters    = [e for e in events if e["event_type"] == "agent.iteration"]

print(f"Total events    : {len(events)}")
print(f"LLM requests    : {len(llm_req)}  responses: {len(llm_resp)}")
print(f"Tool calls      : {len(t_start)}  results: {len(t_result)}  errors: {len(t_error)}")
print(f"Agent iterations: {len(iters)}")

tok_in  = sum(e["payload"].get("tokens_in", 0)  for e in llm_resp)
tok_out = sum(e["payload"].get("tokens_out", 0) for e in llm_resp)
cost    = sum(e["payload"].get("cost_usd", 0.0) for e in llm_resp)
print(f"Tokens in/out   : {tok_in:,} / {tok_out:,}  cost=${cost:.4f}")

durs = [e["payload"].get("duration_ms", 0) for e in llm_resp]
if durs:
    print(f"LLM dur         : min={min(durs):.0f}ms  max={max(durs):.0f}ms  avg={sum(durs)/len(durs):.0f}ms")

# Tool breakdown
tool_freq: dict[str, int] = {}
tool_durs: dict[str, list[float]] = {}
for e in t_start:
    n = e["payload"].get("tool_name", "?")
    tool_freq[n] = tool_freq.get(n, 0) + 1
for e in t_result:
    n = e["payload"].get("tool_name", "?")
    tool_durs.setdefault(n, []).append(e["payload"].get("duration_ms", 0))

print("\nTool usage:")
for n, c in sorted(tool_freq.items(), key=lambda x: -x[1]):
    dlist = tool_durs.get(n, [])
    avg   = sum(dlist) / len(dlist) if dlist else 0
    mx    = max(dlist) if dlist else 0
    print(f"  {n:30s}: {c:2d}x  avg={avg:6.0f}ms  max={mx:6.0f}ms")

# Retry detection
print("\nLLM retry analysis (consecutive requests without response):")
prev_req: str | None = None
retry_count = 0
for e in sorted(events, key=lambda x: x["timestamp"]):
    et = e["event_type"]
    if et == "llm.request":
        if prev_req:
            retry_count += 1
            print(f"  RETRY at {e['timestamp'][11:19]}  (prev request: {prev_req})")
        prev_req = e["timestamp"][11:19]
    elif et == "llm.response":
        prev_req = None
if retry_count == 0:
    print("  None detected")

# Slow tools
print("\nSlow tool calls (>10s):")
slow = False
for e in t_result:
    dur  = e["payload"].get("duration_ms", 0)
    name = e["payload"].get("tool_name", "?")
    if dur > 10_000:
        slow = True
        print(f"  {name}: {dur/1000:.1f}s")
if not slow:
    print("  None")

# Tool errors
if t_error:
    print("\nTool errors:")
    for e in t_error:
        print(f"  {e['payload'].get('tool_name','?')}: {str(e['payload'].get('error',''))[:100]}")

print("\nDone.")
