"""Quick scan status checker."""
import json
from collections import Counter

audit_path = r"c:\Users\Gadouri\Desktop\New folder (2)\phantom\phantom_runs\host-docker-internal-3000_05c6\audit.jsonl"

lines = [json.loads(l) for l in open(audit_path, encoding="utf-8")]
tools = [e for e in lines if e["event_type"] == "tool_call"]
vulns = [e for e in lines if e["event_type"] == "vulnerability_found"]

print(f"Total audit entries: {len(lines)}")
print(f"Total tool calls: {len(tools)}")
print(f"Vulnerabilities found: {len(vulns)}")
print()

# Event types
types = Counter(e["event_type"] for e in lines)
print("Event types:", dict(types))
print()

# Tool usage
tool_names = Counter(e["data"]["tool_name"] for e in tools)
print("=== Tool Usage ===")
for t, c in tool_names.most_common():
    print(f"  {t:25s} x{c}")
print()

# Sub-agent tasks
print("=== Sub-agents ===")
for e in lines:
    if e["event_type"] == "tool_call":
        tn = e["data"].get("tool_name", "")
        if tn == "create_agent":
            task = e["data"].get("args", {}).get("task", "")[:120]
            print(f"  CREATED: {task}")
        elif tn == "agent_finish":
            summary = str(e["data"].get("args", {}).get("summary", ""))[:120]
            print(f"  FINISH:  {summary}")
print()

# Last 12 tool calls
print("=== Last 12 tool calls ===")
for e in tools[-12:]:
    d = e["data"]
    cmd = d.get("args", {}).get("command", "")[:90]
    tool = d.get("tool_name", "?")
    ok = "OK" if d.get("success") else "FAIL"
    dur = d.get("duration_ms", 0) / 1000
    print(f"  {tool:20s} {ok:4s} {dur:6.1f}s  {cmd}")

if vulns:
    print()
    print("=== Vulnerabilities ===")
    for v in vulns:
        vd = v["data"]
        print(f"  [{vd.get('severity','?')}] {vd.get('title','?')}")
