"""Analyze the v0.9.23 scan audit trail - fixed field names."""
import json

with open("phantom_runs/host-docker-internal-3000_9fe3/audit.jsonl") as f:
    lines = [json.loads(l) for l in f if l.strip()]

tool_calls = [l for l in lines if l.get("event_type") == "tool_call"]
print(f"Total: {len(tool_calls)} tool calls\n")

for i, tc in enumerate(tool_calls):
    ts = tc["timestamp"].split("T")[1][:8]
    d = tc.get("data", {})
    tool = d.get("tool_name", "?")
    success = d.get("success", "?")
    agent = tc.get("agent_id", "root")[:15]
    duration = d.get("duration_ms", 0)

    args = d.get("args", {})
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except Exception:
            args = {}

    # Extract key argument
    arg_val = ""
    if isinstance(args, dict):
        for k in ["target", "url", "action", "task", "command", "query", "finding", "title", "name", "severity"]:
            if k in args:
                v = str(args[k])[:80]
                arg_val += f"{k}={v} "
        if not arg_val and "code" in args:
            code_str = str(args["code"])[:80]
            arg_val = f"code={code_str}"

    dur_str = f"{duration/1000:.1f}s" if duration else ""
    print(f"{i+1:3d}. {ts} {tool:28s} ok={str(success):5s} {dur_str:>7s} | {arg_val}")

# Summary
print("\n=== TOOL USAGE SUMMARY ===")
from collections import Counter
tool_counter = Counter(tc.get("data", {}).get("tool_name") for tc in tool_calls)
for tool, count in tool_counter.most_common():
    print(f"  {count:3d}x {tool}")

# Subagent creation details
print("\n=== SUBAGENT CREATION DETAILS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "create_agent":
        args = d.get("args", {})
        task = str(args.get("task", "?"))[:200]
        name = args.get("name", "?")
        skills = args.get("skills", "?")
        print(f"  Agent: {name}")
        print(f"  Skills: {skills}")
        print(f"  Task: {task}")
        print()

# Vuln reports
print("\n=== VULNERABILITY REPORT CALLS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "create_vulnerability_report":
        args = d.get("args", {})
        title = args.get("title", "?")
        endpoint = args.get("endpoint", "?")
        sev = args.get("attack_vector", "?")
        success = d.get("success", "?")
        print(f"  Title: {title}")
        print(f"  Endpoint: {endpoint}")
        print(f"  Success: {success}")
        print()

# Record findings
print("\n=== RECORD_FINDING CALLS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "record_finding":
        args = d.get("args", {})
        finding = args.get("finding", args.get("description", args.get("title", "?")))
        cat = args.get("category", "?")
        sev = args.get("severity", "")
        print(f"  [{cat}/{sev}] {finding}")

# Security scanner results
print("\n=== SECURITY SCANNER RESULTS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") in ("nuclei_scan", "sqlmap_test", "ffuf_directory_scan", "katana_crawl", "nmap_scan", "httpx_probe"):
        tool = d.get("tool_name")
        ts = tc["timestamp"].split("T")[1][:8]
        args = d.get("args", {})
        target = args.get("target", args.get("url", "?"))
        success = d.get("success", "?")
        dur = d.get("duration_ms", 0)
        
        # Extra args
        extra = ""
        for k in ["severity", "tags", "wordlist", "depth", "ports"]:
            if k in args:
                extra += f"{k}={args[k]} "
        
        print(f"  {ts} {tool:24s} ok={str(success):5s} {dur/1000:.0f}s target={str(target)[:50]} {extra}")

# Browser actions
print("\n=== BROWSER ACTIONS (what was browsed) ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "browser_action":
        ts = tc["timestamp"].split("T")[1][:8]
        args = d.get("args", {})
        action = args.get("action", "?")
        url = args.get("url", "")
        text = args.get("text", "")
        selector = args.get("selector", "")
        desc = f"action={action}"
        if url: desc += f" url={url[:60]}"
        if text: desc += f" text={text[:40]}"
        if selector: desc += f" sel={selector[:40]}"
        print(f"  {ts} {desc}")

# Python action code snippets
print("\n=== PYTHON_ACTION CODES (first 80 chars) ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "python_action":
        ts = tc["timestamp"].split("T")[1][:8]
        args = d.get("args", {})
        code = str(args.get("code", "?"))[:120].replace("\n", " | ")
        print(f"  {ts} {code}")
