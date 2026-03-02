"""Analyze the v0.9.23 scan audit trail."""
import json

with open("phantom_runs/host-docker-internal-3000_9fe3/audit.jsonl") as f:
    lines = [json.loads(l) for l in f if l.strip()]

tool_calls = [l for l in lines if l.get("event_type") == "tool_call"]
print(f"Total: {len(tool_calls)} tool calls\n")

for i, tc in enumerate(tool_calls):
    ts = tc["timestamp"].split("T")[1][:8]
    d = tc.get("data", {})
    tool = d.get("tool_name", "?")
    success = d.get("result_success", "?")
    agent = (d.get("agent_name") or "root")[:30]

    args = d.get("arguments", {})
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except Exception:
            args = {}

    # Extract key argument
    arg_val = ""
    if isinstance(args, dict):
        for k in ["target", "url", "action", "task", "command", "query", "finding", "title", "name"]:
            if k in args:
                v = str(args[k])[:80]
                arg_val = f"{k}={v}"
                break
        if not arg_val and "code" in args:
            code_str = str(args["code"])[:80]
            arg_val = f"code={code_str}"

    print(f"{i+1:3d}. {ts} {tool:28s} ok={str(success):5s} | {agent:30s} | {arg_val}")

# Summary
print("\n\n=== TOOL USAGE SUMMARY ===")
from collections import Counter
tool_counter = Counter(d.get("data", {}).get("tool_name") for d in tool_calls)
for tool, count in tool_counter.most_common():
    print(f"  {count:3d}x {tool}")

# Check create_agent details
print("\n\n=== SUBAGENT CREATION DETAILS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "create_agent":
        args = d.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        task = str(args.get("task", ""))[:150]
        name = args.get("name", "?")
        skills = args.get("skills", "?")
        print(f"  Agent: {name}")
        print(f"  Skills: {skills}")
        print(f"  Task: {task}")
        print()

# Check vuln report details
print("\n=== VULNERABILITY REPORT CALLS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "create_vulnerability_report":
        args = d.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        title = args.get("title", "?")
        endpoint = args.get("endpoint", "?")
        success = d.get("result_success", "?")
        print(f"  Title: {title}")
        print(f"  Endpoint: {endpoint}")
        print(f"  Success: {success}")
        print()

# Record findings
print("\n=== RECORD_FINDING CALLS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") == "record_finding":
        args = d.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        finding = args.get("finding", args.get("description", args.get("title", "?")))
        cat = args.get("category", "?")
        print(f"  [{cat}] {finding}")

# Check failed tool calls
print("\n\n=== FAILED TOOL CALLS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("result_success") is False:
        tool = d.get("tool_name", "?")
        ts = tc["timestamp"].split("T")[1][:8]
        result = str(d.get("result_summary", ""))[:120]
        print(f"  {ts} {tool}: {result}")

# Check what results nuclei/sqlmap/ffuf actually returned
print("\n\n=== SECURITY SCANNER RESULTS ===")
for tc in tool_calls:
    d = tc.get("data", {})
    if d.get("tool_name") in ("nuclei_scan", "sqlmap_test", "ffuf_directory_scan", "katana_crawl", "nmap_scan", "httpx_probe"):
        tool = d.get("tool_name")
        ts = tc["timestamp"].split("T")[1][:8]
        args = d.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {}
        target = args.get("target", args.get("url", "?"))
        result = d.get("result_data", d.get("result_summary", ""))
        if isinstance(result, dict):
            # Summarize
            findings = result.get("findings", [])
            total = result.get("total_urls", result.get("total_findings", ""))
            summary = result.get("summary", "")
            if findings:
                result_str = f"{len(findings)} findings: " + ", ".join(str(f.get("template_name", f.get("name", "")))[:40] for f in findings[:5])
            elif total:
                result_str = f"total={total}, summary={summary}"
            else:
                result_str = json.dumps(result)[:150]
        else:
            result_str = str(result)[:150]
        print(f"  {ts} {tool:24s} target={str(target)[:50]} => {result_str}")
