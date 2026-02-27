"""Analyze a Phantom scan's audit.jsonl to understand coverage and gaps."""
import json
import sys
from collections import Counter
from pathlib import Path

def analyze(audit_path: str):
    with open(audit_path) as f:
        lines = [json.loads(l) for l in f]

    first_ts = lines[0]['timestamp'][:19]
    last_ts = lines[-1]['timestamp'][:19]
    print(f"Scan Duration: {first_ts} to {last_ts}")
    print(f"Total audit events: {len(lines)}")
    print()

    # Tool usage
    tool_calls = [l for l in lines if l['event_type'] == 'tool_call']
    tool_counts = Counter(l['data']['tool_name'] for l in tool_calls)
    print("=== TOOL USAGE ===")
    for t, c in tool_counts.most_common():
        print(f"  {t}: {c}")

    # Agent distribution
    agent_counts = Counter(l.get('agent_id', '?') for l in tool_calls)
    print(f"\n=== AGENTS ({len(agent_counts)}) ===")
    for a, c in agent_counts.most_common():
        print(f"  {a}: {c} calls")

    # Sub-agent creation
    print("\n=== AGENTS CREATED ===")
    for l in tool_calls:
        d = l['data']
        if d['tool_name'] == 'create_agent':
            args = d['args']
            name = args.get('name', '?')
            skills = args.get('skills', '?')
            task = args.get('task', '?')[:150]
            print(f"  [{skills}] {name}")
            print(f"    Task: {task}")

    # Security tools
    sec_tools = ['sqlmap_test','ffuf_directory_scan','katana_crawl','nuclei_scan',
                 'nmap_scan','nikto_scan','xss_scan','ssrf_scan','command_injection_scan',
                 'check_known_vulnerabilities']
    print("\n=== SECURITY TOOLS USED ===")
    for l in tool_calls:
        d = l['data']
        if d['tool_name'] in sec_tools:
            tn = d['tool_name']
            success = d.get('success', '?')
            dur = d.get('duration_ms', 0)
            args_str = str(d['args'])[:120]
            print(f"  {tn}: success={success} dur={dur:.0f}ms")
            print(f"    {args_str}")

    # HTTP requests
    print("\n=== HTTP REQUESTS ===")
    urls = []
    for l in tool_calls:
        d = l['data']
        if d['tool_name'] == 'send_request':
            args = d['args']
            method = args.get('method', '?')
            url = args.get('url', '?')
            urls.append(f"{method} {url}")
            print(f"  {method} {url}")

    # Vulnerability reports
    print("\n=== VULNERABILITY REPORTS CREATED ===")
    for l in tool_calls:
        d = l['data']
        if d['tool_name'] == 'create_vulnerability_report':
            args = d['args']
            title = args.get('title', '?')[:80]
            sev = args.get('severity', '?')
            success = d.get('success', '?')
            print(f"  [{sev}] {title} (ok={success})")

    # Findings
    print("\n=== RECORDED FINDINGS ===")
    for l in tool_calls:
        d = l['data']
        if d['tool_name'] == 'record_finding':
            success = d.get('success', '?')
            args = d['args']
            finding = args.get('finding', args.get('description', '?'))[:120]
            print(f"  ok={success}: {finding}")

    # Errors
    print("\n=== ERRORS ===")
    for l in tool_calls:
        d = l['data']
        if not d.get('success', True):
            tn = d['tool_name']
            msg = str(d.get('result_summary', ''))[:120]
            print(f"  {tn}: {msg}")

    # Unique endpoints tested
    print(f"\n=== COVERAGE SUMMARY ===")
    unique_urls = set(urls)
    print(f"  Unique HTTP requests: {len(unique_urls)}")
    print(f"  Total tool calls: {len(tool_calls)}")
    print(f"  Security tools used: {sum(1 for l in tool_calls if l['data']['tool_name'] in sec_tools)}")
    print(f"  python_action: {tool_counts.get('python_action', 0)}")
    print(f"  browser_action: {tool_counts.get('browser_action', 0)}")
    print(f"  Sub-agents: {tool_counts.get('create_agent', 0)}")


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'phantom_runs/host-docker-internal-3000_fa26/audit.jsonl'
    analyze(path)
