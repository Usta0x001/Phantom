"""Analyze the last scan's audit log to understand tool usage and weaknesses."""
import json
import sys
from pathlib import Path

SCANNER_TOOLS = {'nuclei_scan', 'sqlmap_test', 'katana_crawl', 'nmap_scan', 
                 'ffuf_directory_scan', 'httpx_probe', 'nuclei_scan_cves', 'nuclei_scan_misconfigs'}

def analyze_scan(run_dir: str):
    audit_path = Path(run_dir) / "audit.jsonl"
    if not audit_path.exists():
        print(f"No audit.jsonl in {run_dir}")
        return

    tools = {}
    iterations = 0
    errors = []
    empty_responses = 0
    vuln_reports = 0
    tool_results = {}
    sandbox_errors = 0
    phases = []
    
    with open(audit_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                e = json.loads(line)
            except:
                continue
            
            event = e.get('event', '')
            
            if event == 'tool_call':
                tn = e.get('tool_name', '?')
                tools[tn] = tools.get(tn, 0) + 1
            elif event == 'iteration_start':
                iterations += 1
            elif event == 'tool_error':
                errors.append(e.get('error', '?')[:120])
                if 'sandbox' in str(e.get('error', '')).lower() or 'container' in str(e.get('error', '')).lower():
                    sandbox_errors += 1
            elif event == 'tool_result':
                tn = e.get('tool_name', '?')
                success = e.get('success', True)
                if tn not in tool_results:
                    tool_results[tn] = {'success': 0, 'fail': 0}
                if success:
                    tool_results[tn]['success'] += 1
                else:
                    tool_results[tn]['fail'] += 1
            elif event == 'vulnerability_found':
                vuln_reports += 1
            elif event == 'phase_transition':
                phases.append(e.get('details', '?'))

    total = sum(tools.values())
    
    print("=" * 70)
    print(f"SCAN ANALYSIS: {run_dir}")
    print("=" * 70)
    print(f"Iterations:       {iterations}")
    print(f"Total tool calls: {total}")
    print(f"Vulns reported:   {vuln_reports}")
    print(f"Tool errors:      {len(errors)}")
    print(f"Sandbox errors:   {sandbox_errors}")
    print(f"Empty responses:  {empty_responses}")
    
    print("\n=== TOOL USAGE ===")
    for t, c in sorted(tools.items(), key=lambda x: -x[1]):
        pct = c * 100 // total if total else 0
        scanner = ' <<< SCANNER' if t in SCANNER_TOOLS else ''
        print(f"  {t:40s} {c:4d} ({pct:2d}%){scanner}")
    
    scanner_total = sum(tools.get(t, 0) for t in SCANNER_TOOLS)
    sr = tools.get('send_request', 0)
    print(f"\nScanner tools: {scanner_total}/{total} ({scanner_total*100//total if total else 0}%)")
    print(f"send_request:  {sr}/{total} ({sr*100//total if total else 0}%)")
    
    print("\n=== TOOL SUCCESS/FAIL ===")
    for t, stats in sorted(tool_results.items(), key=lambda x: -x[1].get('fail', 0)):
        if stats['fail'] > 0:
            print(f"  {t:40s} OK={stats['success']} FAIL={stats['fail']}")
    
    if errors:
        print(f"\n=== ERRORS (first 15) ===")
        unique_errors = list(dict.fromkeys(errors))  # deduplicate preserving order
        for e in unique_errors[:15]:
            print(f"  - {e}")
    
    if phases:
        print(f"\n=== PHASE TRANSITIONS ===")
        for p in phases:
            print(f"  - {p}")
    
    # Key diagnosis
    print("\n" + "=" * 70)
    print("DIAGNOSIS")
    print("=" * 70)
    
    issues = []
    if scanner_total == 0:
        issues.append("CRITICAL: Zero scanner tools used! nuclei/sqlmap/katana never ran.")
    elif scanner_total < 5:
        issues.append(f"HIGH: Only {scanner_total} scanner calls — scanners barely used.")
    
    if sr > 0 and total > 0 and sr / total > 0.6:
        issues.append(f"HIGH: send_request dominance at {sr*100//total}% — agent is doing manual testing only.")
    
    if sandbox_errors > 3:
        issues.append(f"CRITICAL: {sandbox_errors} sandbox errors — scanner tools can't execute!")
    
    if iterations > 0 and vuln_reports / max(1, iterations) < 0.05:
        issues.append(f"MEDIUM: Low vuln/iteration ratio ({vuln_reports}/{iterations})")
    
    for issue in issues:
        print(f"  [{issue}]")
    
    if not issues:
        print("  No major issues detected in tool usage patterns.")


if __name__ == "__main__":
    # Find most recent scan run
    runs_dir = Path("phantom_runs")
    if len(sys.argv) > 1:
        analyze_scan(sys.argv[1])
    else:
        runs = sorted(runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        if runs:
            analyze_scan(str(runs[0]))
        else:
            print("No scan runs found")
