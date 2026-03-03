"""Analyze audit log with correct field names."""
import json, sys
from pathlib import Path

SCANNERS = {'nuclei_scan','sqlmap_test','katana_crawl','nmap_scan',
            'ffuf_directory_scan','httpx_probe','nuclei_scan_cves','nuclei_scan_misconfigs'}

run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else sorted(
    Path("phantom_runs").iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[0]

audit = run_dir / "audit.jsonl"
tools = {}
errors = []
vulns = 0
tool_timings = []

with open(audit, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            e = json.loads(line)
        except:
            continue
        et = e.get('event_type', '')
        data = e.get('data', {})
        ts = e.get('timestamp', '')
        
        if et == 'tool_call':
            tn = data.get('tool_name', '?')
            tools[tn] = tools.get(tn, 0) + 1
            success = data.get('success', True)
            err_msg = data.get('error', '')
            tool_timings.append({'tool': tn, 'ts': ts, 'success': success})
            if not success or err_msg:
                errors.append(f"{tn}: {str(err_msg)[:120]}")
        elif et == 'vulnerability_reported':
            vulns += 1
        elif et == 'scan_started':
            print(f"Scan started: {ts}")
        elif et == 'scan_completed':
            print(f"Scan completed: {ts}")

total = sum(tools.values())
print(f"\n{'='*70}")
print(f"SCAN ANALYSIS: {run_dir.name}")
print(f"{'='*70}")
print(f"Total tool calls: {total}")
print(f"Vulns reported:   {vulns}")
print(f"Errors:           {len(errors)}")

print(f"\n--- TOOL USAGE ---")
for t, c in sorted(tools.items(), key=lambda x: -x[1]):
    pct = c * 100 // total if total else 0
    tag = ' [SCANNER]' if t in SCANNERS else ''
    print(f"  {t:40s} {c:3d} ({pct:2d}%){tag}")

sr = tools.get('send_request', 0)
sc = sum(tools.get(t, 0) for t in SCANNERS)
print(f"\nScanner total: {sc}/{total} ({sc*100//total if total else 0}%)")
print(f"send_request:  {sr}/{total} ({sr*100//total if total else 0}%)")

# Show tool call timeline (first 20 calls)
print(f"\n--- TOOL CALL ORDER (first 20) ---")
for i, tt in enumerate(tool_timings[:20]):
    status = "OK" if tt['success'] else "FAIL"
    tag = " [S]" if tt['tool'] in SCANNERS else ""
    print(f"  {i+1:2d}. {tt['tool']:35s} {status}{tag}   {tt['ts'][11:19]}")

# Show errors
if errors:
    unique_err = list(dict.fromkeys(errors))
    print(f"\n--- ERRORS ({len(errors)} total, {len(unique_err)} unique) ---")
    for e in unique_err[:15]:
        print(f"  - {e}")

# Diagnosis
print(f"\n{'='*70}")
print("ROOT CAUSE DIAGNOSIS")
print(f"{'='*70}")

if sc == 0:
    print("  [CRITICAL] Zero scanner tools used!")
elif sc < 5:
    print(f"  [HIGH] Only {sc} scanner calls — scanners barely used")

if sr > 0 and total > 0 and sr / total > 0.6:
    print(f"  [HIGH] send_request dominance: {sr*100//total}%")

if len(errors) > total * 0.3:
    print(f"  [CRITICAL] {len(errors)}/{total} calls errored ({len(errors)*100//total}% failure rate)")

sandbox_errs = [e for e in errors if 'sandbox' in e.lower() or 'container' in e.lower() or 'proxy' in e.lower()]
if sandbox_errs:
    print(f"  [CRITICAL] {len(sandbox_errs)} sandbox/proxy errors — tools can't execute in sandbox!")
    
if vulns < 10:
    print(f"  [HIGH] Only {vulns} vulns found — expected 50+ for Juice Shop")
