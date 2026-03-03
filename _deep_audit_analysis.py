"""Deep analysis: what did each tool return? Why did agent stop using scanners?"""
import json
from pathlib import Path

run_dir = sorted(Path("phantom_runs").iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)[0]
audit = run_dir / "audit.jsonl"

entries = []
with open(audit, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            entries.append(json.loads(line))
        except:
            pass

print(f"Total audit entries: {len(entries)}")
print(f"\n{'='*70}")
print("DETAILED TOOL CALL ANALYSIS")
print(f"{'='*70}")

for i, e in enumerate(entries):
    et = e.get('event_type', '')
    data = e.get('data', {})
    ts = e.get('timestamp', '')[11:19]
    
    if et == 'tool_call':
        tn = data.get('tool_name', '?')
        args = data.get('args', {})
        success = data.get('success', True)
        result_preview = str(data.get('result', ''))[:200]
        error = data.get('error', '')
        
        # For scanners, show what they found
        if tn in ('nuclei_scan', 'nmap_scan', 'katana_crawl', 'ffuf_directory_scan', 
                  'httpx_probe', 'sqlmap_test'):
            print(f"\n[{ts}] {tn} {'OK' if success else 'FAIL'}")
            print(f"  Args: {json.dumps(args)[:150]}")
            if error:
                print(f"  ERROR: {error[:200]}")
            # Try to extract findings count
            result = data.get('result', {})
            if isinstance(result, dict):
                findings = result.get('total_findings', result.get('findings', ''))
                if isinstance(findings, list):
                    print(f"  Findings: {len(findings)}")
                elif findings:
                    print(f"  Findings: {findings}")
                urls_found = result.get('urls_found', result.get('discovered_urls', ''))
                if urls_found:
                    if isinstance(urls_found, list):
                        print(f"  URLs found: {len(urls_found)}")
                    else:
                        print(f"  URLs: {urls_found}")
            print(f"  Result preview: {result_preview}")
        
        elif tn == 'create_vulnerability_report':
            vuln_name = args.get('name', args.get('title', '?'))
            vuln_sev = args.get('severity', '?')
            print(f"\n[{ts}] VULN REPORT: [{vuln_sev}] {vuln_name}")
        
        elif tn == 'finish_scan':
            print(f"\n[{ts}] FINISH_SCAN attempted")
            if not success:
                print(f"  Blocked: {error[:100]}")
        
        elif tn == 'send_request':
            method = args.get('method', '?')
            url = args.get('url', '?')
            # Truncate URL
            if len(url) > 80:
                url = url[:77] + '...'
            print(f"  [{ts}] {method:6s} {url}")

print(f"\n{'='*70}")
print("KEY INSIGHTS")
print(f"{'='*70}")
print("1. Did scanners return useful data?")
print("2. Why no sqlmap_test?")
print("3. Why 7 finish_scan attempts?")
print("4. What endpoints were tested manually?")
