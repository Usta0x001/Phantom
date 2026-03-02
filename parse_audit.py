"""Parse audit.jsonl to show scan progress."""
import json
import sys
import glob

# Find the latest run directory
run_dirs = sorted(glob.glob("phantom_runs/host-docker-internal-3000_*"))
if not run_dirs:
    print("No run directories found")
    sys.exit(1)

run_dir = run_dirs[-1]
audit_path = f"{run_dir}/audit.jsonl"

print(f"=== Audit log: {audit_path} ===\n")

tool_count = 0
vuln_count = 0

with open(audit_path) as f:
    for line in f:
        if not line.strip():
            continue
        d = json.loads(line)
        et = d.get("event_type", "?")
        data = d.get("data", {})

        if et == "scan_started":
            print(f"SCAN START: targets={data.get('targets', [])}, mode={data.get('scan_mode', '?')}")
        elif et == "tool_call":
            tool_count += 1
            tool = data.get("tool_name", "?")
            args = data.get("args", {})
            success = data.get("success", "?")
            duration = data.get("duration_ms", 0)
            args_str = str(args)[:150]
            status = "OK" if success else "FAIL"
            print(f"  [{tool_count:3d}] {status:4s} {tool:25s} ({duration/1000:.1f}s) {args_str}")
        elif et == "vulnerability_found":
            vuln_count += 1
            vid = data.get("vulnerability_id", "?")
            sev = data.get("severity", "?")
            name = data.get("name", "?")
            print(f"  *** VULN #{vuln_count}: [{sev.upper():8s}] {vid} - {name}")
        elif et == "compression":
            print(f"  [COMPRESS] {data.get('input_messages', '?')} msgs -> summary")

print(f"\n=== TOTALS: {tool_count} tool calls, {vuln_count} vulnerabilities ===")
