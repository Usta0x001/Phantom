"""Extract send_request failure details from the latest audit log."""
import json
import os
import glob

# Find latest run directory
runs_dir = "phantom_runs"
run_dirs = sorted(glob.glob(os.path.join(runs_dir, "*")), key=os.path.getmtime, reverse=True)

for run_dir in run_dirs[:3]:
    audit_file = os.path.join(run_dir, "audit.jsonl")
    if not os.path.exists(audit_file):
        continue
    
    print(f"\n=== {audit_file} ===\n")
    
    with open(audit_file) as f:
        for line in f:
            ev = json.loads(line)
            if ev.get("event") == "tool_call":
                tool = ev.get("tool_name", "")
                if "send_request" in tool or "repeat_request" in tool:
                    seq = ev.get("sequence", "?")
                    success = ev.get("success", None)
                    result = ev.get("result", "")
                    error = ev.get("error", "")
                    params = ev.get("parameters", {})
                    
                    print(f"Event #{seq} | {tool} | success={success}")
                    print(f"  Params: {json.dumps(params, indent=4)[:500]}")
                    if error:
                        print(f"  ERROR: {error[:500]}")
                    if result:
                        print(f"  RESULT: {str(result)[:500]}")
                    print()
    break
