import json, sys
d = json.load(open("phantom_runs/host-docker-internal-3000_79a0/checkpoint.json"))
print(f"Iteration: {d['iteration']}/{d['max_iterations']}")
print(f"Phase: {d['phase']}")
print(f"Endpoints: {len(d['endpoints'])}")
print(f"Tested: {len(d['tested_endpoints'])}")
print(f"Vulns: {d['vuln_stats']}")
print(f"Findings: {len(d['findings_ledger'])}")
print("Recent findings:")
for f in d['findings_ledger'][-10:]:
    print(f"  {f[:100]}")
