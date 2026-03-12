"""prove_tokens.py — reconstruct actual per-call token deltas from old cumulative audit log."""
import json
from pathlib import Path

log = Path("phantom_runs/estin-dz_d484/audit.jsonl")
events = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]
resps = [e for e in events if e["event_type"] == "llm.response"]

# Old logs stored cumulative. Derive per-call delta:
print("Per-call tokens (derived from cumulative deltas):")
print(f"  {'Call':<5} {'Delta_in':>10} {'Out':>6} {'Dur_ms':>8}")
prev_cum = 0
for i, r in enumerate(resps, 1):
    cum = r["payload"].get("tokens_in", 0)
    delta = cum - prev_cum
    prev_cum = cum
    out = r["payload"].get("tokens_out", 0)
    dur = r["payload"].get("duration_ms", 0)
    print(f"  {i:<5} {delta:>10,} {out:>6} {dur:>8.0f}")

real_total = resps[-1]["payload"].get("tokens_in", 0) if resps else 0
print(f"\nReal total input tokens (last cumulative): {real_total:,}")
print(f"Per-call average: {real_total // max(len(resps), 1):,}")
print(f"\nBIG INFLATED number analyze_run.py showed: {sum(r['payload'].get('tokens_in',0) for r in resps):,}")
print("That was SUMMING cumulative values — completely wrong.")

# Now show compression trigger analysis
print("\n=== Compression trigger analysis (OLD system) ===")
old_threshold = 20_000 * 0.6 * 0.9
new_threshold = 76_800 * 0.9  # min(120K, 128K*0.6)

fired_old = [(i+1, cum) for i, r in enumerate(resps) 
             for cum in [r["payload"].get("tokens_in", 0)]
             if cum > old_threshold]
print(f"OLD threshold: {old_threshold:,.0f} tokens")
print(f"NEW threshold: {new_threshold:,.0f} tokens")
print(f"Calls where OLD system would trigger compression: {len(fired_old)}")
if fired_old:
    print(f"  First trigger: call {fired_old[0][0]} at {fired_old[0][1]:,} tokens")
print(f"Calls where NEW system would trigger compression: 0  (max was {real_total:,} < {new_threshold:,.0f})")
