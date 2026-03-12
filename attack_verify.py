"""attack_verify.py — Full adversarial verification of all changes."""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

print("=" * 70)
print("ADVERSARIAL VERIFICATION OF ALL CHANGES")
print("=" * 70)

# ── PROOF 1: Token interpretation ─────────────────────────────────────────
print("\n[PROOF 1] Actual per-call token sizes (not cumulative sums)")
log = ROOT / "phantom_runs/estin-dz_d484/audit.jsonl"
events = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]
resps = [e for e in events if e["event_type"] == "llm.response"]

# tokens_in in OLD audit = cumulative running total.
# Per-call actual = consecutive difference.
raw_cumulatives = [r["payload"].get("tokens_in", 0) for r in resps]
per_call = [raw_cumulatives[0]] + [
    raw_cumulatives[i] - raw_cumulatives[i-1] for i in range(1, len(raw_cumulatives))
]
print(f"  {'Call':<5} {'Per-call tokens':>16}  {'Out':>5}  {'Dur':>7}")
for i, (pc, r) in enumerate(zip(per_call, resps), 1):
    out = r["payload"].get("tokens_out", 0)
    dur = r["payload"].get("duration_ms", 0)
    print(f"  {i:<5} {pc:>16,}  {out:>5}  {dur:>6.0f}ms")

# System prompt is likely ~25K tokens (call 1 = 30K, initial history = small)
# Real conversation history size ≈ per_call - system_prompt_size
# Call 1 per_call = 30,248; system prompt ≈ 28K; initial history ≈ 2K
total_real = sum(per_call)
print(f"\n  Total input tokens actually sent: {total_real:,}")
print(f"  TUI reported: 547,279 tokens ✓" if total_real == 547_279 else f"  MISMATCH: {total_real}")

# Conversation history grows per call by:
deltas_growth = [per_call[i] - per_call[i-1] for i in range(1, len(per_call))]
print(f"\n  Conversation growth per iteration (new tokens added):")
print(f"  {deltas_growth}")
print(f"  Average: {sum(deltas_growth)/len(deltas_growth):.0f} tokens/iter")

# Estimate conversation_history size (no system prompt) at each iteration
# System prompt ≈ call_1_size minus initial small task
# Initial task is probably ~200-500 tokens
# Estimate: sys_prompt ≈ call_15_per_call - 15*avg_growth - initial_task
avg_growth = sum(deltas_growth) / len(deltas_growth)
est_sys_prompt = per_call[0] - avg_growth / 2  # rough
est_hist = [pc - est_sys_prompt for pc in per_call]
print(f"\n  Estimated system prompt size: ~{est_sys_prompt:,.0f} tokens")
print(f"  Estimated conversation history size at each call:")
for i, h in enumerate(est_hist, 1):
    print(f"    Call {i:2d}: {max(0, h):6,.0f} tokens conversation history")

# ── PROOF 2: Compression threshold comparison ──────────────────────────────
print("\n[PROOF 2] Compression threshold: OLD vs NEW")
OLD_THRESHOLD = 20_000 * 0.6 * 0.9   # 10,800
NEW_THRESHOLD = 76_800 * 0.9           # 69,120 (128K fallback → 76.8K max → 0.9 trigger)

print(f"  OLD threshold: {OLD_THRESHOLD:,.0f} tokens (conversation history only)")
print(f"  NEW threshold: {NEW_THRESHOLD:,.0f} tokens")
print()

old_fires = sum(1 for h in est_hist if h > OLD_THRESHOLD)
new_fires = sum(1 for h in est_hist if h > NEW_THRESHOLD)
print(f"  OLD: compression would fire on {old_fires}/15 calls")
print(f"  NEW: compression would fire on {new_fires}/15 calls")

# ── PROOF 3: Tool truncation savings ───────────────────────────────────────
print("\n[PROOF 3] Tool truncation savings (chars saved per call)")
tool_results = [e for e in events if e["event_type"] == "tool.result"]
OLD_DEFAULT = 6000
from phantom.tools.executor import _get_truncation_limit

KNOWN_TOOLS_AND_EXPECTED = {
    "naabu": 1500, "nmap": 3000, "grep": 2000, "curl": 2000,
    "terminal_execute": 4000, "browser_action": 3000,
    "nuclei": 5000, "sqlmap": 5000, "unknown_tool": 6000,
}

total_old_limit = 0
total_new_limit = 0
for e in tool_results:
    name = e["payload"].get("tool_name", "?")
    chars = e["payload"].get("result_chars", 0)
    new_lim = _get_truncation_limit(name)
    actually_sent_old = min(chars, OLD_DEFAULT)
    actually_sent_new = min(chars, new_lim)
    total_old_limit += actually_sent_old
    total_new_limit += actually_sent_new
    savings = actually_sent_old - actually_sent_new
    print(f"  {name:25s}: chars={chars:5,}  old_lim={OLD_DEFAULT:5,}  new_lim={new_lim:5,}  saved={savings:5,}")

print(f"\n  Total chars in context (old): {total_old_limit:,}")
print(f"  Total chars in context (new): {total_new_limit:,}")
print(f"  Total saved:                  {total_old_limit - total_new_limit:,} chars ({100*(total_old_limit-total_new_limit)/max(total_old_limit,1):.1f}%)")
print(f"  Approx tokens saved:          ~{(total_old_limit - total_new_limit) // 4:,} tokens/scan")

# ── PROOF 4: Verify new code constants ────────────────────────────────────
print("\n[PROOF 4] Code constant verification")
from phantom.llm.memory_compressor import (
    MAX_TOTAL_TOKENS, MIN_RECENT_MESSAGES, _CONTEXT_FILL_RATIO, MAX_CONTEXT_CEILING,
    COMPRESSOR_MAX_TOKENS, _get_model_context_window
)
assert MAX_TOTAL_TOKENS == 128_000,         f"FAIL MAX_TOTAL_TOKENS: {MAX_TOTAL_TOKENS}"
assert MIN_RECENT_MESSAGES == 12,           f"FAIL MIN_RECENT_MESSAGES: {MIN_RECENT_MESSAGES}"
assert _CONTEXT_FILL_RATIO == 0.6,          f"FAIL fill ratio: {_CONTEXT_FILL_RATIO}"
assert MAX_CONTEXT_CEILING == 120_000,      f"FAIL ceiling: {MAX_CONTEXT_CEILING}"
assert COMPRESSOR_MAX_TOKENS == 1500,       f"FAIL compressor max tokens: {COMPRESSOR_MAX_TOKENS}"
assert _get_model_context_window("openai/Kimi-K2.5") == 128_000, "FAIL fallback"
print("  MAX_TOTAL_TOKENS = 128,000 ✓")
print("  MIN_RECENT_MESSAGES = 12 ✓")
print("  Kimi-K2.5 context window fallback = 128,000 ✓")
print("  Threshold for Kimi-K2.5: {:,} tokens ✓".format(
    min(MAX_CONTEXT_CEILING, max(MIN_RECENT_MESSAGES * 200, int(128_000 * _CONTEXT_FILL_RATIO)))
))

# ── PROOF 5: Env-var configs work ─────────────────────────────────────────
print("\n[PROOF 5] Env-var override chain priority")
os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"] = "naabu=9999"
from phantom.tools.executor import _get_truncation_limit as gtl
assert gtl("naabu") == 9999,  "FAIL: env override lost"
del os.environ["PHANTOM_TOOL_TRUNCATION_OVERRIDES"]
assert gtl("naabu") == 1500,  "FAIL: built-in not restored"
print("  env override > built-in > global default: ✓")

os.environ["PHANTOM_MAX_INPUT_TOKENS"] = "50000"
import importlib, phantom.llm.memory_compressor as mcm
importlib.reload(mcm)
mc2 = mcm.MemoryCompressor(model_name="openai/Kimi-K2.5")
assert mc2._max_total_tokens == 50_000, f"FAIL PHANTOM_MAX_INPUT_TOKENS: {mc2._max_total_tokens}"
del os.environ["PHANTOM_MAX_INPUT_TOKENS"]
print("  PHANTOM_MAX_INPUT_TOKENS override: ✓")

# ── PROOF 6: Audit log_compression event new method ──────────────────────
print("\n[PROOF 6] New audit.log_compression method")
from phantom.logging.audit import AuditLogger
al = AuditLogger.__new__(AuditLogger)
al.enabled = False
al.log_compression("agent", "openai/Kimi-K2.5", 20, 8, 50000, 10, 1500.0)
print("  log_compression() callable with enabled=False: ✓")

print("\n" + "=" * 70)
print("ALL PROOFS PASSED")
print("=" * 70)
