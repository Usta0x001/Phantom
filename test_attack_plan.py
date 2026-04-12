import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

print("=" * 70)
print("ATTACK THE PLAN - FIND REMAINING ISSUES")
print("=" * 70)

from phantom.llm.memory_compressor import _extract_anchors_from_chunk
from phantom.agents.state import AgentState

attacks_survived = 0
attacks_total = 0

print("\n" + "=" * 70)
print("ATTACK 1: Empty/Uncertain Keywords Still Miss")
print("=" * 70)

attacks_total += 1
miss_cases = [
    "",
    "   ",
    "No vulnerability here",
    "Safe endpoint",
    "Nothing found",
]

for text in miss_cases:
    anchors = _extract_anchors_from_chunk([{"role": "assistant", "content": text}])
    # Should NOT anchor empty or safe
    if not text.strip() or "safe" in text.lower() or "nothing" in text.lower():
        if not anchors:
            print(f"  [PASS] '{text}' -> NOT anchored (correct)")
            attacks_survived += 1
        else:
            print(f"  [FAIL] '{text}' -> anchored (should not)")

print(f"\n[RESULT] {attacks_survived}/{attacks_total} passed")


print("\n" + "=" * 70)
print("ATTACK 2: Message Expiration Doesn't Delete Critical Data")
print("=" * 70)

attacks_total += 1
state = AgentState(agent_id="attack2")

for i in range(10):
    state.add_message("user", f"Task {i}")
    state.add_message("assistant", f"Result {i}")
    if i == 5:
        state.add_message("assistant", "CRITICAL: Found SQLi!")

# Keep track of finding
finding_before = any("SQLi" in str(m.get("content", "")) for m in state.messages)
print(f"  Finding before: {finding_before}")

removed = state.cleanup_old_messages()
finding_after = any("SQLi" in str(m.get("content", "")) for m in state.messages)
print(f"  Finding after: {finding_after}")

if finding_before and not finding_after:
    print(f"  [FAIL] Critical finding lost!")
else:
    print(f"  [PASS] Critical finding preserved")
    attacks_survived += 1


print("\n" + "=" * 70)
print("ATTACK 3: Confidence Score Not Propagated")
print("=" * 70)

attacks_total += 1
state3 = AgentState(agent_id="attack3")

state3.add_finding_anchor({"text": "Might be issue", "key": "test1", "confidence": "low"})
state3.add_finding_anchor({"text": "Found SQLi", "key": "test2", "confidence": "high"})

anchors = state3.finding_anchors
has_confidence = all("confidence" in a for a in anchors)

if has_confidence:
    print(f"  [PASS] All anchors have confidence")
    attacks_survived += 1
else:
    print(f"  [FAIL] Missing confidence in some anchors")


print("\n" + "=" * 70)
print("ATTACK 4: Too Many Anchors")
print("=" * 70)

attacks_total += 1
state4 = AgentState(agent_id="attack4")

for i in range(20):
    state4.add_finding_anchor({"text": f"Finding {i}", "key": f"find{i}"})

if len(state4.finding_anchors) <= 15:
    print(f"  [PASS] Anchors capped at {len(state4.finding_anchors)}")
    attacks_survived += 1
else:
    print(f"  [FAIL] Too many anchors: {len(state4.finding_anchors)}")


print("\n" + "=" * 70)
print("ATTACK 5: Duplicate Anchors")
print("=" * 70)

attacks_total += 1
state5 = AgentState(agent_id="attack5")

state5.add_finding_anchor({"text": "Found SQLi", "key": "find1"})
state5.add_finding_anchor({"text": "Found SQLi", "key": "find1"})  # duplicate
state5.add_finding_anchor({"text": "Found RCE", "key": "find2"})

if len(state5.finding_anchors) == 2:
    print(f"  [PASS] Duplicate rejected, {len(state5.finding_anchors)} unique")
    attacks_survived += 1
else:
    print(f"  [FAIL] Duplicates allowed: {len(state5.finding_anchors)}")


print("\n" + "=" * 70)
print("ATTACK SUMMARY")
print("=" * 70)

print(f"\nTotal attacks: {attacks_total}")
print(f"Survived: {attacks_survived}")
print(f"Failed: {attacks_total - attacks_survived}")

if attacks_survived == attacks_total:
    print("\nALL ATTACKS SURVIVED!")
else:
    print(f"\nSOME ATTACKS FAILED: {attacks_total - attacks_survived}")

print("\n" + "=" * 70)
print("ATTACK COMPLETE")
print("=" * 70)