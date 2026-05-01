"""
COMPRESSION FIX VALIDATION
Verifies all 4 token-reduction fixes work without breaking tool schemas.
"""

from pathlib import Path
import re


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("COMPRESSION FIX VALIDATION")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 1: Prompt caching uses supports_prompt_caching (not just Anthropic)
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 1] Prompt caching uses supports_prompt_caching...")

llm_src = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
assert_true(
    "supports_prompt_caching used instead of _is_anthropic",
    "supports_prompt_caching(self.config.canonical_model)" in llm_src,
    "still using _is_anthropic only",
)
assert_true(
    "_is_anthropic check removed from caching path",
    "if self._is_anthropic() and self.config.enable_prompt_caching:" not in llm_src,
    "old anthropic-only check still present",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 2: Examples truncated to 1 function call per tool
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 2] Examples truncated to 1 function call per tool...")

from phantom.tools.registry import tools

# Find tools that HAD multiple examples in their raw XML
multi_example_tools = []
for t in tools:
    name = t.get("name", "")
    xml = t.get("xml_schema", "")
    # Count function calls in the loaded schema
    calls = len(re.findall(r"<function=[^>]+>", xml))
    if calls > 1:
        multi_example_tools.append((name, calls))

assert_true(
    "no tool has more than 1 example in loaded schema",
    len(multi_example_tools) == 0,
    f"tools with >1 example: {multi_example_tools}",
)

# Check web_search specifically (had 11 examples in raw XML)
web_search_xml = next(t.get("xml_schema", "") for t in tools if t.get("name") == "web_search")
web_examples = len(re.findall(r"<function=web_search>", web_search_xml))
assert_true(
    "web_search has exactly 1 example",
    web_examples == 1,
    f"has {web_examples} examples",
)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 3: Tool descriptions stripped of marketing bloat
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 3] Tool descriptions stripped of marketing bloat...")

# Check web_search description
ws_desc = re.search(r"<description>(.*?)</description>", web_search_xml, re.DOTALL)
if ws_desc:
    desc_text = ws_desc.group(1)
    assert_true(
        "web_search desc has no bullet lists",
        "\n- " not in desc_text and "\n* " not in desc_text,
        f"bullet list found: {desc_text[:200]}",
    )
    assert_true(
        "web_search desc has no 'PRIMARY' marketing speak",
        "PRIMARY" not in desc_text,
        f"marketing speak found: {desc_text[:200]}",
    )

# Check bruteforce_directories
bf_xml = next(t.get("xml_schema", "") for t in tools if t.get("name") == "bruteforce_directories")
bf_desc = re.search(r"<description>(.*?)</description>", bf_xml, re.DOTALL)
if bf_desc:
    desc_text = bf_desc.group(1)
    assert_true(
        "bruteforce_directories desc has no 'Features' section",
        "Features:" not in desc_text and "features:" not in desc_text,
        f"features section found",
    )
    assert_true(
        "bruteforce_directories desc has no 'Common Findings' section",
        "Common Findings" not in desc_text,
        f"common findings found",
    )
    # But it SHOULD still mention it's active recon
    assert_true(
        "bruteforce_directories still mentions ACTIVE reconnaissance",
        "ACTIVE reconnaissance" in desc_text or "active reconnaissance" in desc_text,
        "critical warning stripped",
    )


# ═══════════════════════════════════════════════════════════════════════════
# FIX 4: Parameter descriptions truncated to first sentence
# ═══════════════════════════════════════════════════════════════════════════
print("\n[FIX 4] Parameter descriptions truncated to first sentence...")

cvr_xml = next(t.get("xml_schema", "") for t in tools if t.get("name") == "create_vulnerability_report")
param_descs = re.findall(
    r"<parameter[^>]*>.*?<description>(.*?)</description>.*?</parameter>",
    cvr_xml,
    re.DOTALL,
)
assert_true(
    "create_vulnerability_report has parameters",
    len(param_descs) > 0,
    f"no parameters found",
)

all_short = all(len(d.strip()) <= 130 for d in param_descs)
assert_true(
    "all parameter descriptions <= 130 chars",
    all_short,
    f"longest: {max(len(d.strip()) for d in param_descs)} chars",
)

# Verify they're not empty
all_nonempty = all(len(d.strip()) > 10 for d in param_descs)
assert_true(
    "all parameter descriptions non-empty",
    all_nonempty,
    "some parameter descriptions are empty",
)


# ═══════════════════════════════════════════════════════════════════════════
# OVERALL: No broken schemas
# ═══════════════════════════════════════════════════════════════════════════
print("\n[OVERALL] No broken schemas after compression...")

broken = [t.get("name") for t in tools if "Schema not found" in t.get("xml_schema", "")]
assert_true(
    "zero broken schemas",
    len(broken) == 0,
    f"broken: {broken}",
)

# Verify total prompt size reduction
from phantom.tools.registry import get_tools_prompt
prompt = get_tools_prompt()
assert_true(
    "tool prompt under 140K chars (was 163K)",
    len(prompt) < 140000,
    f"prompt is {len(prompt)} chars",
)


print("\n" + "=" * 70)
print("ALL COMPRESSION FIXES VALIDATED")
print("=" * 70)
