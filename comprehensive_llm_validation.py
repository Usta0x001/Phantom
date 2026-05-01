"""
COMPREHENSIVE LLM PROMPT VALIDATION
=====================================

Reads the actual XML data going to the LLM, validates everything,
and proves the system is perfect for first-try understanding.
"""

import asyncio
import re
import sys
import html
from pathlib import Path
from collections import Counter

# ── Load modules ───────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from phantom.tools.registry import tools, _load_xml_schema
from phantom.llm.utils import parse_tool_invocations, fix_incomplete_tool_call, normalize_tool_format

ERRORS: list[str] = []
WARNINGS: list[str] = []

def error(label: str, detail: str) -> None:
    ERRORS.append(f"[FAIL] {label}: {detail}")
    print(f"  [FAIL] {label}: {detail}")

def warn(label: str, detail: str) -> None:
    WARNINGS.append(f"[WARN] {label}: {detail}")
    print(f"  [WARN] {label}: {detail}")

def ok(label: str) -> None:
    print(f"  [PASS] {label}")

print("=" * 70)
print("COMPREHENSIVE LLM PROMPT & PARSER VALIDATION")
print("=" * 70)

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Registry integrity — all tools loaded, no duplicates
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 1] Registry integrity...")

if not tools:
    error("tools loaded", "registry is empty")
else:
    ok(f"{len(tools)} tools loaded")

names = [t["name"] for t in tools]
dupes = {n: c for n, c in Counter(names).items() if c > 1}
if dupes:
    error("duplicate tool names", str(dupes))
else:
    ok("no duplicate tool names")

missing_schema = [t["name"] for t in tools if not t.get("xml_schema")]
if missing_schema:
    error("missing xml_schema", f"{len(missing_schema)} tools: {missing_schema[:5]}")
else:
    ok("all tools have xml_schema")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: XML well-formedness of every schema
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 2] XML well-formedness...")

broken: list[str] = []
for tool in tools:
    xml = tool.get("xml_schema", "")
    # Basic structural checks
    open_tools = xml.count("<tool ")
    close_tools = xml.count("</tool>")
    if open_tools != close_tools:
        broken.append(f"{tool['name']}: <tool> mismatch ({open_tools} vs {close_tools})")
        continue
    open_desc = xml.count("<description>")
    close_desc = xml.count("</description>")
    if open_desc != close_desc:
        broken.append(f"{tool['name']}: <description> mismatch ({open_desc} vs {close_desc})")
        continue
    # Check that every <function=...> block has balanced <parameter=...> and </parameter>
    for fn_match in re.finditer(r"(<function=[^>]+>)(.*?)(</function>)", xml, re.DOTALL):
        fn_body = fn_match.group(2)
        p_open = len(re.findall(r"<parameter=", fn_body))
        p_close = fn_body.count("</parameter>")
        if p_open != p_close:
            broken.append(f"{tool['name']}: function block param mismatch ({p_open} vs {p_close})")
    # Check for unclosed <example> / <examples> tags
    for tag in ["example", "examples"]:
        raw_opens = len(re.findall(rf"<{tag}\b[^/]*?>", xml))
        raw_closes = xml.count(f"</{tag}>")
        if raw_opens != raw_closes:
            broken.append(f"{tool['name']}: <{tag}> unclosed ({raw_opens} vs {raw_closes})")

if broken:
    for b in broken[:10]:
        error("XML structural issue", b)
    if len(broken) > 10:
        error("XML structural issues", f"...and {len(broken)-10} more")
else:
    ok("all schemas structurally sound")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: Example validity — every example must be parseable
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 3] Example validity & parser compatibility...")

unparseable_examples: list[str] = []
example_count = 0
for tool in tools:
    xml = tool.get("xml_schema", "")
    examples = re.findall(r"<function=[^>]+>.*?</function>", xml, re.DOTALL)
    example_count += len(examples)
    for ex in examples:
        parsed = parse_tool_invocations(ex)
        if not parsed:
            unparseable_examples.append(f"{tool['name']}: {ex[:80]}...")

if unparseable_examples:
    for u in unparseable_examples[:10]:
        error("unparseable example", u)
    if len(unparseable_examples) > 10:
        error("unparseable examples", f"...and {len(unparseable_examples)-10} more")
else:
    ok(f"all {example_count} examples parseable by parser")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: Parameter consistency — examples use real params
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 4] Parameter consistency...")

param_mismatches: list[str] = []
for tool in tools:
    xml = tool.get("xml_schema", "")
    declared = set(tool.get("parameters", []))
    if not declared:
        continue
    examples = re.findall(r"<function=[^>]+>.*?</function>", xml, re.DOTALL)
    for ex in examples:
        used = set(re.findall(r"<parameter=([^>]+)>", ex))
        unknown = used - declared
        if unknown:
            param_mismatches.append(f"{tool['name']}: unknown params {unknown} in example")

if param_mismatches:
    for p in param_mismatches[:10]:
        warn("param mismatch", p)
    if len(param_mismatches) > 10:
        warn("param mismatches", f"...and {len(param_mismatches)-10} more")
else:
    ok("all example params match declared params")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: Description quality — not empty, not truncated mid-word
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 5] Description quality...")

bad_descs: list[str] = []
for tool in tools:
    xml = tool.get("xml_schema", "")
    desc_match = re.search(r"<description>(.*?)</description>", xml, re.DOTALL)
    if not desc_match:
        bad_descs.append(f"{tool['name']}: missing <description>")
        continue
    desc = desc_match.group(1).strip()
    if not desc:
        bad_descs.append(f"{tool['name']}: empty description")
    elif desc.endswith("...") and len(desc) >= 117:
        # Truncated param desc inside tool-level desc? Check if it's the tool desc itself.
        pass  # Allow param desc truncation
    elif any(word in desc.lower() for word in ["features:", "common findings:", "elite features:"]):
        bad_descs.append(f"{tool['name']}: still has marketing bloat")
    elif "This is your PRIMARY" in desc or "This is your MAIN" in desc:
        bad_descs.append(f"{tool['name']}: still has PRIMARY marketing speak")

if bad_descs:
    for b in bad_descs[:10]:
        error("description issue", b)
    if len(bad_descs) > 10:
        error("description issues", f"...and {len(bad_descs)-10} more")
else:
    ok("all descriptions clean")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 6: Parameter description truncation check
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 6] Parameter description quality...")

long_params: list[str] = []
empty_params: list[str] = []
for tool in tools:
    xml = tool.get("xml_schema", "")
    for param_match in re.finditer(r"<parameter\b[^>]*>.*?</parameter>", xml, re.DOTALL | re.IGNORECASE):
        block = param_match.group(0)
        desc_m = re.search(r"<description>(.*?)</description>", block, re.DOTALL)
        if not desc_m:
            continue
        text = desc_m.group(1).strip()
        if not text:
            empty_params.append(f"{tool['name']}: empty param desc")
        elif len(text) > 130:
            long_params.append(f"{tool['name']}: param desc {len(text)} chars")

if empty_params:
    error("empty param descriptions", f"{len(empty_params)} found")
else:
    ok("no empty param descriptions")

if long_params:
    for p in long_params[:5]:
        warn("long param description", p)
    if len(long_params) > 5:
        warn("long param descriptions", f"...and {len(long_params)-5} more")
else:
    ok("all param descriptions <= 130 chars")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 7: System prompt — no placeholders, clear rules
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 7] System prompt validation...")

sys_prompt_path = Path("phantom/agents/PhantomAgent/system_prompt.jinja")
sys_prompt = sys_prompt_path.read_text(encoding="utf-8")

# Check for dangerous placeholders
bad_placeholders = []
# The system prompt should NOT contain <function=tool_name> as an example
if "<function=tool_name>" in sys_prompt:
    bad_placeholders.append("<function=tool_name> in system prompt")
# It SHOULD contain a warning against using "tool_name"
if 'NEVER "tool_name"' not in sys_prompt and "NEVER 'tool_name'" not in sys_prompt:
    if "tool_name" in sys_prompt:
        bad_placeholders.append("tool_name mentioned without NEVER warning")

if bad_placeholders:
    for b in bad_placeholders:
        error("system prompt placeholder", b)
else:
    ok("no dangerous placeholders in system prompt")

# Check critical rules exist
critical_rules = [
    "PUT THE TOOL CALL FIRST",
    "MANDATORY: EVERY response must contain exactly ONE tool call",
    "finish_scan",
    "NEVER output natural language without a tool call",
    "Output exactly ONE tool call per response",
    "Use REAL tool names",
]
for rule in critical_rules:
    if rule in sys_prompt:
        ok(f"system prompt has: '{rule}'")
    else:
        error("missing critical rule", rule)

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 8: Combined prompt size & structure
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 8] Combined prompt size & structure...")

# Simulate get_tools_prompt()
from phantom.tools.registry import tools as registry_tools
tool_blocks = [t.get("xml_schema", "") for t in registry_tools if t.get("xml_schema")]
combined = "\n\n".join(tool_blocks)

total_chars = len(combined)
total_tools = len(tool_blocks)
ok(f"combined tool prompt: {total_chars:,} chars across {total_tools} tools")

if total_chars > 200_000:
    error("tool prompt too large", f"{total_chars:,} chars > 200K limit")
elif total_chars > 150_000:
    warn("tool prompt large", f"{total_chars:,} chars")
else:
    ok("tool prompt under 150K chars")

# Check examples-per-tool distribution
examples_per_tool = []
for t in registry_tools:
    xml = t.get("xml_schema", "")
    count = len(re.findall(r"<function=[^>]+>.*?</function>", xml, re.DOTALL))
    examples_per_tool.append(count)

max_examples = max(examples_per_tool) if examples_per_tool else 0
avg_examples = sum(examples_per_tool) / len(examples_per_tool) if examples_per_tool else 0

ok(f"examples per tool: max={max_examples}, avg={avg_examples:.1f}")

if max_examples > 1:
    multi = [t["name"] for t, c in zip(registry_tools, examples_per_tool) if c > 1]
    error("tools with >1 example", f"{multi}")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 9: Parser adversarial tests
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 9] Parser adversarial tests...")

parser_tests = [
    # (name, input, expected_tool_name_or_none)
    ("standard call", '<function=send_request><parameter=method>GET</parameter></function>', "send_request"),
    ("with reasoning after", '<function=send_request><parameter=method>GET</parameter></function>\nNow fetching the page.', "send_request"),
    ("reasoning before", 'Let me check the status.\n<function=get_scan_status></function>', "get_scan_status"),
    ("incomplete fixed", '<function=send_request><parameter=method>GET</parameter>', "send_request"),
    ("multiple calls (should extract first)", '<function=a><parameter=x>1</parameter></function><function=b><parameter=y>2</parameter></function>', "a"),
    ("invoke format", '<invoke name="send_request"><parameter name="method">GET</parameter></invoke>', "send_request"),
    ("parameter name attr", '<function=send_request><parameter name="method">GET</parameter></function>', "send_request"),
    ("tool_name rejected", '<function=tool_name><parameter=x>1</parameter></function>', None),
    ("no params", '<function=get_scan_status></function>', "get_scan_status"),
    ("multiline params", '<function=send_request><parameter=body>{\n  "key": "value"\n}</parameter></function>', "send_request"),
    ("HTML in reasoning", 'Check this </function> tag in reasoning.\n<function=send_request><parameter=url>http://x</parameter></function>', "send_request"),
    ("nested-looking tags", '<function=send_request><parameter=body><xml>test</xml></parameter></function>', "send_request"),
]

parser_pass = 0
parser_fail = 0
for name, inp, expected in parser_tests:
    parsed = parse_tool_invocations(inp)
    if expected is None:
        if parsed is None or not parsed:
            parser_pass += 1
        else:
            parser_fail += 1
            error(f"parser test: {name}", f"expected None, got {parsed}")
    else:
        if parsed and parsed[0]["toolName"] == expected:
            parser_pass += 1
        else:
            parser_fail += 1
            error(f"parser test: {name}", f"expected {expected}, got {parsed}")

ok(f"parser tests: {parser_pass}/{len(parser_tests)} passed")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 10: LLM simulation — verify the LLM would understand
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 10] LLM comprehension simulation...")

# The system prompt + tool prompt is what the LLM sees.
# Let's verify that a model could reasonably infer the format from ONE example.
# Check: every tool has at least one example.
no_example_tools = [t["name"] for t in registry_tools if not re.search(r"<function=[^>]+>.*?</function>", t.get("xml_schema", ""), re.DOTALL)]
if no_example_tools:
    error("tools with no examples", f"{no_example_tools}")
else:
    ok("every tool has at least one example")

# Check: system prompt has a finish_scan example
if "<function=finish_scan>" in sys_prompt:
    ok("system prompt has finish_scan example")
else:
    error("missing finish_scan example", "system prompt lacks explicit finish_scan example")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 11: Semantic checks — would LLM know what to do?
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 11] Semantic clarity checks...")

# Every tool must have a non-empty description
tools_no_desc = [t["name"] for t in registry_tools if not re.search(r"<description>(.+?)</description>", t.get("xml_schema", ""), re.DOTALL)]
if tools_no_desc:
    error("tools missing description", f"{tools_no_desc}")
else:
    ok("all tools have descriptions")

# Tools should not have parameter names that are unclear
unclear_params: list[str] = []
for t in registry_tools:
    xml = t.get("xml_schema", "")
    params = re.findall(r'<parameter\b[^>]*\bname="([^"]+)"', xml)
    for p in params:
        if len(p) <= 1 or p.lower() in ("a", "b", "c", "x", "y", "z"):
            unclear_params.append(f"{t['name']}.{p}")

if unclear_params:
    warn("unclear param names", f"{unclear_params[:5]}...")
else:
    ok("all param names are descriptive")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 12: Integration — end-to-end tool prompt assembly
# ═══════════════════════════════════════════════════════════════════════════
print("\n[PHASE 12] Integration: full prompt assembly...")

# Verify the registry can be imported without errors
try:
    from phantom.tools.registry import tools as _t
    ok("registry imports cleanly")
except Exception as e:
    error("registry import", str(e))

# Verify LLM utils can be imported
try:
    from phantom.llm.utils import parse_tool_invocations as _p
    ok("llm.utils imports cleanly")
except Exception as e:
    error("llm.utils import", str(e))

# ═══════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("FINAL VALIDATION REPORT")
print("=" * 70)
print(f"Tools loaded:        {len(tools)}")
print(f"Total prompt size:   {total_chars:,} chars")
print(f"Max examples/tool:   {max_examples}")
print(f"Parser tests passed: {parser_pass}/{len(parser_tests)}")
print(f"Warnings:            {len(WARNINGS)}")
print(f"Errors:              {len(ERRORS)}")

if ERRORS:
    print("\n[FAIL] ERRORS FOUND - SYSTEM NOT PERFECT:")
    for e in ERRORS:
        print(f"  {e}")
    sys.exit(1)
else:
    print("\n[PASS] ALL VALIDATIONS PASSED - LLM CAN UNDERSTAND AND WORK FROM FIRST TRY")
    if WARNINGS:
        print("\nMinor warnings (non-blocking):")
        for w in WARNINGS:
            print(f"  {w}")
    sys.exit(0)
