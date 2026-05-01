"""End-to-end execution path verification."""
import asyncio
import inspect
from phantom.tools.registry import get_tool_by_name, get_tool_names, get_tool_param_schema, needs_agent_state
from phantom.tools.executor import validate_tool_availability, _validate_tool_arguments, execute_tool_with_validation
from phantom.llm.utils import parse_tool_invocations

print("=" * 60)
print("END-TO-END EXECUTION PATH VERIFICATION")
print("=" * 60)

# 1. Test tool invocation parsing
print("\n[1] TOOL INVOCATION PARSING")
llm_output = '''
I'll check the scan status first.
<function=get_scan_status>
  <parameter=include_recommendations>true</parameter>
</function>

Now let me search for files:
<function=search_files>
  <parameter=path>/workspace</parameter>
  <parameter=regex>def\s+main</parameter>
</function>
'''

invocations = parse_tool_invocations(llm_output)
if invocations:
    print(f"  Parsed {len(invocations)} tool invocations:")
    for inv in invocations:
        print(f"    - {inv['toolName']}: {inv['args']}")
else:
    print("  FAIL: Could not parse invocations")

# 2. Test argument validation
print("\n[2] ARGUMENT VALIDATION")
test_cases = [
    ("get_scan_status", {"include_recommendations": "true"}, True),
    ("get_scan_status", {}, True),  # all optional
    ("finish_scan", {"executive_summary": "test"}, False),  # missing required
    ("browser_action", {"action": "goto", "url": "https://example.com"}, True),
    ("browser_action", {"action": "goto", "timeout": "10"}, False),  # phantom param
    ("detect_pattern", {"response_body": "error", "vuln_class": "sqli"}, True),
]

for tool_name, kwargs, should_pass in test_cases:
    error = _validate_tool_arguments(tool_name, kwargs)
    passed = error is None
    if passed == should_pass:
        print(f"  PASS: {tool_name} with {kwargs} -> {'valid' if passed else 'invalid'}")
    else:
        print(f"  FAIL: {tool_name} with {kwargs} -> expected {'valid' if should_pass else 'invalid'}, got {'valid' if passed else 'invalid'}")
        if error:
            print(f"       Error: {error}")

# 3. Test needs_agent_state
print("\n[3] AGENT STATE REQUIREMENTS")
agent_state_tools = [n for n in get_tool_names() if needs_agent_state(n)]
print(f"  Tools requiring agent_state: {sorted(agent_state_tools)}")

# 4. Test actual tool execution for host tools
print("\n[4] ACTUAL TOOL EXECUTION (host tools)")

async def test_tools():
    tests = [
        ("detect_pattern", {"response_body": "SQL syntax error near", "vuln_class": "sqli"}),
        ("detect_error_based", {"response_body": "MySQL error", "vuln_class": "sqli"}),
        ("detect_timing_based", {"baseline_time": 0.2, "test_time": 5.2}),
        ("web_search", {"query": "CVE-2021-44228"}),
    ]
    
    for name, kwargs in tests:
        try:
            result = await execute_tool_with_validation(name, **kwargs)
            if isinstance(result, str) and result.startswith("Error:"):
                print(f"  FAIL: {name} -> {result}")
            else:
                print(f"  PASS: {name} executed successfully")
        except Exception as e:
            print(f"  FAIL: {name} -> {type(e).__name__}: {e}")

asyncio.run(test_tools())

# 5. Check for phantom params in schemas that would fail validation
print("\n[5] PHANTOM PARAM CHECK")
phantom_found = []
for name in sorted(get_tool_names()):
    schema = get_tool_param_schema(name)
    if not schema:
        continue
    func = get_tool_by_name(name)
    sig = inspect.signature(func)
    func_params = set(sig.parameters.keys())
    func_params.discard('agent_state')
    func_params.discard('state')
    schema_params = schema.get('params', set())
    extra = schema_params - func_params
    if extra:
        phantom_found.append(f"{name}: phantom params {extra}")

if phantom_found:
    for p in phantom_found:
        print(f"  FAIL: {p}")
else:
    print("  PASS: No phantom params in any schema")

print("\n" + "=" * 60)
print("EXECUTION PATH VERIFICATION COMPLETE")
print("=" * 60)
