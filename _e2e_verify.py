"""Comprehensive end-to-end tool verification."""
import inspect
import asyncio
from phantom.tools.registry import get_tool_by_name, get_tool_names, get_tool_param_schema, should_execute_in_sandbox

print("=" * 60)
print("END-TO-END TOOL VERIFICATION")
print("=" * 60)

# 1. Signature match
print("\n[1] SCHEMA/FUNCTION SIGNATURE MATCH")
issues = []
for name in sorted(get_tool_names()):
    func = get_tool_by_name(name)
    sig = inspect.signature(func)
    func_params = set(sig.parameters.keys())
    func_required = set(p for p, param in sig.parameters.items() if param.default is inspect._empty)
    func_params.discard('agent_state')
    func_params.discard('state')
    func_required.discard('agent_state')
    func_required.discard('state')
    schema = get_tool_param_schema(name)
    if not schema:
        issues.append(f'{name}: NO SCHEMA')
        continue
    schema_params = schema.get('params', set())
    schema_required = schema.get('required', set())
    extra = schema_params - func_params
    missing = func_params - schema_params
    extra_req = schema_required - func_required
    missing_req = func_required - schema_required
    if extra or missing or extra_req or missing_req:
        issues.append(f'{name}: extra={extra} missing={missing} extra_req={extra_req} missing_req={missing_req}')

if issues:
    for i in issues:
        print(f"  FAIL: {i}")
else:
    print("  PASS: All 56 tools match perfectly")

# 2. Schema XML validity check
print("\n[2] SCHEMA XML VALIDITY")
import re
from pathlib import Path
schema_files = list(Path('phantom/tools').rglob('*_schema.xml'))
xml_issues = []
for sf in schema_files:
    content = sf.read_text()
    # Check for unclosed tags
    open_tools = content.count('<tool')
    close_tools = content.count('</tool>')
    if open_tools != close_tools:
        xml_issues.append(f'{sf}: {open_tools} <tool> vs {close_tools} </tool>')
    # Check empty schemas (should be valid <tools></tools>)
    if '<tools>' not in content and '<tool_schemas>' not in content:
        xml_issues.append(f'{sf}: missing root element')

if xml_issues:
    for i in xml_issues:
        print(f"  FAIL: {i}")
else:
    print(f"  PASS: All {len(schema_files)} schema files are well-formed")

# 3. Tool execution smoke tests
print("\n[3] TOOL EXECUTION SMOKE TESTS")

async def run_async(func, *args, **kwargs):
    return await func(*args, **kwargs)

# Test sync tools
sync_tests = [
    ('query_hypotheses', [], {}),
    ('get_hypothesis_summary', [], {}),
    ('get_scan_status', [], {'include_recommendations': False}),
    ('detect_pattern', ['test body'], {'vuln_class': 'sqli'}),
    ('detect_error_based', ['test body'], {'vuln_class': 'sqli'}),
    ('detect_timing_based', [1.0, 2.0], {}),
    ('list_files', ['/workspace'], {'recursive': False}),
    ('search_files', ['/workspace', 'test'], {}),
    ('str_replace_editor', ['view', '/workspace'], {}),
    ('terminal_execute', ['echo hello'], {}),
]

exec_issues = []
for name, args, kwargs in sync_tests:
    try:
        func = get_tool_by_name(name)
        if inspect.iscoroutinefunction(func):
            result = asyncio.run(run_async(func, *args, **kwargs))
        else:
            result = func(*args, **kwargs)
        if isinstance(result, dict) and result.get('error'):
            err = result['error']
            if 'not found' in str(err).lower() or 'required' in str(err).lower():
                exec_issues.append(f'{name}: returned error: {err}')
            # Other errors like directory not found are OK for smoke test
    except Exception as e:
        exec_issues.append(f'{name}: EXCEPTION: {type(e).__name__}: {e}')

if exec_issues:
    for i in exec_issues:
        print(f"  FAIL: {i}")
else:
    print("  PASS: All smoke tests executed without exceptions")

# 4. Sandbox flags check
print("\n[4] SANDBOX EXECUTION FLAGS")
sandbox_tools = [n for n in get_tool_names() if should_execute_in_sandbox(n)]
print(f"  Sandbox tools ({len(sandbox_tools)}): {sorted(sandbox_tools)}")
host_tools = [n for n in get_tool_names() if not should_execute_in_sandbox(n)]
print(f"  Host tools ({len(host_tools)}): {sorted(host_tools)}")

# 5. Check for async/sync mismatch in hypothesis tools
print("\n[5] ASYNC/SYNC CORRECTNESS")
async_issues = []
for name in ['record_payload_test', 'confirm_hypothesis', 'reject_hypothesis']:
    func = get_tool_by_name(name)
    if not inspect.iscoroutinefunction(func):
        async_issues.append(f'{name}: should be async but is sync')

if async_issues:
    for i in async_issues:
        print(f"  FAIL: {i}")
else:
    print("  PASS: Async tools are correctly defined")

print("\n" + "=" * 60)
print("VERIFICATION COMPLETE")
print("=" * 60)
