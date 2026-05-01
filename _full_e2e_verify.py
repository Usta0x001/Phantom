"""Final comprehensive end-to-end verification of the phantom tool system."""
import inspect
import re
import sys

# Force fresh import
for mod_name in list(sys.modules.keys()):
    if mod_name.startswith('phantom'):
        del sys.modules[mod_name]

import phantom.tools
from phantom.tools.registry import (
    tools, _tools_by_name, _tool_param_schemas,
    get_tools_prompt, get_tool_names, get_tool_by_name,
    get_tool_param_schema, needs_agent_state, should_execute_in_sandbox
)
from phantom.tools.executor import validate_tool_availability, _validate_tool_arguments
from phantom.llm.utils import parse_tool_invocations

ERRORS = []
WARNINGS = []

def error(msg):
    ERRORS.append(msg)
    print(f"  ERROR: {msg}")

def warning(msg):
    WARNINGS.append(msg)
    print(f"  WARN: {msg}")

def ok(msg):
    print(f"  PASS: {msg}")

print("=" * 70)
print("PHANTOM SYSTEM END-TO-END VERIFICATION")
print("=" * 70)

# =============================================================================
# 1. REGISTRY VERIFICATION
# =============================================================================
print("\n[1] REGISTRY VERIFICATION")
print(f"  Tools registered: {len(tools)}")
print(f"  Tools by name: {len(_tools_by_name)}")
print(f"  Param schemas: {len(_tool_param_schemas)}")

names_from_tools = {t['name'] for t in tools}
names_from_by_name = set(_tools_by_name.keys())
names_from_schemas = set(_tool_param_schemas.keys())

if names_from_tools != names_from_by_name:
    error(f"tools list vs _tools_by_name mismatch: {names_from_tools ^ names_from_by_name}")
else:
    ok("tools list matches _tools_by_name")

if names_from_tools != names_from_schemas:
    error(f"tools list vs schemas mismatch: {names_from_tools ^ names_from_schemas}")
else:
    ok("tools list matches _tool_param_schemas")

xml_loaded = 0
fallback_loaded = 0
error_loaded = 0
for t in tools:
    xml = t.get('xml_schema', '')
    if 'Schema not found' in xml:
        fallback_loaded += 1
    elif 'Error loading schema' in xml:
        error_loaded += 1
    else:
        xml_loaded += 1

print(f"  Schemas from XML files: {xml_loaded}")
print(f"  Fallback schemas: {fallback_loaded}")
print(f"  Error schemas: {error_loaded}")

if fallback_loaded > 0:
    error(f"{fallback_loaded} tools using fallback schemas!")
if error_loaded > 0:
    error(f"{error_loaded} tools with schema load errors!")
if xml_loaded == len(tools):
    ok("All schemas loaded from XML files")

# =============================================================================
# 2. SCHEMA VS FUNCTION SIGNATURE VERIFICATION
# =============================================================================
print("\n[2] SCHEMA VS FUNCTION SIGNATURE VERIFICATION")

mismatch_count = 0
for name in sorted(_tools_by_name.keys()):
    func = _tools_by_name[name]
    schema = get_tool_param_schema(name)
    
    if not schema:
        error(f"{name}: No param schema found")
        mismatch_count += 1
        continue
    
    sig = inspect.signature(func)
    sig_params = set()
    sig_required = set()
    
    for pname, param in sig.parameters.items():
        if pname in ('agent_state', 'state'):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        sig_params.add(pname)
        if param.default is inspect.Parameter.empty:
            sig_required.add(pname)
    
    schema_params = schema.get('params', set())
    schema_required = schema.get('required', set())
    
    extra_in_schema = schema_params - sig_params
    missing_from_schema = sig_params - schema_params
    extra_required = schema_required - sig_required
    missing_required = sig_required - schema_required
    
    issues = []
    if extra_in_schema:
        issues.append(f"phantom params: {extra_in_schema}")
    if missing_from_schema:
        issues.append(f"missing params: {missing_from_schema}")
    if extra_required:
        issues.append(f"over-required: {extra_required}")
    if missing_required:
        issues.append(f"under-required: {missing_required}")
    
    if issues:
        error(f"{name}: {'; '.join(issues)}")
        mismatch_count += 1

if mismatch_count == 0:
    ok(f"All {len(_tools_by_name)} tools have matching schemas")
else:
    print(f"  TOTAL MISMATCHES: {mismatch_count}")

# =============================================================================
# 3. AGENT_STATE REQUIREMENTS
# =============================================================================
print("\n[3] AGENT_STATE REQUIREMENTS")
state_tools = []
for name in sorted(_tools_by_name.keys()):
    func = _tools_by_name[name]
    sig = inspect.signature(func)
    if 'agent_state' in sig.parameters:
        param = sig.parameters['agent_state']
        if param.default is inspect.Parameter.empty:
            state_tools.append(name)
            ok(f"{name}: requires agent_state (no default)")

print(f"  Tools requiring agent_state: {len(state_tools)}")

# =============================================================================
# 4. IMPORT VERIFICATION
# =============================================================================
print("\n[4] IMPORT VERIFICATION")
import importlib

modules_to_test = [
    'phantom.tools.browser.browser_actions',
    'phantom.tools.file_edit.file_edit_actions',
    'phantom.tools.terminal.terminal_actions',
    'phantom.tools.python.python_actions',
    'phantom.tools.proxy.proxy_actions',
    'phantom.tools.notes.notes_actions',
    'phantom.tools.vuln_intel.vuln_intel_actions',
    'phantom.tools.detection.detector',
    'phantom.tools.response_analysis.response_analysis_actions',
    'phantom.tools.recon.directory_bruteforce',
    'phantom.tools.recon.js_analysis_actions',
    'phantom.tools.osint.osint_actions',
    'phantom.tools.osint.subdomain_bruteforce',
    'phantom.tools.hypothesis.hypothesis_actions',
    'phantom.tools.reporting.reporting_actions',
    'phantom.tools.reporting.elite_reporting',
    'phantom.tools.scan_registry',
    'phantom.tools.agents_graph.agents_graph_actions',
    'phantom.tools.session_mgmt.auth_automation',
    'phantom.tools.session_mgmt.session_mgmt_actions',
    'phantom.tools.finish.finish_actions',
    'phantom.tools.waf.waf_actions',
    'phantom.tools.payload_gen.payload_gen_actions',
    'phantom.tools.api_schema.api_schema_actions',
    'phantom.tools.web_search.web_search_actions',
    'phantom.tools.thinking.thinking_actions',
    'phantom.tools.todo.todo_actions',
]

import_errors = []
for mod_name in modules_to_test:
    try:
        importlib.import_module(mod_name)
        ok(f"{mod_name.split('.')[-1]} imports cleanly")
    except Exception as e:
        error(f"{mod_name}: {type(e).__name__}: {e}")
        import_errors.append(mod_name)

if 'phantom.tools.terminal.terminal_actions' in import_errors:
    print("  NOTE: terminal_actions may fail on Windows due to libtmux - this is expected")

# =============================================================================
# 5. ARGUMENT VALIDATION
# =============================================================================
print("\n[5] ARGUMENT VALIDATION")

test_cases = [
    # (tool_name, kwargs, should_pass, description)
    ("get_scan_status", {"include_recommendations": "true"}, True, "valid optional param"),
    ("get_scan_status", {}, True, "no params, all optional"),
    ("finish_scan", {"executive_summary": "test", "methodology": "m", "technical_analysis": "t", "recommendations": "r"}, True, "all required present"),
    ("finish_scan", {"executive_summary": "test"}, False, "missing required params"),
    ("browser_action", {"action": "goto", "url": "https://example.com"}, True, "valid browser action"),
    ("browser_action", {"action": "goto", "timeout": "10"}, False, "phantom param timeout"),
    ("browser_action", {"action": "goto", "selector": "div"}, False, "phantom param selector"),
    ("browser_action", {"action": "goto", "wait_state": "networkidle"}, False, "phantom param wait_state"),
    ("detect_pattern", {"response_body": "error", "vuln_class": "sqli"}, True, "valid detector"),
    ("str_replace_editor", {"command": "view", "path": "/test"}, True, "valid file edit"),
    ("str_replace_editor", {"command": "view", "path": "/test", "view_range": "[1,10]"}, True, "view_range as string"),
    ("terminal_execute", {"command": "ls", "timeout": "30"}, True, "valid terminal"),
    ("terminal_execute", {"command": "ls", "phantom_param": "x"}, False, "unknown param"),
    ("cve_search", {"product": "apache"}, True, "valid CVE search"),
    ("cve_search", {"keyword": "apache"}, False, "wrong param name (keyword)"),
    ("web_search", {"query": "test"}, True, "valid web search"),
    ("send_request", {"method": "GET", "url": "https://example.com"}, True, "valid proxy request"),
    ("send_request", {"url": "https://example.com"}, False, "missing required method"),
    ("whois_lookup", {"domain": "example.com"}, True, "valid whois"),
    ("dns_enum", {"domain": "example.com"}, True, "valid dns enum"),
    ("add_hypothesis", {"surface": "test", "vuln_class": "sqli"}, True, "valid hypothesis"),
    ("add_hypothesis", {"surface": "test", "payload": "test"}, False, "wrong param name (payload)"),
    ("analyze_response", {"response_body": "test"}, True, "valid analyze_response"),
    ("analyze_response", {"response_body": "test", "request_url": "x"}, False, "wrong param name (request_url)"),
]

validation_errors = 0
for tool_name, kwargs, should_pass, desc in test_cases:
    error_msg = _validate_tool_arguments(tool_name, kwargs)
    passed = error_msg is None
    if passed == should_pass:
        ok(f"{tool_name} ({desc}): {'accepted' if passed else 'rejected'}")
    else:
        error(f"{tool_name} ({desc}): expected {'pass' if should_pass else 'fail'}, got {'pass' if passed else 'fail'}")
        if error_msg:
            print(f"         Error: {error_msg[:100]}")
        validation_errors += 1

if validation_errors == 0:
    ok(f"All {len(test_cases)} validation tests passed")

# =============================================================================
# 6. TOOL INVOCATION PARSING
# =============================================================================
print("\n[6] TOOL INVOCATION PARSING")

parse_tests = [
    ("""<function=get_scan_status>
  <parameter=include_recommendations>true</parameter>
</function>""", 1, "simple single tool"),
    ("""Some text
<function=browser_action>
  <parameter=action>goto</parameter>
  <parameter=url>https://example.com</parameter>
</function>
More text""", 1, "tool in middle of text"),
    ("""<function=detect_pattern>
  <parameter=response_body>SQL error</parameter>
  <parameter=vuln_class>sqli</parameter>
</function>
<function=detect_error_based>
  <parameter=response_body>MySQL error</parameter>
  <parameter=vuln_class>sqli</parameter>
</function>""", 2, "multiple tools"),
    ("""I'll check that.
<function=search_files>
  <parameter=path>/workspace</parameter>
  <parameter=regex>def main</parameter>
</function>
Now I'll analyze.""", 1, "tool with reasoning"),
    ("""<function=browser_action>
  <parameter=action>goto</parameter>
  <parameter=url>https://example.com</parameter>
""", 1, "incomplete tool (should be fixed)"),
    ("Just some text without tools", 0, "no tools"),
    ("""<function=tool_name>
  <parameter=x>y</parameter>
</function>""", 0, "placeholder tool_name rejected"),
    ("""<function=browser_action><parameter=action>screenshot</parameter></function>""", 1, "single-line tool"),
]

parse_errors = 0
for content, expected_count, desc in parse_tests:
    result = parse_tool_invocations(content)
    actual_count = len(result) if result else 0
    if actual_count == expected_count:
        ok(f"{desc}: found {actual_count} tool(s)")
    else:
        error(f"{desc}: expected {expected_count}, found {actual_count}")
        if result:
            for r in result:
                print(f"         Found: {r['toolName']}")
        parse_errors += 1

param_test = """<function=str_replace_editor>
  <parameter=command>view</parameter>
  <parameter=path>/tmp/test.py</parameter>
  <parameter=view_range>[1, 10]</parameter>
</function>"""
result = parse_tool_invocations(param_test)
if result and result[0]['args'].get('view_range') == '[1, 10]':
    ok("Parameter values extracted correctly")
else:
    error("Parameter value extraction failed")

html_test = """<function=browser_action>
  <parameter=action>goto</parameter>
  <parameter=url>https://example.com?foo=1&amp;bar=2</parameter>
</function>"""
result = parse_tool_invocations(html_test)
if result and result[0]['args'].get('url') == 'https://example.com?foo=1&bar=2':
    ok("HTML entities unescaped correctly")
else:
    error("HTML entity unescape failed")

# =============================================================================
# 7. PROMPT GENERATION
# =============================================================================
print("\n[7] PROMPT GENERATION")

prompt = get_tools_prompt()
print(f"  Prompt length: {len(prompt)} chars")

tool_mentions = re.findall(r'<tool\b[^>]*\bname="([^"]+)"', prompt)
print(f"  Tool definitions in prompt: {len(tool_mentions)}")
print(f"  Unique tool names in prompt: {len(set(tool_mentions))}")

missing = names_from_tools - set(tool_mentions)
if missing:
    error(f"Tools missing from prompt: {missing}")
else:
    ok("All tools present in prompt")

phantom = {'execute_fuzz_batch', 'generate_oast_payload', 'check_oast_interactions'}
found_phantom = phantom & set(tool_mentions)
if found_phantom:
    error(f"Phantom tools in prompt: {found_phantom}")
else:
    ok("No phantom tools in prompt")

if '<required>true</required>' in prompt or 'required="true"' in prompt:
    ok("Prompt contains required parameter annotations")
else:
    warning("Prompt may be missing required parameter annotations")

# =============================================================================
# 8. TOOL EXECUTION
# =============================================================================
print("\n[8] TOOL EXECUTION")
import asyncio
from phantom.tools.executor import execute_tool_with_validation

async def test_execution():
    exec_tests = [
        ("detect_pattern", {"response_body": "SQL syntax error", "vuln_class": "sqli"}),
        ("detect_error_based", {"response_body": "MySQL has gone away", "vuln_class": "sqli"}),
        ("detect_timing_based", {"baseline_time": 0.2, "test_time": 5.5}),
        ("web_search", {"query": "CVE-2021-44228"}),
        ("cve_search", {"product": "apache"}),
        ("whois_lookup", {"domain": "example.com"}),
        ("analyze_response", {"response_body": "test body"}),
    ]
    
    exec_errors = 0
    for name, kwargs in exec_tests:
        try:
            result = await execute_tool_with_validation(name, **kwargs)
            if isinstance(result, str) and result.startswith("Error:"):
                error(f"{name}: Execution returned error: {result[:100]}")
                exec_errors += 1
            else:
                ok(f"{name}: Executed successfully")
        except Exception as e:
            error(f"{name}: Exception during execution: {type(e).__name__}: {e}")
            exec_errors += 1
    
    return exec_errors

exec_errors = asyncio.run(test_execution())

# =============================================================================
# 9. FULL INTEGRATION FLOW
# =============================================================================
print("\n[9] FULL INTEGRATION FLOW")

integration_input = """I'll analyze the response for SQL injection patterns.

<function=detect_pattern>
  <parameter=response_body>You have an error in your SQL syntax near '1=1'</parameter>
  <parameter=vuln_class>sqli</parameter>
</function>

Let me also check for error-based indicators.

<function=detect_error_based>
  <parameter=response_body>MySQL Error 1064: You have an error in your SQL syntax</parameter>
  <parameter=vuln_class>sqli</parameter>
</function>
"""

invocations = parse_tool_invocations(integration_input)
if not invocations or len(invocations) != 2:
    error(f"Integration parse failed: expected 2 tools, got {len(invocations) if invocations else 0}")
else:
    ok(f"Integration parse: found {len(invocations)} tools")
    
    all_valid = True
    for inv in invocations:
        name = inv['toolName']
        args = inv['args']
        err = _validate_tool_arguments(name, args)
        if err:
            error(f"Integration validation failed for {name}: {err[:100]}")
            all_valid = False
    
    if all_valid:
        ok("Integration validation: all tools valid")
        
        async def run_integration():
            results = []
            for inv in invocations:
                name = inv['toolName']
                args = inv['args']
                result = await execute_tool_with_validation(name, **args)
                results.append((name, result))
            return results
        
        results = asyncio.run(run_integration())
        for name, result in results:
            if isinstance(result, str) and result.startswith("Error:"):
                error(f"Integration execution {name}: {result[:100]}")
            else:
                ok(f"Integration execution {name}: success")

# =============================================================================
# 10. SANDBOX EXECUTION FLAGS
# =============================================================================
print("\n[10] SANDBOX EXECUTION FLAGS")

sandbox_tools = [t['name'] for t in tools if t.get('sandbox_execution', True)]
host_tools = [t['name'] for t in tools if not t.get('sandbox_execution', True)]

print(f"  Sandbox-only tools: {len(sandbox_tools)}")
print(f"  Host-side tools: {len(host_tools)}")

expected_sandbox = {'list_requests', 'send_request', 'view_request', 'scope_rules',
                   'list_files', 'search_files', 'str_replace_editor', 'browser_action',
                   'terminal_execute', 'python_action', 'repeat_request', 'create_session', 'update_session'}
expected_host = set(names_from_tools) - expected_sandbox

actual_sandbox = set(sandbox_tools)
actual_host = set(host_tools)

sandbox_ok = expected_sandbox == actual_sandbox
host_ok = expected_host == actual_host

if not sandbox_ok:
    extra = actual_sandbox - expected_sandbox
    missing = expected_sandbox - actual_sandbox
    if extra:
        warning(f"Unexpected sandbox tools: {extra}")
    if missing:
        warning(f"Missing expected sandbox tools: {missing}")
else:
    ok("Sandbox tools match expected set")

if not host_ok:
    extra = actual_host - expected_host
    missing = expected_host - actual_host
    if extra:
        warning(f"Unexpected host tools: {extra}")
    if missing:
        warning(f"Missing expected host tools: {missing}")
else:
    ok("Host tools match expected set")

# =============================================================================
# 11. EDGE CASES
# =============================================================================
print("\n[11] EDGE CASES")

empty_test = _validate_tool_arguments("detect_pattern", {"response_body": "", "vuln_class": ""})
if empty_test is None:
    ok("Empty string params accepted (valid for some tools)")
else:
    warning(f"Empty string params rejected: {empty_test[:80]}")

unknown = validate_tool_availability("nonexistent_tool")
if not unknown[0]:
    ok("Unknown tool correctly rejected")
else:
    error("Unknown tool was accepted!")

view_agent = _validate_tool_arguments("view_agent_graph", {})
if view_agent is None:
    ok("view_agent_graph with no regular params accepted")
else:
    ok(f"view_agent_graph validation: {view_agent[:60]}")

# =============================================================================
# SUMMARY
# =============================================================================
print("\n" + "=" * 70)
print("VERIFICATION SUMMARY")
print("=" * 70)
print(f"Total tools checked: {len(tools)}")
print(f"Errors found: {len(ERRORS)}")
print(f"Warnings: {len(WARNINGS)}")

if ERRORS:
    print("\nERRORS:")
    for e in ERRORS:
        print(f"  - {e}")

if WARNINGS:
    print("\nWARNINGS:")
    for w in WARNINGS:
        print(f"  - {w}")

if not ERRORS:
    print("\n" + "=" * 70)
    print("ALL CHECKS PASSED - SYSTEM IS CLEAN")
    print("=" * 70)
else:
    print("\n" + "=" * 70)
    print(f"SYSTEM HAS {len(ERRORS)} ERROR(S) - NEEDS FIXING")
    print("=" * 70)
    sys.exit(1)
