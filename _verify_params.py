import inspect
from phantom.tools.registry import get_tool_by_name, get_tool_names

# Check every tool: do schema params match function params?
mismatches = []

for name in sorted(get_tool_names()):
    func = get_tool_by_name(name)
    sig = inspect.signature(func)
    func_params = set(sig.parameters.keys())
    
    # agent_state is injected by executor, not in schema
    func_params.discard('agent_state')
    func_params.discard('state')
    
    # Get schema XML
    from phantom.tools.registry import get_tool_param_schema
    schema = get_tool_param_schema(name)
    if schema:
        schema_params = set(schema.keys())
    else:
        schema_params = set()
    
    # Check schema has params not in function
    extra_in_schema = schema_params - func_params
    missing_in_schema = func_params - schema_params
    
    if extra_in_schema:
        mismatches.append(f"{name}: SCHEMA HAS EXTRA params not in function: {extra_in_schema}")
    if missing_in_schema:
        mismatches.append(f"{name}: FUNCTION HAS params not in schema: {missing_in_schema}")

print(f"Checked {len(get_tool_names())} tools")
print(f"Mismatches: {len(mismatches)}")
for m in mismatches:
    print("  ", m)
