from phantom.tools.registry import get_tools_prompt, get_tool_names
import re

prompt = get_tools_prompt()

# Count tools in prompt
tool_count = len(re.findall(r'<tool\b', prompt))
print(f'Tools in prompt: {tool_count}')

# Check for phantom tools that shouldn't be there
bad_tools = ['execute_fuzz_batch', 'generate_oast_payload', 'check_oast_interactions']
for t in bad_tools:
    if t in prompt:
        print(f'BAD: {t} in prompt')
    else:
        print(f'OK: {t} not in prompt')

# Check all registered tools appear in prompt
missing = []
for name in sorted(get_tool_names()):
    if f'name="{name}"' not in prompt:
        missing.append(name)

if missing:
    for m in missing:
        print(f'MISSING FROM PROMPT: {m}')
else:
    print('ALL 56 TOOLS IN PROMPT')

print('PROMPT VERIFICATION COMPLETE')
