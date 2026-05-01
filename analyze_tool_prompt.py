import re
from phantom.tools.registry import get_tools_prompt

p = get_tools_prompt()
tools = re.findall(r'<tool\b[^>]*\bname="([^"]+)"[^>]*>', p)
print(f'Total tools in prompt: {len(tools)}')
print(f'Unique tools: {len(set(tools))}')
print(f'Total chars: {len(p)}')

blocks = re.split(r'(?=<tool\b)', p)
sizes = []
for block in blocks:
    if '<tool' in block:
        name_match = re.search(r'name="([^"]+)"', block)
        if name_match:
            sizes.append((name_match.group(1), len(block)))

print('\nTop 15 largest tools:')
for name, size in sorted(sizes, key=lambda x: -x[1])[:15]:
    print(f'  {name}: {size} chars')

# Show total description text
total_desc = 0
for m in re.finditer(r'<description>(.*?)</description>', p, re.DOTALL):
    total_desc += len(m.group(1))
print(f'\nTotal description chars: {total_desc}')

# Show total examples text
total_examples = 0
for m in re.finditer(r'<example[^>]*>(.*?)</example>', p, re.DOTALL):
    total_examples += len(m.group(1))
print(f'Total examples chars: {total_examples}')

# Show total parameters text
total_params = 0
for m in re.finditer(r'<parameters>(.*?)</parameters>', p, re.DOTALL):
    total_params += len(m.group(1))
print(f'Total parameters chars: {total_params}')
