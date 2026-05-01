import re
from phantom.tools.registry import get_tools_prompt

p = get_tools_prompt()

# Find example sizes per tool
blocks = re.split(r'(?=<tool\b)', p)
for block in blocks:
    if '<tool' not in block:
        continue
    name_match = re.search(r'name="([^"]+)"', block)
    if not name_match:
        continue
    name = name_match.group(1)
    size = len(block)
    if size < 3000:
        continue
    
    desc_match = re.search(r'<description>(.*?)</description>', block, re.DOTALL)
    desc_size = len(desc_match.group(1)) if desc_match else 0
    
    examples = re.findall(r'<example[^>]*>(.*?)</example>', block, re.DOTALL)
    example_size = sum(len(e) for e in examples)
    
    params_match = re.search(r'<parameters>(.*?)</parameters>', block, re.DOTALL)
    params_size = len(params_match.group(1)) if params_match else 0
    
    print(f"\n{name}: {size} chars")
    print(f"  description: {desc_size} chars ({desc_size/size*100:.0f}%)")
    print(f"  examples: {example_size} chars ({example_size/size*100:.0f}%), count={len(examples)}")
    print(f"  parameters: {params_size} chars ({params_size/size*100:.0f}%)")
    
    # Show first 200 chars of description
    if desc_match:
        desc = desc_match.group(1).strip()[:200].replace('\n', ' ')
        print(f"  desc preview: {desc}...")
