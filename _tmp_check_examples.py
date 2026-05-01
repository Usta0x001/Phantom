from phantom.tools.registry import tools
import re

for t in tools:
    xml = t.get("xml_schema", "")
    examples = re.findall(r"<function=[^>]+>.*?</function>", xml, re.DOTALL)
    for ex in examples:
        if "[" in ex or "true" in ex.lower() or "false" in ex.lower():
            print(f"{t['name']}: {ex[:120]}...")
            break
