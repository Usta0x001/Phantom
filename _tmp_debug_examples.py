from phantom.tools.registry import tools
import re

for t in tools:
    xml = t.get("xml_schema", "")
    if "<example>" in xml:
        ex = re.search(r"<example>(.*?)</example>", xml, re.DOTALL)
        if ex and "<function=" not in ex.group(1):
            print(f"{t['name']}: {repr(ex.group(1)[:100])}")
