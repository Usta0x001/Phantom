from phantom.tools.registry import tools
import re

with open("_tmp_debug_examples.txt", "w", encoding="utf-8") as f:
    for t in tools:
        xml = t.get("xml_schema", "")
        if "<example>" in xml:
            ex = re.search(r"<example>(.*?)</example>", xml, re.DOTALL)
            if ex and "<function=" not in ex.group(1):
                f.write(f"{t['name']}: {repr(ex.group(1)[:120])}\n")
print("written to _tmp_debug_examples.txt")
