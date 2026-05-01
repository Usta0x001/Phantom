from phantom.tools.registry import tools
import re

no_ex = []
for t in tools:
    xml = t.get("xml_schema", "")
    if not re.search(r"<function=[^>]+>.*?</function>", xml, re.DOTALL):
        no_ex.append(t["name"])

with open("_tmp_no_ex_schemas.txt", "w", encoding="utf-8") as f:
    for name in no_ex:
        for t in tools:
            if t["name"] == name:
                f.write(f"=== {name} ===\n")
                f.write(t["xml_schema"])
                f.write("\n\n")
                break

print(f"Dumped {len(no_ex)} schemas to _tmp_no_ex_schemas.txt")
