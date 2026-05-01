from phantom.tools.registry import tools
import re

complex_tools = []
for t in tools:
    xml = t.get("xml_schema", "")
    if re.search(r"<function=[^>]+>.*?</function>", xml, re.DOTALL):
        continue
    has_array = 'type="array"' in xml or 'type="list"' in xml
    has_bool = 'type="boolean"' in xml
    has_object = 'type="object"' in xml or 'type="dict"' in xml
    params = re.findall(r'<parameter\b[^>]*\bname="([^"]+)"', xml)
    if has_array or has_bool or has_object or len(params) > 3:
        complex_tools.append((t["name"], has_array, has_bool, has_object, len(params)))

for name, arr, boo, obj, count in complex_tools:
    print(f"{name}: array={arr}, bool={boo}, object={obj}, params={count}")
