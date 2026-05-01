from phantom.tools.registry import tools

print(f'Registry loaded {len(tools)} tools')
bad = []
for t in tools:
    xml = t.get('xml_schema', '')
    if not xml or '<tool' not in xml:
        bad.append(t['name'])

if bad:
    for b in bad:
        print(f'BAD XML for {b}')
else:
    print('All registry XML schemas are valid')

# Verify schemas are actually being loaded from files vs fallback
from pathlib import Path
file_loaded = 0
fallback = 0
for t in tools:
    xml = t.get('xml_schema', '')
    if 'Schema not found' in xml or 'Error loading schema' in xml:
        fallback += 1
        print(f'FALLBACK: {t["name"]}')
    else:
        file_loaded += 1

print(f'Loaded from files: {file_loaded}, Fallback: {fallback}')
