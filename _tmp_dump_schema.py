from phantom.tools.registry import tools
for t in tools:
    if t['name'] == 'fetch_js_files':
        with open('_tmp_schema.txt', 'w', encoding='utf-8') as f:
            f.write(t['xml_schema'])
        print('written to _tmp_schema.txt')
        break
