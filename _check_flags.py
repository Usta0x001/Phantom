from phantom.tools.registry import tools

for t in tools:
    if t['name'] in ('repeat_request', 'create_session', 'update_session'):
        print(f"{t['name']}: sandbox_execution={t.get('sandbox_execution', True)}")
