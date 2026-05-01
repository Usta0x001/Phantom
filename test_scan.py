import json

with open(r'C:\Users\Gadouri\Desktop\New folder (2)\phantom\phantom_runs\estin-dz_5e7e\events.jsonl') as f:
    for i, line in enumerate(f):
        e = json.loads(line)
        if e.get('event_type') == 'chat':
            payload = e.get('payload')
            print(f'Line {i}: event_type={e.get("event_type")}')
            print(f'  payload type: {type(payload)}')
            print(f'  payload: {str(payload)[:500]}')
            print()
            break