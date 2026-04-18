import json
import re

with open('phantom/agents/base_agent.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Remove the broken junk inserted at line 818 (which has no actions variable)
broken_junk = """        def _strip_args(val: Any) -> Any:
            if isinstance(val, str):
                return val.strip()
            if isinstance(val, dict):
                return {k: _strip_args(v) for k, v in val.items()}
            if isinstance(val, list):
                return [_strip_args(v) for v in val]
            return val

        try:
            batch_signature = json.dumps(
                [
                    {
                        "toolName": action.get("toolName"),
                        "args": _strip_args(action.get("args", {})),
                    }
                    for action in actions
                ],
                sort_keys=True,
            )
        except Exception:  # noqa: BLE001
            batch_signature = ""

"""
content = content.replace(broken_junk, '')

# 2. Replace the ACTUAL hashing logic strings (there are multiple)
target = """        try:
            batch_signature = json.dumps(
                [
                    {
                        "toolName": action.get("toolName"),
                        "args": action.get("args", {}),
                    }
                    for action in actions
                ],
                sort_keys=True,
            )
        except Exception:  # noqa: BLE001
            batch_signature = \"\"\""""

fixed = """        def _strip(v):
            if isinstance(v, str): return v.strip()
            if isinstance(v, dict): return {k: _strip(val) for k, val in v.items()}
            if isinstance(v, list): return [_strip(val) for val in v]
            return v
        try:
            batch_signature = json.dumps(
                [{"toolName": a.get("toolName"), "args": _strip(a.get("args", {}))} for a in actions],
                sort_keys=True,
            )
        except Exception:
            batch_signature = \"\"\""""

content = content.replace(target, fixed)

# Write back
with open('phantom/agents/base_agent.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("A2 Fix Script executed.")
