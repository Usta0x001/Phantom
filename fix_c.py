import re

with open('phantom/tools/dynamic_tools.py', 'r', encoding='utf-8') as f:
    content = f.read()

# C2 Fix
target_c2 = '    "main_agent": ["web_testing", "terminal", "browser", "reporting", "agent_management", "memory"],'
fixed_c2 = '    "main_agent": ["web_testing", "terminal", "browser", "reporting", "agent_management", "memory", "files", "notes", "todo"],'
content = content.replace(target_c2, fixed_c2)

# C1 Fix
target_c1 = '        "spawn": ["agent_management"],\n    }'
fixed_c1 = '        "spawn": ["agent_management"],\n        "vuln": ["web_testing", "browser"],\n        "exploit": ["web_testing", "browser"],\n        "cve": ["web_testing", "terminal"],\n        "test": ["web_testing", "browser"],\n        "pollution": ["web_testing", "browser"],\n        "web": ["web_testing", "browser"],\n    }'
content = content.replace(target_c1, fixed_c1)

with open('phantom/tools/dynamic_tools.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("C1/C2 Fix Script executed.")
