with open("phantom/agents/base_agent.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if 961 <= i <= 1021:  # Lines 962-1022 (0-indexed)
        if len(line.strip()) > 0:
            lines[i] = "    " + line

with open("phantom/agents/base_agent.py", "w", encoding="utf-8") as f:
    f.writelines(lines)
print("Indented lines 962-1022.")
