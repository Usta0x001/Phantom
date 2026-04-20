import sys

with open("phantom/agents/base_agent.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

in_fix_block = False
new_lines = []

for line in lines:
    if line.startswith("                    if not message.get(\"read\", False):"):
        # We need to shift this and everything after it by 4 spaces
        in_fix_block = True
    elif line.startswith("        except (AttributeError, KeyError, TypeError) as e:"):
        in_fix_block = False
    elif line.startswith("                    from phantom.telemetry.tracer import get_global_tracer"):
        pass

    if in_fix_block and line.startswith("                    "):
        new_lines.append("    " + line)
    else:
        new_lines.append(line)

with open("phantom/agents/base_agent.py", "w", encoding="utf-8") as f:
    f.writelines(new_lines)
print("Indentation fixed.")
