from phantom.tools.registry import tools
names = sorted([t["name"] for t in tools])
for n in names:
    print(n)
print(f"\nTotal: {len(names)}")
