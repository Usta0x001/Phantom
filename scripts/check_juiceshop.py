"""Check what Juice Shop challenges were solved during the Phantom scan."""
import json
import requests
from collections import Counter

r = requests.get('http://localhost:3000/api/Challenges', timeout=10)
data = r.json()
challenges = data.get('data', [])
print(f"Total Juice Shop challenges: {len(challenges)}")

by_diff = Counter(c.get('difficulty') for c in challenges)
for d, count in sorted(by_diff.items()):
    print(f"  Difficulty {d}: {count}")

by_cat = Counter(c.get('category') for c in challenges)
print()
for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {count}")

solved = [c for c in challenges if c.get('solved')]
print(f"\nSolved during scan: {len(solved)}")
for c in solved:
    diff = c.get('difficulty', '?')
    cat = c.get('category', '?')
    name = c.get('name', '?')
    desc = c.get('description', '')[:80]
    print(f"  [Diff {diff}] {cat}: {name} - {desc}")

unsolved_critical = [c for c in challenges if not c.get('solved') and c.get('difficulty', 0) <= 3]
print(f"\nUnsolved easy/medium challenges ({len(unsolved_critical)}):")
for c in sorted(unsolved_critical, key=lambda x: x.get('difficulty', 0)):
    diff = c.get('difficulty', '?')
    cat = c.get('category', '?')
    name = c.get('name', '?')
    desc = c.get('description', '')[:80]
    print(f"  [Diff {diff}] {cat}: {name} - {desc}")
