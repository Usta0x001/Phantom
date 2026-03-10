#!/usr/bin/env python3
"""Strip UTF-8 BOM from tracked files.

Run before committing when editing with tools that add BOM (e.g. PowerShell
Set-Content -Encoding UTF8). Targets .py, .md, .toml, .yaml, .yml, .jinja,
.jinja2, .txt, .json, .cfg, .ini and .rst files.

Usage:
    python scripts/strip_bom.py          # dry-run (print affected files)
    python scripts/strip_bom.py --fix    # strip BOM in-place
"""

import sys
from pathlib import Path

BOM = b"\xef\xbb\xbf"
EXTENSIONS = {".py", ".md", ".toml", ".yaml", ".yml", ".jinja", ".jinja2",
              ".txt", ".json", ".cfg", ".ini", ".rst"}

root = Path(__file__).parent.parent
fix = "--fix" in sys.argv
found = []

for path in sorted(root.rglob("*")):
    if path.suffix not in EXTENSIONS:
        continue
    if any(p in path.parts for p in (".git", "__pycache__", "node_modules", "dist", ".venv")):
        continue
    try:
        raw = path.read_bytes()
    except OSError:
        continue
    if raw.startswith(BOM):
        found.append(path)
        if fix:
            path.write_bytes(raw[3:])
            print(f"  stripped: {path.relative_to(root)}")
        else:
            print(f"  BOM found: {path.relative_to(root)}")

if not found:
    print("No BOM found — all clean.")
elif not fix:
    print(f"\n{len(found)} file(s) have BOM. Run with --fix to strip them.")
    sys.exit(1)
else:
    print(f"\nStripped BOM from {len(found)} file(s).")
