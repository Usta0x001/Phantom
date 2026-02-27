"""Check all Python files for syntax errors."""
import ast
import pathlib
import sys

errors = []
files = list(pathlib.Path("phantom").rglob("*.py"))
for f in files:
    try:
        source = f.read_text(encoding="utf-8")
        ast.parse(source, filename=str(f))
    except SyntaxError as e:
        errors.append(f"{f}: line {e.lineno}: {e.msg}")

if errors:
    print(f"FOUND {len(errors)} SYNTAX ERRORS:")
    for err in errors:
        print(f"  {err}")
    sys.exit(1)
else:
    print(f"All {len(files)} Python files parse OK - no syntax errors")
