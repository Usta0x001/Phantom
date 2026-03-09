"""
Script to add @pytest.mark.skip to test classes that import deleted modules.
Run from the phantom project root.
"""
import ast
import re
import sys
from pathlib import Path

# Modules that were deleted in lean-phantom
DELETED_MODULES = {
    "phantom.core",
    "phantom.models",
    "phantom.agents.enhanced_state",
    "phantom.agents.protocol",
    "phantom.llm.provider_registry",
    "phantom.tools.output_sanitizer",
    "phantom.interface.cli_app",
    "phantom.interface.formatters",
}

FAILING_TEST_FILES = [
    "tests/test_all_modules.py",
    "tests/test_e2e_system.py",
    "tests/test_integration.py",
    "tests/test_p0_fixes.py",
    "tests/test_p1_fixes.py",
    "tests/test_scan_quality_fixes.py",
    "tests/test_security_fixes.py",
    "tests/test_v0910_coverage.py",
    "tests/test_v0912_wiring.py",
    "tests/test_v0913_fixes.py",
    "tests/test_v0915_security.py",
    "tests/test_v0916_hardening.py",
    "tests/test_v0917_fixes.py",
    "tests/test_v0918_features.py",
    "tests/test_v0920_audit_fixes.py",
    "tests/test_v093_security.py",
    "tests/test_v0940_dynamic_provider.py",
    "tests/test_v096_discovery.py",
    "tests/test_v098_features.py",
    "tests/test_v099_fixes.py",
]

SKIP_REASON = "lean-phantom: tests for removed features"


def imports_deleted_module(source_fragment: str) -> bool:
    """Check if source text imports from a deleted module."""
    for mod in DELETED_MODULES:
        if re.search(r'\bfrom\s+' + re.escape(mod), source_fragment):
            return True
        if re.search(r'\bimport\s+' + re.escape(mod), source_fragment):
            return True
    return False


def process_file(path: Path) -> tuple[int, int]:
    """Process a test file, adding skip markers to affected classes.
    
    Returns: (classes_skipped, classes_kept)
    """
    content = path.read_text(encoding="utf-8")
    
    # Parse to find class definitions
    try:
        tree = ast.parse(content)
    except SyntaxError:
        print(f"  SYNTAX ERROR parsing {path.name}")
        return 0, 0
    
    skipped = 0
    kept = 0
    
    # Check if pytest is imported
    has_pytest = "import pytest" in content
    
    # Find classes that need skipping
    classes_to_skip = set()
    
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        
        # Collect source of all methods in this class
        class_source_lines = content.splitlines()
        class_lines = []
        end_lineno = node.end_lineno if hasattr(node, 'end_lineno') else len(class_source_lines)
        class_text = "\n".join(class_source_lines[node.lineno - 1:end_lineno])
        
        if imports_deleted_module(class_text):
            classes_to_skip.add(node.lineno)
            skipped += 1
        else:
            kept += 1
    
    # Also check module-level test functions
    module_funcs_to_skip = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            func_lines = content.splitlines()
            end_lineno = node.end_lineno if hasattr(node, 'end_lineno') else len(func_lines)
            func_text = "\n".join(func_lines[node.lineno - 1:end_lineno])
            if imports_deleted_module(func_text):
                module_funcs_to_skip.add(node.lineno)
                skipped += 1
            else:
                kept += 1
    
    if not classes_to_skip and not module_funcs_to_skip:
        return 0, kept
    
    # Rebuild file with skip markers inserted before affected classes/functions
    lines = content.splitlines(keepends=True)
    
    # Insert markers from bottom to top to preserve line numbers
    insert_lines = sorted(list(classes_to_skip) + list(module_funcs_to_skip), reverse=True)
    
    for lineno in insert_lines:
        # Find the right indentation level (look at the line)
        target_line = lines[lineno - 1]
        indent = len(target_line) - len(target_line.lstrip())
        indent_str = " " * indent
        skip_marker = f'{indent_str}@pytest.mark.skip(reason="{SKIP_REASON}")\n'
        lines.insert(lineno - 1, skip_marker)
    
    new_content = "".join(lines)
    
    # Make sure pytest is imported
    if not has_pytest:
        new_content = "import pytest\n" + new_content
    
    path.write_text(new_content, encoding="utf-8")
    return skipped, kept


base = Path(r"C:\Users\Gadouri\Desktop\New folder (2)\phantom")

total_skipped = 0
total_kept = 0

for file_path in FAILING_TEST_FILES:
    path = base / file_path
    if not path.exists():
        print(f"SKIP (not found): {file_path}")
        continue
    
    s, k = process_file(path)
    total_skipped += s
    total_kept += k
    print(f"{file_path:<46} classes/funcs skipped={s} kept={k}")

print(f"\nTotal: {total_skipped} classes/funcs marked to skip, {total_kept} left untouched")
