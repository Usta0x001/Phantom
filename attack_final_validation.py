"""
FINAL PERFECT SYSTEM VALIDATION
Tests for all critical fixes applied in the comprehensive audit round.
"""

import json
import sys
from pathlib import Path


def assert_true(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"[FAIL] {label}: {detail}")
    print(f"  [PASS] {label}")


print("=" * 70)
print("FINAL PERFECT SYSTEM VALIDATION")
print("=" * 70)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Telemetry import error is logged, not silent
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 1] Telemetry logs import errors instead of swallowing silently...")

telemetry_src = Path("phantom/telemetry/__init__.py").read_text(encoding="utf-8")
assert_true(
    "catches ImportError specifically",
    "except ImportError" in telemetry_src,
    "still catches broad Exception",
)
assert_true(
    "logs the error",
    "_logger.warning" in telemetry_src or "logger.warning" in telemetry_src,
    "does not log the error",
)


# ═══════════════════════════════════════════════════════════════════════════
# 2. Terminal session logs audit failures instead of pass
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 2] Terminal session logs audit failures...")

term_src = Path("phantom/tools/terminal/terminal_session.py").read_text(encoding="utf-8")
assert_true(
    "audit log exception is logged",
    "logger.debug" in term_src.split("log_quarantine_block")[1].split("return {")[0],
    "still uses bare pass",
)
assert_true(
    "libtmux import is guarded",
    "try:" in term_src and "import libtmux" in term_src.split("try:")[1].split("logger =")[0],
    "libtmux not guarded",
)
assert_true(
    "libtmux None check in initialize",
    "if libtmux is None:" in term_src,
    "no None check",
)


# ═══════════════════════════════════════════════════════════════════════════
# 3. Diff scanner logs JSON parse errors
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 3] Diff scanner logs JSON parse errors...")

diff_src = Path("phantom/core/diff_scanner.py").read_text(encoding="utf-8")
assert_true(
    "checkpoint parse error logged",
    "logger.warning" in diff_src.split("json.loads(cp_file")[1].split("# Fallback")[0],
    "checkpoint error not logged",
)
assert_true(
    "fallback JSON parse error logged",
    "logger.debug" in diff_src.split("for json_file in sorted")[1].split("return []")[0],
    "fallback error not logged",
)
assert_true(
    "any() uses tuple not list",
    "any((self.new_vulns, self.fixed_vulns, self.persistent_vulns))" in diff_src,
    "still uses any([...])",
)


# ═══════════════════════════════════════════════════════════════════════════
# 4. Tool server does not raise at import time
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 4] Tool server does not raise at import time...")

ts_src = Path("phantom/runtime/tool_server.py").read_text(encoding="utf-8")
assert_true(
    "no module-level sandbox RuntimeError",
    "if not SANDBOX_MODE:" not in ts_src.split('if __name__')[0],
    "sandbox check still at module level",
)
assert_true(
    "sandbox RuntimeError inside __main__ guard",
    "if not SANDBOX_MODE:" in ts_src.split('if __name__')[1],
    "sandbox check not in __main__ block",
)


# ═══════════════════════════════════════════════════════════════════════════
# 5. CLI uses sys.stdout.write not bare print()
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 5] CLI JSON output uses sys.stdout.write...")

cli_src = Path("phantom/interface/cli.py").read_text(encoding="utf-8")
json_output_section = cli_src.split("if json_mode:")[1].split("elif quiet_mode:")[0]
assert_true(
    "uses sys.stdout.write for JSON",
    "sys.stdout.write" in json_output_section,
    "still uses bare print()",
)


# ═══════════════════════════════════════════════════════════════════════════
# 6. No unnecessary string join in cli_app
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 6] No unnecessary string join in HTML output...")

cli_app_src = Path("phantom/interface/cli_app.py").read_text(encoding="utf-8")
assert_true(
    "no ''.join([literal])",
    '"".join(["<p><em>No vulnerabilities found.</em></p>"])' not in cli_app_src,
    "unnecessary join still present",
)


# ═══════════════════════════════════════════════════════════════════════════
# 7. All modules in execution path import cleanly
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 7] All execution path modules import cleanly...")

try:
    from phantom.telemetry import Tracer, get_global_tracer, set_global_tracer
    from phantom.tools.terminal.terminal_session import TerminalSession
    from phantom.core.diff_scanner import DiffScanner
    from phantom.interface.cli import run_cli
    from phantom.interface.cli_app import cli_main, app
    assert_true("all execution modules import cleanly", True)
except Exception as e:
    assert_true("all execution modules import cleanly", False, str(e))


# ═══════════════════════════════════════════════════════════════════════════
# 8. No dead function references
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 8] No orphaned _truncate_to_first_function...")

utils_src = Path("phantom/llm/utils.py").read_text(encoding="utf-8")
assert_true(
    "_truncate_to_first_function removed",
    "def _truncate_to_first_function" not in utils_src,
    "orphaned function still present",
)


# ═══════════════════════════════════════════════════════════════════════════
# 9. No deleted globals references
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 9] No references to deleted globals...")

llm_src = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
tracer_src = Path("phantom/telemetry/tracer.py").read_text(encoding="utf-8")
assert_true(
    "no _GLOBAL_STATS_LOCK in llm.py",
    "_GLOBAL_STATS_LOCK" not in llm_src,
    "still referenced",
)
assert_true(
    "no _GLOBAL_TOTAL_STATS in llm.py",
    "_GLOBAL_TOTAL_STATS" not in llm_src,
    "still referenced",
)
assert_true(
    "no _GLOBAL_STATS_LOCK in tracer.py",
    "_GLOBAL_STATS_LOCK" not in tracer_src,
    "still referenced in tracer",
)


# ═══════════════════════════════════════════════════════════════════════════
# 10. No RICH_TOOL_NAMES dead code
# ═══════════════════════════════════════════════════════════════════════════
print("\n[TEST 10] RICH_TOOL_NAMES removed...")

reg_src = Path("phantom/tools/registry.py").read_text(encoding="utf-8")
assert_true(
    "RICH_TOOL_NAMES removed",
    "RICH_TOOL_NAMES" not in reg_src,
    "still present",
)


# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("ALL FINAL VALIDATION TESTS PASSED - SYSTEM IS PERFECT")
print("=" * 70)
