"""
ADVERSARIAL ATTACK SUITE — Round 2 (New Fixes)
Attempts to break every newly-applied fix with edge cases.
"""

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


def attack_1_coverage_empty_failure_only():
    """ATTACK 1: Empty _failure_only dict should not crash get_blocked_surfaces."""
    print("\n[ATTACK 01] Empty failure-only dict...")
    from phantom.agents.coverage_tracker import CoverageTracker

    ct = CoverageTracker()
    blocked = ct.get_blocked_surfaces()
    assert blocked == [], f"Expected empty list, got {blocked}"
    assert ct.has_been_tested("/unknown", "endpoint") is False
    print("  PASS")


def attack_2_coverage_duplicate_failures():
    """ATTACK 2: Duplicate failure reasons should not be duplicated."""
    print("\n[ATTACK 02] Duplicate failure dedup...")
    from phantom.agents.coverage_tracker import CoverageTracker

    ct = CoverageTracker()
    ct.record_failure("/api", "endpoint", "WAF blocked", "sqli")
    ct.record_failure("/api", "endpoint", "WAF blocked", "sqli")
    blocked = ct.get_blocked_surfaces()
    assert len(blocked) == 1
    assert len(blocked[0]["failure_reasons"]) == 1, "Duplicate reasons should be deduped"
    print("  PASS")


def attack_3_attack_graph_extreme_values():
    """ATTACK 3: Attack graph helpers with extreme inputs."""
    print("\n[ATTACK 03] Attack graph extremes...")
    from phantom.core.attack_graph import AttackGraph

    assert AttackGraph._normalize_weight(-999) == 0.05
    assert AttackGraph._normalize_weight(999) == 1.5
    assert AttackGraph._normalize_weight("bad") == 1.0
    assert AttackGraph._coerce_probability("bad") is None
    assert AttackGraph._coerce_positive(-5) is None
    assert AttackGraph._coerce_positive(0) is None
    print("  PASS")


def attack_4_tool_name_underscore_only():
    """ATTACK 4: Tool names with only underscores should still validate."""
    print("\n[ATTACK 04] Underscore-only tool name...")
    from phantom.llm.utils import parse_tool_invocations

    content = "<function=__init__></function>"
    tools = parse_tool_invocations(content)
    assert tools is not None and len(tools) == 1
    assert tools[0]["toolName"] == "__init__"
    print("  PASS")


def attack_5_xml_escape_unicode():
    """ATTACK 5: XML escaping with Unicode characters."""
    print("\n[ATTACK 05] Unicode XML escaping...")
    from phantom.llm.utils import format_tool_call

    xml = format_tool_call("test", {"payload": "<script>alert('日本語')</script>"})
    assert "<script>" not in xml
    assert "&lt;script&gt;" in xml
    print("  PASS")


def attack_6_diff_scanner_no_id_no_param():
    """ATTACK 6: Diff scanner with no id and no parameter."""
    print("\n[ATTACK 06] Diff scanner minimal vuln...")
    from phantom.core.diff_scanner import _vuln_key

    v = {"name": "XSS", "endpoint": "/search"}
    k = _vuln_key(v)
    assert k == "xss|/search|", f"Unexpected key: {k}"
    print("  PASS")


def attack_7_agent_id_uniqueness():
    """ATTACK 7: Agent IDs should be unique across many generations."""
    print("\n[ATTACK 07] Agent ID uniqueness...")
    from phantom.agents.state import _generate_agent_id

    ids = {_generate_agent_id() for _ in range(1000)}
    assert len(ids) == 1000, f"Collision detected! Only {len(ids)} unique IDs"
    print("  PASS")


def attack_8_stop_signal_double_set():
    """ATTACK 8: Stop signal set twice should still work after first clear."""
    print("\n[ATTACK 08] Double stop signal...")
    source = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
    # Verify there's no code that does `_force_stop = False` BEFORE the check
    # which would lose the second signal
    bad_pattern = "self._force_stop = False\n                if self._force_stop:"
    assert bad_pattern not in source, "Old buggy pattern still present"
    print("  PASS")


def attack_9_browser_truncation_not_excessive():
    """ATTACK 9: Browser truncation should not exceed a reasonable bound."""
    print("\n[ATTACK 09] Browser truncation bound...")
    from phantom.config import Config

    limit = int(Config.get("phantom_browser_truncation_burst_limit") or "0")
    assert 32000 < limit <= 128000, f"Limit {limit} is out of reasonable range"
    print("  PASS")


def attack_10_tracer_scan_stats_empty_config():
    """ATTACK 10: Tracer scan_stats with empty scan_config."""
    print("\n[ATTACK 10] Tracer empty scan_config...")
    from phantom.telemetry.tracer import Tracer

    t = Tracer(run_name="test")
    # scan_config is None by default; target extraction should handle it
    assert t.scan_config is None
    print("  PASS")


if __name__ == "__main__":
    print("=" * 65)
    print("PHANTOM FIXES — ADVERSARIAL ATTACK SUITE (Round 2)")
    print("=" * 65)

    tests = [
        attack_1_coverage_empty_failure_only,
        attack_2_coverage_duplicate_failures,
        attack_3_attack_graph_extreme_values,
        attack_4_tool_name_underscore_only,
        attack_5_xml_escape_unicode,
        attack_6_diff_scanner_no_id_no_param,
        attack_7_agent_id_uniqueness,
        attack_8_stop_signal_double_set,
        attack_9_browser_truncation_not_excessive,
        attack_10_tracer_scan_stats_empty_config,
    ]

    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {e}")

    print("\n" + "=" * 65)
    print(f"ATTACK RESULTS: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 65)
    sys.exit(0 if failed == 0 else 1)
