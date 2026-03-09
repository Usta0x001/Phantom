"""
Scan Quality Fix Verification Tests
Tests for schema loading, argument aliases, timeout fix, LOGIC-002
Run: python -m pytest tests/test_scan_quality_fixes.py -v
"""
import inspect
import pytest


class TestSchemaLoading:
    """Verify that _get_schema_path falls back to consolidated schemas."""

    def test_security_tools_have_schemas(self):
        """All security tools must have proper XML schemas (not 'Schema not found')."""
        from phantom.tools.registry import tools

        broken = []
        for t in tools:
            if t.get("module") == "security":
                schema = t.get("xml_schema", "")
                if "Schema not found" in schema or "Error loading" in schema:
                    broken.append(t["name"])

        assert not broken, f"Security tools still missing schemas: {broken}"

    def test_katana_crawl_has_schema_params(self):
        """katana_crawl must have parameter definitions in its schema."""
        from phantom.tools.registry import tools

        for t in tools:
            if t["name"] == "katana_crawl":
                assert "<parameter" in t.get("xml_schema", ""), "katana_crawl schema missing parameters"
                assert 'name="target"' in t["xml_schema"], "katana_crawl missing 'target' param"
                return
        pytest.fail("katana_crawl not found in registry")

    def test_httpx_probe_has_targets_param(self):
        """httpx_probe schema must define 'targets' parameter."""
        from phantom.tools.registry import tools

        for t in tools:
            if t["name"] == "httpx_probe":
                assert 'name="targets"' in t.get("xml_schema", ""), "httpx_probe missing 'targets' param"
                return
        pytest.fail("httpx_probe not found in registry")

    def test_all_tools_have_schemas(self):
        """No tool should have 'Schema not found' fallback."""
        from phantom.tools.registry import tools

        broken = []
        for t in tools:
            schema = t.get("xml_schema", "")
            if "Schema not found" in schema:
                broken.append(f"{t['name']} ({t.get('module', '?')})")

        assert not broken, f"Tools with missing schemas: {broken}"

    def test_consolidated_schema_fallback(self):
        """_get_schema_path should fall back to folder-level consolidated schema."""
        from phantom.tools.registry import _get_schema_path
        from phantom.tools.security.nmap_tool import nmap_scan

        path = _get_schema_path(nmap_scan)
        assert path is not None, "nmap_scan should find a schema path"
        assert path.exists(), f"Schema path {path} does not exist"
        assert "security_tools_schema.xml" in path.name


class TestArgumentAliases:
    """Verify argument alias resolution in convert_arguments."""

    def test_target_to_targets_alias(self):
        """'target' should be auto-corrected to 'targets' when function expects 'targets'."""
        from phantom.tools.argument_parser import convert_arguments

        def mock_func(targets: str, ports: str = "80"):
            pass

        result = convert_arguments(mock_func, {"target": "http://example.com"})
        assert "targets" in result, "Alias 'target' -> 'targets' not applied"
        assert result["targets"] == "http://example.com"

    def test_target_to_url_alias(self):
        """'target' should be auto-corrected to 'url' when function expects 'url'."""
        from phantom.tools.argument_parser import convert_arguments

        def mock_func(url: str, wordlist: str = "common.txt"):
            pass

        result = convert_arguments(mock_func, {"target": "http://example.com"})
        assert "url" in result, "Alias 'target' -> 'url' not applied"
        assert result["url"] == "http://example.com"

    def test_headers_to_extra_args_alias(self):
        """'headers' should be auto-corrected to 'extra_args' when function expects it."""
        from phantom.tools.argument_parser import convert_arguments

        def mock_func(url: str, extra_args: str | None = None):
            pass

        result = convert_arguments(mock_func, {"url": "http://x.com", "headers": "Auth: Bearer tok"})
        assert "extra_args" in result, "Alias 'headers' -> 'extra_args' not applied"

    def test_no_alias_when_param_exists(self):
        """If the original param name exists in function, don't alias it."""
        from phantom.tools.argument_parser import convert_arguments

        def mock_func(target: str, url: str = ""):
            pass

        result = convert_arguments(mock_func, {"target": "http://example.com"})
        assert "target" in result
        assert "url" not in result  # Should NOT alias since 'target' exists

    def test_unknown_params_still_dropped(self):
        """Parameters with no alias match should still be dropped."""
        from phantom.tools.argument_parser import convert_arguments

        def mock_func(url: str):
            pass

        result = convert_arguments(mock_func, {"url": "http://x.com", "nonexistent": "val"})
        assert "url" in result
        assert "nonexistent" not in result


class TestTimeoutConfig:
    """Verify sandbox timeout default is sufficient for long-running tools."""

    def test_sandbox_timeout_default_sufficient(self):
        """Default SANDBOX_EXECUTION_TIMEOUT should be >= 600s for nuclei scans."""
        # Test the code default, not the runtime value (which may come from saved config)
        # The code uses: Config.get("phantom_sandbox_execution_timeout") or "600"
        import phantom.tools.executor as exe_mod
        import importlib
        import os

        # Verify the source code default is 600, not 120
        source = importlib.util.find_spec("phantom.tools.executor")
        src_path = source.origin
        with open(src_path, "r") as f:
            content = f.read()
        # Find the default timeout string
        assert 'or "600"' in content, (
            "executor.py default timeout should be '600', not '120'. "
            "Long-running tools like nuclei_scan need at least 600s."
        )


@pytest.mark.skip(reason="lean-phantom: tests for removed features")
@pytest.mark.skip(reason="lean-phantom: tests for removed features")
class TestLogic002CompressionBoundary:
    """LOGIC-002: Compression limit check must happen BEFORE incrementing."""

    def test_compression_at_exact_limit(self):
        """Exactly max_compression_calls calls should succeed, next should fail."""
        from phantom.core.cost_controller import CostController, CostLimitExceeded

        cc = CostController(max_compression_calls=3)
        # Exactly 3 should work
        for _ in range(3):
            cc.record_usage(cost_usd=0.01, is_compression=True)
        # 4th should fail
        with pytest.raises(CostLimitExceeded) as exc_info:
            cc.record_usage(cost_usd=0.01, is_compression=True)
        assert "reached limit" in str(exc_info.value) or "Compression calls" in str(exc_info.value)

    def test_over_limit_cost_not_recorded(self):
        """The call that exceeds the limit must NOT have its cost recorded."""
        from phantom.core.cost_controller import CostController, CostLimitExceeded

        cc = CostController(max_compression_calls=2)
        cc.record_usage(cost_usd=0.10, is_compression=True)
        cc.record_usage(cost_usd=0.10, is_compression=True)
        snapshot_before = cc.get_snapshot()

        with pytest.raises(CostLimitExceeded):
            cc.record_usage(cost_usd=0.50, is_compression=True)

        snapshot_after = cc.get_snapshot()
        # The 0.50 cost should NOT have been added
        assert snapshot_after.compression_calls == snapshot_before.compression_calls
        assert snapshot_after.total_cost_usd == snapshot_before.total_cost_usd
