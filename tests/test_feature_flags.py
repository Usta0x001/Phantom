"""Tests for phantom.core.feature_flags."""

import os

import pytest

from phantom.core.feature_flags import clear_cache, get_all_flags, is_enabled


class TestFeatureFlags:
    def setup_method(self):
        clear_cache()

    def teardown_method(self):
        clear_cache()
        # Clean up env vars we may have set
        for key in list(os.environ):
            if key.startswith("PHANTOM_FF_"):
                os.environ.pop(key, None)

    def test_defaults_are_true_for_core_flags(self):
        assert is_enabled("PHANTOM_FF_SCOPE_ENFORCEMENT") is True
        assert is_enabled("PHANTOM_FF_OUTPUT_SANITIZER") is True
        assert is_enabled("PHANTOM_FF_TOOL_FIREWALL") is True

    def test_mtls_defaults_to_false(self):
        assert is_enabled("PHANTOM_FF_MTLS") is False

    def test_env_override_to_false(self):
        os.environ["PHANTOM_FF_FINISH_GUARD"] = "false"
        clear_cache()
        assert is_enabled("PHANTOM_FF_FINISH_GUARD") is False

    def test_env_override_to_true(self):
        os.environ["PHANTOM_FF_MTLS"] = "true"
        clear_cache()
        assert is_enabled("PHANTOM_FF_MTLS") is True

    def test_cache_is_sticky(self):
        assert is_enabled("PHANTOM_FF_FINISH_GUARD") is True
        os.environ["PHANTOM_FF_FINISH_GUARD"] = "false"
        # Without cache clear, old value persists
        assert is_enabled("PHANTOM_FF_FINISH_GUARD") is True

    def test_cache_clear_reloads(self):
        assert is_enabled("PHANTOM_FF_FINISH_GUARD") is True
        os.environ["PHANTOM_FF_FINISH_GUARD"] = "false"
        clear_cache()
        assert is_enabled("PHANTOM_FF_FINISH_GUARD") is False

    def test_unknown_flag_defaults_to_false(self):
        assert is_enabled("PHANTOM_FF_NONEXISTENT") is False

    def test_get_all_flags(self):
        flags = get_all_flags()
        assert isinstance(flags, dict)
        assert "PHANTOM_FF_SCOPE_ENFORCEMENT" in flags
        assert "PHANTOM_FF_MTLS" in flags
