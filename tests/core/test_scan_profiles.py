"""Tests for phantom.core.scan_profiles — ScanProfile + list/get helpers."""

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from phantom.core.scan_profiles import ScanProfile, get_profile, list_profiles


# ── list_profiles ──────────────────────────────────────────────────────────────

class TestListProfiles:
    def test_returns_five_profiles(self):
        profiles = list_profiles()
        assert len(profiles) == 5

    def test_all_have_name_key(self):
        for p in list_profiles():
            assert "name" in p, f"Profile dict missing 'name': {p}"

    def test_known_profile_names_present(self):
        names = {p["name"] for p in list_profiles()}
        for expected in ("quick", "standard", "deep", "stealth", "api_only"):
            assert expected in names, f"'{expected}' not in list_profiles() results"

    def test_returns_list_of_dicts(self):
        profiles = list_profiles()
        assert isinstance(profiles, list)
        assert all(isinstance(p, dict) for p in profiles)


# ── get_profile ────────────────────────────────────────────────────────────────

class TestGetProfile:
    @pytest.mark.parametrize("name", ["quick", "standard", "deep", "stealth", "api_only"])
    def test_returns_scan_profile(self, name):
        p = get_profile(name)
        assert isinstance(p, ScanProfile)

    def test_unknown_profile_raises_key_error(self):
        with pytest.raises(KeyError):
            get_profile("totally_unknown_profile")

    def test_quick_has_low_effort(self):
        p = get_profile("quick")
        assert p.reasoning_effort == "low"

    def test_deep_has_high_effort(self):
        p = get_profile("deep")
        assert p.reasoning_effort == "high"

    def test_quick_max_iterations_less_than_deep(self):
        assert get_profile("quick").max_iterations < get_profile("deep").max_iterations

    def test_stealth_no_browser(self):
        p = get_profile("stealth")
        assert p.enable_browser is False

    def test_standard_has_browser(self):
        p = get_profile("standard")
        assert p.enable_browser is True

    def test_all_profiles_have_required_attributes(self):
        required = [
            "name", "description", "scan_mode", "max_iterations",
            "sandbox_timeout_s", "reasoning_effort", "enable_browser",
        ]
        for name in ("quick", "standard", "deep", "stealth", "api_only"):
            p = get_profile(name)
            for attr in required:
                assert hasattr(p, attr), f"Profile '{name}' missing attribute '{attr}'"


# ── ScanProfile dataclass ─────────────────────────────────────────────────────

class TestScanProfileDataclass:
    def test_name_is_string(self):
        for name in ("quick", "standard", "deep"):
            assert isinstance(get_profile(name).name, str)

    def test_max_iterations_positive_int(self):
        for name in ("quick", "standard", "deep", "stealth", "api_only"):
            p = get_profile(name)
            assert isinstance(p.max_iterations, int)
            assert p.max_iterations > 0

    def test_scan_mode_valid(self):
        # Profiles define their own scan_mode strings; just assert it's a non-empty string.
        for name in ("quick", "standard", "deep", "stealth", "api_only"):
            p = get_profile(name)
            assert isinstance(p.scan_mode, str) and p.scan_mode, (
                f"Profile '{name}' has invalid scan_mode '{p.scan_mode}'"
            )

    def test_description_non_empty(self):
        for name in ("quick", "standard", "deep", "stealth", "api_only"):
            p = get_profile(name)
            assert p.description, f"Profile '{name}' has empty description"
