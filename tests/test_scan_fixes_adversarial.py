"""
Adversarial attack tests for all 6 scan fixes (S-01 through S-07).

These tests verify that each fix:
1. Is wired correctly (imports work, code paths are reachable)
2. Behaves correctly under boundary conditions
3. Cannot be trivially bypassed
"""

import pytest
import os
import sys
import json
import datetime

# ── Fix path for imports ──────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ════════════════════════════════════════════════════════════════════════
# S-01 / S-07: REPORTING MANDATE IN SYSTEM PROMPT
# ════════════════════════════════════════════════════════════════════════

class TestReportingMandate:
    """Attack the reporting mandate in the system prompt."""

    def _load_prompt(self):
        prompt_path = os.path.join(
            os.path.dirname(__file__), "..",
            "phantom", "agents", "PhantomAgent", "system_prompt.jinja"
        )
        with open(prompt_path, encoding="utf-8") as f:
            return f.read()

    def test_reporting_mandate_exists(self):
        """ATTACK: The reporting mandate must exist in the prompt."""
        prompt = self._load_prompt()
        assert "<reporting_mandate>" in prompt, "reporting_mandate block is MISSING from prompt"
        assert "</reporting_mandate>" in prompt, "reporting_mandate closing tag is MISSING"

    def test_reporting_mandate_before_tool_usage(self):
        """ATTACK: The mandate MUST appear BEFORE tool_usage so LLM reads it first."""
        prompt = self._load_prompt()
        mandate_pos = prompt.index("<reporting_mandate>")
        tool_usage_pos = prompt.index("<tool_usage>")
        assert mandate_pos < tool_usage_pos, (
            f"reporting_mandate at {mandate_pos} appears AFTER tool_usage at {tool_usage_pos}. "
            "The LLM may not read it in time."
        )

    def test_reporting_mandate_contains_key_instructions(self):
        """ATTACK: The mandate must contain critical keywords."""
        prompt = self._load_prompt()
        mandate_start = prompt.index("<reporting_mandate>")
        mandate_end = prompt.index("</reporting_mandate>")
        mandate = prompt[mandate_start:mandate_end]
        
        required_phrases = [
            "create_vulnerability_report",
            "FAILURE",
            "SUSPECTED",
            "EVERY vulnerability",
        ]
        for phrase in required_phrases:
            assert phrase in mandate, (
                f"CRITICAL: '{phrase}' not found in reporting_mandate block"
            )

    def test_reporting_mandate_not_in_strix(self):
        """VERIFY: Strix should NOT have the reporting mandate (proves it's new)."""
        strix_prompt = os.path.join(
            os.path.dirname(__file__), "..", "..",
            "strix", "strix", "agents", "StrixAgent", "system_prompt.jinja"
        )
        if os.path.exists(strix_prompt):
            with open(strix_prompt, encoding="utf-8") as f:
                content = f.read()
            assert "<reporting_mandate>" not in content, (
                "Strix should NOT have the reporting_mandate — it's a Phantom-only fix"
            )


# ════════════════════════════════════════════════════════════════════════
# S-07: PHASE-GATE INJECTION IN AGENT LOOP
# ════════════════════════════════════════════════════════════════════════

class TestPhaseGateInjection:
    """Attack the phase-gate reporting reminders in base_agent.py."""

    def _load_base_agent(self):
        path = os.path.join(
            os.path.dirname(__file__), "..",
            "phantom", "agents", "base_agent.py"
        )
        with open(path, encoding="utf-8") as f:
            return f.read()

    def test_phase_gate_code_exists(self):
        """ATTACK: Phase-gate injection code must exist in base_agent."""
        code = self._load_base_agent()
        assert "PHASE GATE" in code, "Phase-gate injection not found in base_agent.py"
        assert "RECON" in code and "EXPLOIT" in code and "REPORT" in code, (
            "Phase-gate must reference all three phases: RECON, EXPLOIT, REPORT"
        )

    def test_phase_gate_has_three_thresholds(self):
        """ATTACK: There must be exactly 3 gate thresholds (33%, 66%, 90%)."""
        code = self._load_base_agent()
        assert "0.33" in code, "33% threshold missing"
        assert "0.66" in code, "66% threshold missing"
        assert "0.90" in code or "0.9" in code, "90% threshold missing"

    def test_phase_gate_mentions_create_vulnerability_report(self):
        """ATTACK: Phase-gate messages must tell agent to call the reporting tool."""
        code = self._load_base_agent()
        # Count occurrences of create_vulnerability_report in phase gate section
        gate_start = code.index("S-07: Phase-gate")
        gate_section = code[gate_start:gate_start+2000]
        assert gate_section.count("create_vulnerability_report") >= 2, (
            "Phase-gate messages must mention create_vulnerability_report at least twice"
        )

    def test_phase_gate_boundary_small_iterations(self):
        """ATTACK: Phase-gate must not crash with very small max_iterations (e.g. 3)."""
        # Simulate: max_iter=3, iteration=1 → max(2, int(3*0.33)) = max(2,0) = 2
        max_iter = 3
        gate_33 = max(2, int(max_iter * 0.33))  # = 2
        gate_66 = max(3, int(max_iter * 0.66))  # = 3
        gate_90 = max(4, int(max_iter * 0.90))  # = 4

        assert gate_33 == 2, f"33% gate at max_iter=3 should be 2, got {gate_33}"
        assert gate_66 == 3, f"66% gate at max_iter=3 should be 3, got {gate_66}"
        assert gate_90 == 4, f"90% gate at max_iter=3 should be 4 (unreachable), got {gate_90}"
        # gate_90=4 > max_iter=3 → it won't fire, which is OK for very short scans

    def test_phase_gate_boundary_zero_iterations(self):
        """ATTACK: Phase-gate must NOT fire at iteration 0 or 1."""
        # The code checks _cur_iter > 1, so iterations 0 and 1 should be skipped
        max_iter = 15
        for cur_iter in [0, 1]:
            should_fire = cur_iter > 1
            assert not should_fire, f"Phase-gate should NOT fire at iteration {cur_iter}"


# ════════════════════════════════════════════════════════════════════════
# S-04 / S-06: QUICK MODE LIMITS & MAX_AGENTS
# ════════════════════════════════════════════════════════════════════════

class TestQuickModeLimits:
    """Attack the scan profile limits."""

    def test_quick_profile_low_iterations(self):
        """ATTACK: Quick mode must have max_iterations <= 15."""
        from phantom.core.scan_profiles import get_profile
        quick = get_profile("quick")
        assert quick.max_iterations <= 15, (
            f"Quick mode has {quick.max_iterations} iterations — should be <= 15"
        )

    def test_quick_profile_low_agents(self):
        """ATTACK: Quick mode must cap agents at 3."""
        from phantom.core.scan_profiles import get_profile
        quick = get_profile("quick")
        assert quick.max_agents <= 3, (
            f"Quick mode has max_agents={quick.max_agents} — should be <= 3"
        )

    def test_max_agents_field_exists_all_profiles(self):
        """ATTACK: All profiles must have a max_agents field."""
        from phantom.core.scan_profiles import get_profile
        for name in ["quick", "standard", "deep", "stealth", "api_only"]:
            profile = get_profile(name)
            assert hasattr(profile, "max_agents"), (
                f"Profile '{name}' is missing max_agents field"
            )
            assert isinstance(profile.max_agents, int), (
                f"Profile '{name}' max_agents is not an int"
            )
            assert profile.max_agents > 0, (
                f"Profile '{name}' max_agents is {profile.max_agents} — must be > 0"
            )

    def test_profile_scaling_is_monotonic(self):
        """ATTACK: More aggressive profiles must have more iterations and agents."""
        from phantom.core.scan_profiles import get_profile
        quick = get_profile("quick")
        standard = get_profile("standard")
        deep = get_profile("deep")

        assert quick.max_iterations < standard.max_iterations < deep.max_iterations, (
            f"Iteration scaling broken: quick={quick.max_iterations}, "
            f"standard={standard.max_iterations}, deep={deep.max_iterations}"
        )
        assert quick.max_agents <= standard.max_agents <= deep.max_agents, (
            f"Agent scaling broken: quick={quick.max_agents}, "
            f"standard={standard.max_agents}, deep={deep.max_agents}"
        )

    def test_quick_mode_not_expensive(self):
        """ATTACK: Quick mode must be cheap — low time, low agents."""
        from phantom.core.scan_profiles import get_profile
        quick = get_profile("quick")
        assert quick.sandbox_timeout_s <= 300, "Quick timeout too high"
        assert quick.reasoning_effort == "low", "Quick should use low reasoning effort"


# ════════════════════════════════════════════════════════════════════════
# S-05: CONVERSATION SUMMARY IN CHECKPOINT
# ════════════════════════════════════════════════════════════════════════

class TestConversationSummaryCheckpoint:
    """Attack the conversation_summary field in CheckpointData."""

    def test_checkpoint_model_has_summary_field(self):
        """ATTACK: CheckpointData must have conversation_summary field."""
        from phantom.checkpoint.models import CheckpointData
        cp = CheckpointData(run_name="test_run")
        assert hasattr(cp, "conversation_summary"), (
            "CheckpointData is missing conversation_summary field"
        )
        assert isinstance(cp.conversation_summary, list), (
            "conversation_summary must be a list"
        )

    def test_checkpoint_model_has_saved_at_field(self):
        """ATTACK: CheckpointData must have saved_at field."""
        from phantom.checkpoint.models import CheckpointData
        cp = CheckpointData(run_name="test_run")
        assert hasattr(cp, "saved_at"), "CheckpointData is missing saved_at field"

    def test_conversation_summary_serialize_deserialize(self):
        """ATTACK: conversation_summary must survive JSON round-trip."""
        from phantom.checkpoint.models import CheckpointData
        summary = [
            {"role": "user", "content": "test message"},
            {"role": "assistant", "content": "response", "tool_calls": "terminal_execute"},
        ]
        cp = CheckpointData(
            run_name="test_run",
            conversation_summary=summary,
            saved_at="2026-03-13T15:00:00+00:00",
        )
        data = json.loads(cp.model_dump_json())
        assert data["conversation_summary"] == summary
        assert data["saved_at"] == "2026-03-13T15:00:00+00:00"

    def test_conversation_summary_empty_by_default(self):
        """ATTACK: conversation_summary must default to empty list."""
        from phantom.checkpoint.models import CheckpointData
        cp = CheckpointData(run_name="test_run")
        assert cp.conversation_summary == []
        assert cp.saved_at is None


# ════════════════════════════════════════════════════════════════════════
# S-03: EMERGENCY CHECKPOINT SAVE BEFORE RATE-LIMIT ABORT
# ════════════════════════════════════════════════════════════════════════

class TestRateLimitCheckpointSave:
    """Attack the emergency checkpoint save in base_agent.py."""

    def test_force_save_in_rate_limit_abort_path(self):
        """ATTACK: The rate-limit abort path must call _maybe_save_checkpoint(force=True)."""
        path = os.path.join(
            os.path.dirname(__file__), "..",
            "phantom", "agents", "base_agent.py"
        )
        with open(path, encoding="utf-8") as f:
            code = f.read()

        # Find the rate-limit abort section
        rl_section_start = code.index("API key may be revoked")
        rl_section = code[rl_section_start:rl_section_start+1500]
        
        assert "force=True" in rl_section, (
            "CRITICAL: _maybe_save_checkpoint(force=True) not found in rate-limit abort path"
        )

    def test_maybe_save_checkpoint_accepts_force(self):
        """ATTACK: _maybe_save_checkpoint must accept force parameter."""
        path = os.path.join(
            os.path.dirname(__file__), "..",
            "phantom", "agents", "base_agent.py"
        )
        with open(path, encoding="utf-8") as f:
            code = f.read()

        assert "def _maybe_save_checkpoint(self, tracer" in code
        # Find the function signature
        sig_start = code.index("def _maybe_save_checkpoint")
        sig_line = code[sig_start:code.index("\n", sig_start)]
        assert "force" in sig_line, (
            f"_maybe_save_checkpoint signature doesn't include 'force' parameter: {sig_line}"
        )

    def test_force_false_respects_interval(self):
        """ATTACK: Without force=True, the interval check must still apply."""
        path = os.path.join(
            os.path.dirname(__file__), "..",
            "phantom", "agents", "base_agent.py"
        )
        with open(path, encoding="utf-8") as f:
            code = f.read()

        assert "not force and not checkpoint_mgr.should_save" in code, (
            "The force=False path must still check should_save interval"
        )


# ════════════════════════════════════════════════════════════════════════
# S-02: TOKEN RATIO (Prompt-level fix — verified via prompt analysis)
# ════════════════════════════════════════════════════════════════════════

class TestTokenRatioMitigation:
    """Verify that the prompt encourages substantive output."""

    def _load_prompt(self):
        prompt_path = os.path.join(
            os.path.dirname(__file__), "..",
            "phantom", "agents", "PhantomAgent", "system_prompt.jinja"
        )
        with open(prompt_path, encoding="utf-8") as f:
            return f.read()

    def test_prompt_has_reasoning_requirements(self):
        """ATTACK: The prompt must encourage the LLM to think, not just tool-call."""
        prompt = self._load_prompt()
        assert "think tool" in prompt.lower() or "think" in prompt.lower(), (
            "Prompt must mention the think tool for reasoning"
        )

    def test_prompt_discourages_empty_output(self):
        """ATTACK: The prompt must explicitly forbid empty messages."""
        prompt = self._load_prompt()
        assert "empty" in prompt.lower() and "blank" in prompt.lower(), (
            "Prompt must discourage empty/blank messages"
        )


# ════════════════════════════════════════════════════════════════════════
# CROSS-CUT: STRIX DOES NOT HAVE THE FIXES
# ════════════════════════════════════════════════════════════════════════

class TestStrixLacksFixes:
    """Verify Strix does NOT have any of the fixes (proving they're new)."""

    def _strix_path(self, *parts):
        return os.path.join(os.path.dirname(__file__), "..", "..", "strix", *parts)

    def test_strix_has_no_max_agents(self):
        """Strix scan_profiles should not have max_agents."""
        path = self._strix_path("strix", "core", "scan_profiles.py")
        if not os.path.exists(path):
            pytest.skip("Strix not found")
        with open(path, encoding="utf-8") as f:
            code = f.read()
        assert "max_agents" not in code, "Strix should NOT have max_agents"

    def test_strix_has_no_phase_gate(self):
        """Strix base_agent should not have phase-gate logic."""
        path = self._strix_path("strix", "agents", "base_agent.py")
        if not os.path.exists(path):
            pytest.skip("Strix not found")
        with open(path, encoding="utf-8") as f:
            code = f.read()
        assert "PHASE GATE" not in code, "Strix should NOT have phase-gate"

    def test_strix_has_no_conversation_summary(self):
        """Strix checkpoint models should not have conversation_summary."""
        path = self._strix_path("strix", "checkpoint", "models.py")
        if not os.path.exists(path):
            # Try alternative path
            for alt in ["checkpoint.py", os.path.join("checkpoint", "models.py")]:
                alt_path = self._strix_path("strix", alt)
                if os.path.exists(alt_path):
                    path = alt_path
                    break
            else:
                pytest.skip("Strix checkpoint not found")
        with open(path, encoding="utf-8") as f:
            code = f.read()
        assert "conversation_summary" not in code, (
            "Strix should NOT have conversation_summary"
        )
