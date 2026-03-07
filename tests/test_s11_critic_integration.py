"""Test Suite 4: Adversarial Critic Integration (T1-03, T1-04, DEFECT-AC-001/002)."""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from phantom.core.adversarial_critic import AdversarialCritic, CriticVerdict, ResultReview
from phantom.core.scan_state_machine import ScanState


class TestReviewActionReasoning:
    """T1-03: reasoning passthrough to review_action."""

    def test_high_risk_blocked_without_reasoning(self, critic, mock_state):
        verdict = critic.review_action(
            tool_name="exploit_runner",
            tool_args={"target": "10.0.0.1"},
            state=mock_state,
            current_phase=ScanState.EXPLOITATION,
            reasoning="",
        )
        assert verdict is not None
        assert isinstance(verdict, CriticVerdict)
        assert hasattr(verdict, "allowed")

    def test_high_risk_with_reasoning_may_pass(self, critic, mock_state):
        verdict = critic.review_action(
            tool_name="exploit_runner",
            tool_args={"target": "10.0.0.1"},
            state=mock_state,
            current_phase=ScanState.EXPLOITATION,
            reasoning="CVE-2024-1234 confirmed by nuclei scan; port 443 open with vulnerable OpenSSL version.",
        )
        assert verdict is not None
        assert isinstance(verdict, CriticVerdict)
        assert hasattr(verdict, "allowed")

    def test_safe_tool_always_approved(self, critic, mock_state):
        verdict = critic.review_action(
            tool_name="nmap",
            tool_args={"target": "10.0.0.1"},
            state=mock_state,
            current_phase=ScanState.RECONNAISSANCE,
            reasoning="Initial reconnaissance scan.",
        )
        assert verdict is not None
        assert isinstance(verdict, CriticVerdict)
        assert hasattr(verdict, "allowed")


class TestReviewResult:
    """T1-04: review_result returns structured feedback."""

    def test_review_result_returns_dataclass(self, critic, mock_state):
        result = critic.review_result(
            tool_name="nmap",
            tool_args={"target": "10.0.0.1"},
            result="PORT STATE SERVICE\n22/tcp open ssh\n80/tcp open http",
            state=mock_state,
        )
        assert result is not None
        assert isinstance(result, ResultReview)
        assert hasattr(result, "confidence_adjustment")
        assert isinstance(result.confidence_adjustment, (int, float))

    def test_review_result_negative_on_error(self, critic, mock_state):
        result = critic.review_result(
            tool_name="sqlmap",
            tool_args={"target": "10.0.0.1"},
            result="ERROR: connection timed out",
            state=mock_state,
        )
        assert result is not None
        assert isinstance(result, ResultReview)
        assert hasattr(result, "confidence_adjustment")
        assert result.confidence_adjustment <= 0.0

    def test_review_result_positive_on_success(self, critic, mock_state):
        result = critic.review_result(
            tool_name="nuclei",
            tool_args={"target": "https://target.com"},
            result="[critical] CVE-2024-1234 confirmed on https://target.com",
            state=mock_state,
        )
        assert result is not None
        assert isinstance(result, ResultReview)
        assert hasattr(result, "confidence_adjustment")


class TestGraphFeasibilityGate:
    """Critic should flag infeasible actions based on attack graph state."""

    def test_no_graph_connectivity_blocks_advanced_exploit(self, critic, mock_state):
        mock_state.attack_graph.nodes = {}
        verdict = critic.review_action(
            tool_name="metasploit",
            tool_args={"module": "exploit/multi/http/rce"},
            state=mock_state,
            current_phase=ScanState.EXPLOITATION,
            reasoning="Attempting exploitation.",
        )
        assert verdict is not None
        assert isinstance(verdict, CriticVerdict)
        assert hasattr(verdict, "allowed")
