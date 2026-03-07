"""Test Suite 8: Exception Consolidation (T2-04, DEFECT-SM-001)."""
import pytest
from unittest.mock import MagicMock
from phantom.core.exceptions import InvalidTransitionError, StateError
from phantom.core.scan_state_machine import ScanStateMachine, ScanState


class TestExceptionHierarchy:
    """InvalidTransitionError uses centralized exception from exceptions.py."""

    def test_subclasses_state_error(self):
        assert issubclass(InvalidTransitionError, StateError)

    def test_has_required_attributes(self):
        err = InvalidTransitionError(
            "Cannot transition from RECON to EXPLOITATION",
            from_state="RECON",
            to_state="EXPLOITATION",
        )
        assert hasattr(err, "from_state")
        assert hasattr(err, "to_state")
        assert err.from_state == "RECON"
        assert err.to_state == "EXPLOITATION"

    def test_str_representation(self):
        err = InvalidTransitionError(
            "Invalid transition from RECON to REPORTING",
            from_state="RECON",
            to_state="REPORTING",
        )
        s = str(err)
        assert "RECON" in s
        assert "REPORTING" in s


class TestStateMachineUsesConsolidatedException:
    """scan_state_machine.py should raise from phantom.core.exceptions."""

    def test_invalid_transition_raises_correct_type(self, mock_state):
        sm = ScanStateMachine()
        with pytest.raises(InvalidTransitionError) as exc_info:
            sm.transition(ScanState.REPORTING, state=mock_state)  # skip phases
        err = exc_info.value
        assert isinstance(err, StateError)
        assert isinstance(err, InvalidTransitionError)

    def test_no_local_exception_class(self):
        import phantom.core.scan_state_machine as ssm_module
        members = [
            name for name in dir(ssm_module)
            if name == "InvalidTransitionError"
        ]
        for name in members:
            cls = getattr(ssm_module, name)
            assert cls is InvalidTransitionError, (
                f"{name} in scan_state_machine is a local copy, not the centralized one"
            )
