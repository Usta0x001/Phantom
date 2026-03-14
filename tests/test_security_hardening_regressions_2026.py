from __future__ import annotations

import inspect
import importlib.util

import pytest


_HAS_IPYTHON = importlib.util.find_spec("IPython") is not None


def test_terminal_manager_defaults_quarantine_to_true() -> None:
    from phantom.tools.terminal import terminal_manager

    src = inspect.getsource(terminal_manager.TerminalManager.__init__)
    assert 'os.getenv("PHANTOM_TERMINAL_QUARANTINE", "true")' in src


def test_terminal_session_constructor_default_is_true() -> None:
    from phantom.tools.terminal.terminal_session import TerminalSession

    sig = inspect.signature(TerminalSession.__init__)
    assert sig.parameters["quarantine"].default is True


@pytest.mark.skipif(not _HAS_IPYTHON, reason="IPython not installed in this environment")
def test_python_instance_blocks_unsafe_import() -> None:
    from phantom.tools.python.python_instance import PythonInstance

    instance = PythonInstance.__new__(PythonInstance)
    err = PythonInstance._validate_code_safety(instance, "import os\nprint('x')")

    assert err is not None
    assert "Blocked unsafe import" in err


@pytest.mark.skipif(not _HAS_IPYTHON, reason="IPython not installed in this environment")
def test_python_instance_blocks_unsafe_builtin_call() -> None:
    from phantom.tools.python.python_instance import PythonInstance

    instance = PythonInstance.__new__(PythonInstance)
    err = PythonInstance._validate_code_safety(instance, "eval('2+2')")

    assert err is not None
    assert "Blocked unsafe call" in err


@pytest.mark.skipif(not _HAS_IPYTHON, reason="IPython not installed in this environment")
def test_python_instance_allows_safe_code() -> None:
    from phantom.tools.python.python_instance import PythonInstance

    instance = PythonInstance.__new__(PythonInstance)
    err = PythonInstance._validate_code_safety(instance, "x = 2 + 2\nprint(x)")

    assert err is None
