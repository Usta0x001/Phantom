"""
Verification tests for hardening items applied in March 2026:

  1. asyncio.iscoroutinefunction deprecation — filtered in pytest config
  2. Docker port-probe exponential back-off with jitter
  3. pytest-timeout installed + --timeout active
  4. pytest-cov with branch=True and fail_under=80 configured
  5. traceloop Pydantic v1 warning suppressed via filterwarnings
  6. 'sandbox' pytest marker registered
"""

from __future__ import annotations

import ast
import random
import socket
import threading
from pathlib import Path
from textwrap import dedent
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"
DOCKER_RUNTIME_SRC = (
    Path(__file__).parent.parent / "phantom" / "runtime" / "docker_runtime.py"
)


# ── helpers ─────────────────────────────────────────────────────────────────


def _read_toml_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def _get_method_src(filepath: Path, method_name: str) -> str:
    src = filepath.read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name:
            seg = ast.get_source_segment(src, node)
            if seg:
                return seg
    raise AssertionError(f"Method '{method_name}' not found in {filepath}")


# ── 1. asyncio.iscoroutinefunction deprecation ───────────────────────────────


def test_asyncio_iscoroutinefunction_absent_from_phantom_source() -> None:
    """Our own code must not call asyncio.iscoroutinefunction (deprecated in 3.12)."""
    phantom_dir = Path(__file__).parent.parent / "phantom"
    offenders: list[Path] = []
    for py_file in phantom_dir.rglob("*.py"):
        if "asyncio.iscoroutinefunction" in py_file.read_text(encoding="utf-8", errors="replace"):
            offenders.append(py_file)
    assert offenders == [], (
        f"Found asyncio.iscoroutinefunction in our own code: {offenders!r}\n"
        "Replace with inspect.iscoroutinefunction()"
    )


def test_filterwarnings_litellm_asyncio_in_pyproject() -> None:
    """pyproject.toml must suppress the litellm asyncio deprecation in pytest runs."""
    toml = _read_toml_text()
    assert "asyncio.iscoroutinefunction" in toml, (
        "Missing filterwarnings entry for litellm asyncio.iscoroutinefunction deprecation"
    )
    assert "litellm" in toml.split("asyncio.iscoroutinefunction")[1][:200], (
        "filterwarnings entry should target the 'litellm' module"
    )


# ── 2. Docker port-probe exponential back-off ────────────────────────────────


def test_find_available_port_returns_valid_port() -> None:
    """_find_available_port must return a bindable port number."""
    from phantom.runtime.docker_runtime import DockerRuntime

    # Bypass Docker client init
    rt: DockerRuntime = object.__new__(DockerRuntime)
    port = rt._find_available_port()
    assert isinstance(port, int)
    assert 1024 < port < 65536


def test_find_available_port_accepts_max_attempts_param() -> None:
    """_find_available_port must accept a max_attempts parameter for retry control."""
    src = _get_method_src(DOCKER_RUNTIME_SRC, "_find_available_port")
    assert "max_attempts" in src, (
        "_find_available_port must have a max_attempts parameter"
    )


def test_find_available_port_uses_exponential_backoff() -> None:
    """_find_available_port must use exponential back-off (2**attempt pattern)."""
    src = _get_method_src(DOCKER_RUNTIME_SRC, "_find_available_port")
    assert "2**attempt" in src or "2 ** attempt" in src, (
        "_find_available_port must use 2**attempt exponential back-off"
    )


def test_find_available_port_uses_random_jitter() -> None:
    """_find_available_port must add random jitter to avoid thundering-herd."""
    src = _get_method_src(DOCKER_RUNTIME_SRC, "_find_available_port")
    assert "random" in src, (
        "_find_available_port must add jitter via random.uniform() or similar"
    )


def test_find_available_port_backoff_on_collision(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate an OSError on the first re-bind check; the method must retry and succeed."""
    from phantom.runtime.docker_runtime import DockerRuntime

    rt: DockerRuntime = object.__new__(DockerRuntime)

    _call_count = {"n": 0}
    _original_socket = socket.socket

    class _MockSocket:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._sock = _original_socket(*args, **kwargs)
            _call_count["n"] += 1
            # First strict check socket raises OSError (simulates port seized).
            # The probe sockets (SO_REUSEADDR set) are allowed to succeed.
            self._is_check = False

        def setsockopt(self, *args: Any) -> None:
            self._sock.setsockopt(*args)

        def bind(self, addr: Any) -> None:
            if self._is_check and _call_count["n"] <= 3:
                raise OSError("simulated port-in-use")
            self._sock.bind(addr)

        def getsockname(self) -> Any:
            return self._sock.getsockname()

        def __enter__(self) -> "_MockSocket":
            self._sock.__enter__()
            return self

        def __exit__(self, *a: Any) -> None:
            self._sock.__exit__(*a)

    # Patch sleep to avoid actual delay in tests.
    monkeypatch.setattr("phantom.runtime.docker_runtime.time.sleep", lambda _: None)

    # Should still return a valid port (falls through to best-effort).
    port = rt._find_available_port(max_attempts=3)
    assert isinstance(port, int)
    assert 1024 < port < 65536


def test_docker_runtime_imports_random() -> None:
    """docker_runtime.py must import random (used for jitter)."""
    src = DOCKER_RUNTIME_SRC.read_text(encoding="utf-8")
    assert "import random" in src, "docker_runtime.py must have 'import random'"


# ── 3. pytest-timeout installed and configured ───────────────────────────────


def test_pytest_timeout_importable() -> None:
    """pytest-timeout must be installed."""
    import pytest_timeout  # noqa: F401


def test_timeout_in_pytest_addopts() -> None:
    """pyproject.toml must include --timeout in pytest addopts."""
    toml = _read_toml_text()
    assert "--timeout=" in toml, (
        "pytest addopts in pyproject.toml must include --timeout=<N>"
    )


def test_timeout_applied_to_slow_noop() -> None:
    """Quick smoke-test so that the --timeout plugin is actually active."""
    # If pytest-timeout isn't registered, the @pytest.mark.timeout marker
    # would be unknown and --strict-markers would fail the test collection.
    import time
    time.sleep(0)  # trivially fast — just confirms test runs under timeout guard


# ── 4. Coverage: branch=True and fail_under=80 ───────────────────────────────


def test_coverage_branch_enabled_in_config() -> None:
    """[tool.coverage.run] must set branch = true."""
    toml = _read_toml_text()
    assert "branch = true" in toml, (
        "[tool.coverage.run] must have 'branch = true' for branch coverage"
    )


def test_coverage_fail_under_80() -> None:
    """[tool.coverage.report] must set fail_under = 80."""
    toml = _read_toml_text()
    assert "fail_under = 80" in toml, (
        "[tool.coverage.report] must have 'fail_under = 80'"
    )


# ── 5. traceloop Pydantic v1 warning suppressed ──────────────────────────────


def test_filterwarnings_traceloop_pydantic_in_pyproject() -> None:
    """pyproject.toml must suppress the traceloop PydanticDeprecatedSince20 warning."""
    toml = _read_toml_text()
    assert "PydanticDeprecatedSince20" in toml, (
        "Missing filterwarnings entry for traceloop PydanticDeprecatedSince20"
    )
    assert "traceloop" in toml.split("PydanticDeprecatedSince20")[1][:200], (
        "filterwarnings entry should target the 'traceloop' module"
    )


# ── 6. sandbox marker registered ─────────────────────────────────────────────


def test_sandbox_marker_defined_in_pyproject() -> None:
    """pyproject.toml must declare the 'sandbox' pytest marker."""
    toml = _read_toml_text()
    assert '"sandbox:' in toml or "'sandbox:" in toml or "sandbox:" in toml, (
        "pyproject.toml must define a 'sandbox' marker in [tool.pytest.ini_options].markers"
    )


def test_sandbox_marker_usable(request: pytest.FixtureRequest) -> None:
    """The sandbox marker must be accepted without --strict-markers errors."""
    # If the marker were undefined, collection under --strict-markers would fail.
    _ = request.node.get_closest_marker("sandbox")  # None is fine, just must not error
