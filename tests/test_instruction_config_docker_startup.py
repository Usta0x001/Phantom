from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock


def test_instruction_is_injected_as_high_priority() -> None:
    from phantom.agents.PhantomAgent.phantom_agent import PhantomAgent

    agent = object.__new__(PhantomAgent)
    agent.agent_loop = AsyncMock(return_value={"ok": True})

    scan_config = {
        "user_instructions": "Focus on SQLi and IDOR only",
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": "http://example.com"},
            }
        ],
    }

    import asyncio

    asyncio.run(PhantomAgent.execute_scan(agent, scan_config))

    assert agent.agent_loop.await_count == 1
    task_arg = agent.agent_loop.await_args.kwargs["task"]
    assert "User-supplied mission constraints (highest priority):" in task_arg
    assert "Focus on SQLi and IDOR only" in task_arg


def test_check_docker_connection_auto_starts_on_windows(monkeypatch) -> None:
    from phantom.interface import utils

    calls = {"n": 0}
    client = MagicMock()

    def _from_env():
        calls["n"] += 1
        if calls["n"] == 1:
            from docker.errors import DockerException

            raise DockerException("daemon down")
        return client

    monkeypatch.setattr(utils.docker, "from_env", _from_env)
    monkeypatch.setattr(utils, "_start_docker_desktop_windows", lambda: True)
    monkeypatch.setattr(utils.os, "name", "nt", raising=False)
    monkeypatch.setattr(utils.time, "sleep", lambda _: None)

    got = utils.check_docker_connection()
    assert got is client
    assert calls["n"] >= 2
    assert client.ping.called


def test_cli_app_force_applies_saved_config() -> None:
    src = (Path(__file__).parent.parent / "phantom" / "interface" / "cli_app.py").read_text(
        encoding="utf-8"
    )

    assert "apply_saved_config(force=True)" in src, (
        "scan/resume must force-apply saved config so `phantom config set` is effective "
        "even when shell env is stale"
    )


def test_localhost_target_registers_host_gateway_alias(monkeypatch) -> None:
    from phantom.agents.PhantomAgent.phantom_agent import PhantomAgent
    from phantom.tools.proxy import proxy_manager

    captured: list[str] = []

    def _capture(hostname: str) -> None:
        captured.append(hostname)

    monkeypatch.setattr(proxy_manager, "allow_ssrf_host", _capture)

    agent = object.__new__(PhantomAgent)
    agent.agent_loop = AsyncMock(return_value={"ok": True})

    scan_config = {
        "targets": [
            {
                "type": "web_application",
                "details": {"target_url": "http://localhost:3000"},
            }
        ],
        "user_instructions": "",
    }

    import asyncio

    asyncio.run(PhantomAgent.execute_scan(agent, scan_config))

    assert "localhost" in captured
    assert "host.docker.internal" in captured
