from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_execute_actions_blocks_repeated_identical_batch() -> None:
    from phantom.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.state = MagicMock()
    agent.state.add_message = MagicMock()
    agent._recent_action_batches = [
        '[{"args": {"url": "http://target/a"}, "toolName": "send_request"}]',
        '[{"args": {"url": "http://target/a"}, "toolName": "send_request"}]',
    ]

    actions = [{"toolName": "send_request", "args": {"url": "http://target/a"}}]

    with patch("phantom.agents.base_agent.process_tool_invocations", new_callable=AsyncMock) as mock_exec:
        should_finish = await agent._execute_actions(actions, tracer=None)

    assert should_finish is False
    mock_exec.assert_not_awaited()
    agent.state.add_message.assert_called()


@pytest.mark.asyncio
async def test_execute_actions_allows_non_repeated_batch() -> None:
    from phantom.agents.base_agent import BaseAgent

    agent = BaseAgent.__new__(BaseAgent)
    agent.state = MagicMock()
    agent.state.add_message = MagicMock()
    agent.state.get_conversation_history = MagicMock(return_value=[])
    agent.state.add_action = MagicMock()
    agent._recent_action_batches = []

    actions = [{"toolName": "send_request", "args": {"url": "http://target/b"}}]

    with patch("phantom.agents.base_agent.process_tool_invocations", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = False
        should_finish = await agent._execute_actions(actions, tracer=None)

    assert should_finish is False
    mock_exec.assert_awaited_once()
