import pytest
import os
import re
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Any

from phantom.config.config import Config


# ──────────────────────────────────────────────────────────────────────
# FIX 1: Sandbox Fail-Closed Enforcement Verification
# ──────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_sandbox_fail_closed():
    """Verify that if an offensive tool demands a sandbox but the sandbox
    is misconfigured, the agent crashes via RuntimeError instead of running
    the exploit on the host OS."""
    from phantom.tools.executor import execute_tool
    
    # Mock a tool invocation that requires sandboxing
    mock_agent_state = MagicMock()
    mock_agent_state.sandbox_id = "test_sandbox"
    mock_agent_state.sandbox_token = "valid_token"
    mock_agent_state.agent_id = "agent_007"
    
    # Force phantom environment settings
    os.environ["PHANTOM_SANDBOX_MODE"] = "false"
    
    # By default, tools like `recon_nmap` or `terminal_execute` require sandbox
    with patch("phantom.tools.executor.should_execute_in_sandbox", return_value=True):
        with patch("phantom.tools.executor.get_tool_by_name") as get_tool:
            # We don't want it to actually run anyway, we expect an early crash
            with pytest.raises(RuntimeError) as exc_info:
                await execute_tool("terminal_execute", agent_state=mock_agent_state, command="id")
            
            # The exact string from our patch must be evaluated
            assert "requires Sandbox" in str(exc_info.value)
            assert "PHANTOM_SANDBOX_MODE is disabled" in str(exc_info.value)


# ──────────────────────────────────────────────────────────────────────
# FIX 2: Component Deletion Verification (No Ghost Dependencies)
# ──────────────────────────────────────────────────────────────────────
def test_ghost_components_purged():
    """Verify that rbac, cache, correlation engine, and enhanced state
    are completely scrubbed from the module space, throwing clean ImportErrors."""
    
    with pytest.raises(ImportError):
        import phantom.tools.rbac
        
    with pytest.raises(ImportError):
        import phantom.tools.cache
        
    with pytest.raises(ImportError):
        import phantom.agents.correlation_engine
        
    with pytest.raises(ImportError):
        import phantom.agents.enhanced_state


# ──────────────────────────────────────────────────────────────────────
# FIX 3: Memory Compressor JSON Payload Preservation
# ──────────────────────────────────────────────────────────────────────
def test_memory_compressor_json_payloads():
    """Verify that pure JSON exploitation payloads are captured 
    by the memory compressor and do not decay when the context window shrinks."""
    from phantom.llm.memory_compressor import _extract_anchors_from_chunk
    
    test_chunk = [
        # Noise message (should be decayed)
        {"role": "assistant", "content": "I am looking at the endpoints to see what to attack next."},
        
        # Pure JSON exploit without the english word 'found' (was previously ignored)
        {"role": "assistant", "content": """{"subaction": "sqli_exploit", "toolName": "advanced_request", "args": {"payload": "' OR 1=1--"}, "status": "confirmed"}"""},
        
        # Testing noise (should be decayed)
        {"role": "assistant", "content": "testing xss payload on the parameter"},
    ]
    
    anchors = _extract_anchors_from_chunk(test_chunk)
    
    # We should have exactly 1 anchor, and it MUST be the JSON block
    assert len(anchors) == 1
    assert "sqli_exploit" in anchors[0]["text"]
    assert "payload" in anchors[0]["text"]


# ──────────────────────────────────────────────────────────────────────
# FIX 4: Agent Error Fallback Recovery (SF-05 FIX)
# ──────────────────────────────────────────────────────────────────────
def test_agent_error_fallback():
    """Verify the agent no longer executes an unconditional `if True`
    death spiral upon LLM or Sandbox failure, and correctly defers to
    non_interactive handling."""
    from phantom.agents.base_agent import BaseAgent
    from phantom.llm.llm import LLMRequestFailedError
    
    # Initialize basic agent
    mock_config = {"llm_config": MagicMock(), "non_interactive": False}
    with patch("phantom.agents.base_agent.BaseAgent.__init__", return_value=None):
        agent = BaseAgent(mock_config)
        agent.non_interactive = False
        agent.state = MagicMock()
        agent.state.agent_id = "agent_01"
        
        # Manually invoke the error handler
        error = LLMRequestFailedError("Rate limit exceeded")
        agent._handle_llm_error(error, None)
        
        # Verify it went to the interactive waiting state, NOT unconditional death
        agent.state.enter_waiting_state.assert_called_once()
        agent.state.set_completed.assert_not_called()
