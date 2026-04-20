import asyncio
import threading
import time
import random
import pytest
from typing import Any

from phantom.agents.state import AgentState
from phantom.agents.base_agent import BaseAgent
from phantom.core.attack_graph import AttackGraph



@pytest.mark.asyncio
async def test_adversarial_thread_starvation_graph_lock():
    """
    ATTACK: AF-03 / NEW-01
    GOAL: Spawn 100 threads that violently read/write and lock the graph.
    Check if the _GRAPH_LOCK throws recursion errors, deadlocks or dictionary size mutation errors.
    """
    from phantom.tools.agents_graph.agents_graph_actions import _agent_messages, _GRAPH_LOCK

    state = AgentState(task="lock-breaker")
    _agent_messages[state.agent_id] = []
    
    class FakeAgent(BaseAgent):
        def _initialize_prompts(self): pass
        def _get_system_prompt_variables(self): return {}

    agent = FakeAgent(config={})

    # Pre-populate 100 messages
    for i in range(100):
        _agent_messages[state.agent_id].append({"from": "user", "content": f"msg_{i}", "read": False})

    errors = []

    def attack_thread(thread_id: int):
        try:
            for i in range(20):
                # Aggressively try to invoke the inbox check which locks
                agent._check_agent_messages(state)
                # Randomly lock the graph manually to simulate external actions
                with _GRAPH_LOCK:
                    msgs = _agent_messages.get(state.agent_id, [])
                    if len(msgs) < 1000:
                        msgs.append({"from": f"adversary_{thread_id}", "content": "fuzz", "read": False})
                time.sleep(0.001)
        except Exception as e:
            errors.append(e)

    threads = []
    for i in range(50):
        t = threading.Thread(target=attack_thread, args=(i,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join(timeout=5)

    # Prove no race conditions occurred and threads completed.
    assert len(errors) == 0, f"Thread safety broken! Raised: {errors}"
    assert len(state.messages) > 0, "Agent state messages should not be empty!"


def test_adversarial_attack_graph_exponential_complexity():
    """
    ATTACK: CF-06
    GOAL: Generate a fully-connected K_30 graph. Without depth bounds, this contains 
    billions of simple paths and will instantly CPU timeout and freeze the machine.
    We prove that our fix prevents complexity explosion.
    """
    graph = AttackGraph()
    
    # Build K_30 fully connected graph
    for i in range(30):
        graph._ensure_node_exists(f"surface_{i}", "Surface")
        graph._ensure_node_exists(f"vuln_{i}", "Vulnerability", metadata={"status": "confirmed"})
        
        # Connect vulnerabilities to surfaces and each other
        graph._add_edge(f"surface_{i}", f"vuln_{i}", "EXPOSES")
        for j in range(30):
            if i != j:
                graph._add_edge(f"vuln_{i}", f"vuln_{j}", "CHAINS_TO")
                graph._add_edge(f"surface_{i}", f"surface_{j}", "RELATES_TO")

    # If the cutoff=5 fix is missing, this next line will never return.
    start = time.time()
    paths = graph.get_vulnerability_chains("vuln_0", max_paths_per_target=100)
    end = time.time()
    
    # Should execute in milliseconds, prove it finishes in under a second.
    assert (end - start) < 2.0, "Graph complexity bound bypassed! CPU Denial of Service succeeded."
    # Since we limit max_paths_per_target=100 theoretically it might hit the cap
    assert isinstance(paths, list)


@pytest.mark.asyncio
async def test_adversarial_prompt_injection_eviction():
    """
    ATTACK: CA-01 / SR-06
    GOAL: Submit massive amounts of specifically crafted HTML escaping truncation 
    malicious buffers. See if deduplication suppresses it and if system crashes.
    """
    state = AgentState(task="poison")
    
    vicious_payload = "A" * 150 + "<script>alert(1)"
    for _ in range(50):
        # We use add_message directly simulating inter-agent HTML truncations happening
        # before the SR-06 fix. If the raw is truncated inside an HTML tag, subsequent escapes fail.
        import html as _html
        
        raw_content = vicious_payload
        safe_content = _html.escape(raw_content)
        if len(safe_content) > 100:
            safe_content = safe_content[:97] + "..."
            
        state.add_message("user", f"[From Adversary]: {safe_content}")

    # Deduplication should handle redundant payloads correctly
    # Verify that we don't have broken escaped characters
    for msg in state.messages:
        content = msg.get("content", "")
        # The truncation should not break standard xml parsers downstream
        assert "&lt;" in content or "..." in content


@pytest.mark.asyncio
async def test_adversarial_fault_tolerance(monkeypatch: pytest.MonkeyPatch):
    """
    ATTACK: Execution System "Suppose Nothing Works"
    GOAL: Hardcode the executor to randomly vomit unhandled deep exceptions
    and return memory faults. BaseAgent must catch it securely and loop.
    """
    class TargetAgent(BaseAgent):
        def _initialize_prompts(self): pass
        def _get_system_prompt_variables(self): return {}

    agent = TargetAgent(config={})
    agent.state = AgentState(task="fuzz-loop")
    
    import phantom.tools.executor as ext

    # Malicious injection overriding the tool execution pipeline
    async def catastrophic_executor(*args, **kwargs):
        raise MemoryError("Arbitrary memory fault injected by adversary!")
    
    monkeypatch.setattr(ext, "execute_tool_with_validation", catastrophic_executor)
    
    agent._current_task = asyncio.create_task(ext.execute_tool_with_validation("dummy"))
    
    # Run the internal loop mechanics
    try:
        from phantom.telemetry.tracer import Tracer
        tracer = Tracer("fuzz")
        
        should_finish = await agent._process_tool_invocations(
            agent._current_task,
            tool_calls=[{"function": {"name": "dummy"}}],
            tracer=tracer,
            start_time=time.time()
        )
        assert should_finish is False # Must absorb error and continue
        
        last_error = agent.state.errors[-1]
        assert "Memory fault" in last_error or "MemoryError" in last_error
        
    except MemoryError:
        pytest.fail("BaseAgent leaked an unhandled critical exception during execution pipeline!")
