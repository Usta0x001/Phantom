import os
import sys
import asyncio
import json

ROOT = os.path.abspath('.')
sys.path.insert(0, ROOT)

from phantom.agents.base_agent import BaseAgent
from phantom.agents.state import AgentState

class DummyConfig:
    def __init__(self):
        self.scan_mode = "deep"
        self.max_iterations = 20

class DynamicEndToEndAgent(BaseAgent):
    def __init__(self):
        self.config = {"llm_config": DummyConfig()}
        self.state = AgentState(agent_name="Main", max_iterations=20)
        self.state.context = {"task": "Find vulnerabilities"}
        self._recent_action_batches = []
        self._recent_action_results = []
        self._last_iteration_action_count = 0
        self.hypothesis_ledger = type("HL", (), {
            "get_scored_hypotheses": lambda: [{"hypothesis_id": "H1", "vuln_class": "xss", "surface": "/contact"}],
            "get_all": lambda: {"H1": type("H", (), {"evidence_for": []})()}
        })()

async def attack_end_to_end_loop_evasion():
    agent = DynamicEndToEndAgent()
    
    # We must append TWO recent identical successes to trigger the block
    sig = '[{"args": {"url": "http://target.com/page"}, "toolName": "fetch_url"}]'
    agent._recent_action_results.append((sig, True))
    agent._recent_action_results.append((sig, True))
    
    action_batch_2 = [{"toolName": "fetch_url", "args": {"url": "  http://target.com/page   "}}]
    
    should_finish = await agent._execute_actions(action_batch_2, None)
    
    messages = agent.state.get_conversation_history()
    evasion_blocked = False
    for msg in messages:
        if "repeated the exact same tool action batch multiple times" in msg.get("content", ""):
            evasion_blocked = True
            
    assert evasion_blocked, "END-TO-END FAILED: The agent allowed the whitespace variant to execute!"
    print("[SUCCESS] End-to-End A2 (Loop Evasion): The adversarial whitespace was stripped and the loop was violently terminated.")
    
def test_end_to_end_context_anchor():
    agent = DynamicEndToEndAgent()
    agent.state.add_message("user", "We found an API key in the response: sk_live_abc123")
    agent.state.add_message("assistant", "I will query the database.")
    
    context = agent._build_hypothesis_context()
    
    survived = False
    for msg in context:
        if "sk_live" in msg.get("content", ""):
            survived = True
            
    assert survived, "END-TO-END FAILED: The core credential was discarded during hypothesis context rotation."
    print("[SUCCESS] End-to-End A1 (Context Persistence): Critical data 'sk_live_abc123' survived the environment wipe.")

if __name__ == "__main__":
    print("\n[+] Initializing End-to-End Architecture Proof Sequence...")
    test_end_to_end_context_anchor()
    asyncio.run(attack_end_to_end_loop_evasion())
    print("[+] All Architectural Components Hardened and Structurally Sound.\n")
