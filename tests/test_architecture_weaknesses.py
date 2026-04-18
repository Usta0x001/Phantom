import sys
import os

ROOT = os.path.abspath('.')
sys.path.insert(0, ROOT)

from phantom.agents.base_agent import BaseAgent
from phantom.agents.state import AgentState

class DummyAgent(BaseAgent):
    def __init__(self):
        self.config = {"llm_config": type("LLMConf", (), {"scan_mode": "deep"})()}
        self.state = AgentState(agent_name="Test", max_iterations=10)
        self.hypothesis_ledger = type("HL", (), {
            "get_scored_hypotheses": lambda: [{"hypothesis_id": "H1", "vuln_class": "sqli", "surface": "/api/users"}],
            "get_all": lambda: {"H1": type("H", (), {"evidence_for": []})()}
        })()

def prove_a1():
    agent = DummyAgent()
    agent.state.add_message("user", "Found leaked AWS root credentials: AKIAX12345")
    agent.state.add_message("user", "Testing SQLi on /api/users ...")
    
    context = agent._build_hypothesis_context()
    print("CONTEXT:")
    for msg in context:
        print(" ->", msg)

prove_a1()
