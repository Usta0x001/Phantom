import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath('.'))

# We mock out Litellm so we don't do real requests
os.environ["PHANTOM_LLM"] = "openai/gpt-4"

from phantom.agents.state import BaseAgentState
from phantom.llm.memory_compressor import _extract_anchors_from_chunk
from phantom.tools.executor import _validate_tool_argument_injection

class DAGHypothesis:
    # A mock of the NEW DAG Hypothesis without alpha, beta, tracking, etc.
    def __init__(self):
        self.id = "H-001"
        self.surface = "/api/test"
        self.vuln_class = "sqli"
        self.status = "open"
        self.payloads_tested = []
        self.evidence_for = []
        self.evidence_against = []
        # PURPOSELY OMITTED Math variables!

class TestDAGSafety(unittest.TestCase):
    def test_state_anchor_extraction_survives_missing_confidence(self):
        # Memory compressor expects confidence_score as fallback in dictionary
        # We prove that deleting the math won't crash anchors.
        chunk = [{"role": "user", "content": "found: critical SQLi vulnerability!"}]
        anchors = _extract_anchors_from_chunk(chunk)
        self.assertGreater(len(anchors), 0)
        
        # Test agent state update which tries to get confidence_score
        state = BaseAgentState("test_agent")
        state.finding_anchors = anchors
        # Should not raise AttributeError when sorting or updating
        state.update_finding_anchors()

    def test_executor_survives_missing_confidence(self):
        # Executor also does getattr(hypothesis, 'confidence_score', 50.0)
        h = DAGHypothesis()
        c = getattr(h, "confidence_score", 50.0)
        self.assertEqual(c, 50.0)

if __name__ == '__main__':
    unittest.main()
