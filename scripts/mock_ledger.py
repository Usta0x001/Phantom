from typing import Any, Dict, List
import threading
from datetime import datetime, timezone

class Hypothesis:
    def __init__(self, surface: str, vuln_class: str, hid: str):
        self.id = hid
        self.surface = surface
        self.vuln_class = vuln_class
        self.status = "open"
        self.payloads_tested: List[str] = []
        self.successful_payloads: List[str] = []
        self.evidence_for: List[str] = []
        self.evidence_against: List[str] = []
        self.details: Dict[str, Any] = {}
        self.tests_executed = 0
        self.iterations_spent = 0
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_updated = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "surface": self.surface,
            "vuln_class": self.vuln_class,
            "status": self.status,
        }

class HypothesisLedger:
    def __init__(self):
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._lock = threading.RLock()
        self._id_counter = 0

    def add(self, surface: str, vuln_class: str) -> str:
        with self._lock:
            for hyp in self._hypotheses.values():
                if hyp.surface == surface and hyp.vuln_class == vuln_class:
                    return hyp.id
            self._id_counter += 1
            hid = f"H-{self._id_counter:04d}"
            self._hypotheses[hid] = Hypothesis(surface, vuln_class, hid)
            return hid

    def get_all(self):
        return self._hypotheses

print("Mock loaded successfully")
