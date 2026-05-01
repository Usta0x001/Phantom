import threading
import logging
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_VALID_STATUSES = {"open", "testing", "confirmed", "rejected"}
_ACTIVE_STATUSES = {"open", "testing"}

def _surface_matches(s1: str, s2: str) -> bool:
    """Basic normalization for matching."""
    s1 = str(s1 or "").strip().lower()
    s2 = str(s2 or "").strip().lower()
    return s1 == s2

class Hypothesis:
    def __init__(self, surface: str, vuln_class: str, hid: str):
        self.id = hid
        self.surface = str(surface or "").strip()
        self.vuln_class = str(vuln_class or "").strip().lower()
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
            "tests_executed": self.tests_executed,
            "iterations_spent": self.iterations_spent,
            "payloads_tested": self.payloads_tested,
            "successful_payloads": self.successful_payloads,
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
            "details": self.details,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Hypothesis":
        h = cls(data["surface"], data["vuln_class"], data["id"])
        h.status = data.get("status", "open")
        h.tests_executed = data.get("tests_executed", 0)
        h.iterations_spent = data.get("iterations_spent", 0)
        h.payloads_tested = data.get("payloads_tested", [])
        h.successful_payloads = data.get("successful_payloads", [])
        h.evidence_for = data.get("evidence_for", [])
        h.evidence_against = data.get("evidence_against", [])
        h.details = data.get("details", {})
        h.created_at = data.get("created_at", datetime.now(timezone.utc).isoformat())
        h.last_updated = data.get("last_updated", h.created_at)
        return h

class HypothesisLedger:
    def __init__(self, auto_flush: bool = False, persist_dir: str | None = None):
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._lock = threading.RLock()
        self._id_counter = 0
        self._confirmation_callbacks: List[Callable[[str, Hypothesis], None]] = []

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HypothesisLedger":
        ledger = cls()
        ledger._id_counter = data.get("counter", 0)
        hypotheses = data.get("hypotheses", {})
        if isinstance(hypotheses, dict):
            for hid, hyp_data in hypotheses.items():
                if isinstance(hyp_data, dict):
                    ledger._hypotheses[hid] = Hypothesis.from_dict(hyp_data)
        return ledger

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "counter": self._id_counter,
                "hypotheses": {hid: hyp.to_dict() for hid, hyp in self._hypotheses.items()},
            }

    def get_all(self) -> Dict[str, Hypothesis]:
        with self._lock:
            return dict(self._hypotheses)

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        with self._lock:
            return self._hypotheses.get(hypothesis_id)

    def find_by_surface_and_class(self, surface: str, vuln_class: str) -> Hypothesis | None:
        vuln_lower = str(vuln_class or "").strip().lower()
        with self._lock:
            for hyp in self._hypotheses.values():
                if _surface_matches(hyp.surface, surface) and hyp.vuln_class.lower() == vuln_lower:
                    return hyp
            return None

    def add(self, surface: str, vuln_class: str) -> str:
        vuln_lower = str(vuln_class or "").strip().lower()
        with self._lock:
            existing = self.find_by_surface_and_class(surface, vuln_lower)
            if existing:
                return existing.id
            self._id_counter += 1
            hid = f"HYP-{self._id_counter:04d}"
            self._hypotheses[hid] = Hypothesis(surface, vuln_lower, hid)
            return hid

    def record_payload(self, hypothesis_id: str, payload: str) -> bool:
        with self._lock:
            hyp = self.get(hypothesis_id)
            if not hyp:
                return False
            payload = str(payload or "").strip()
            if payload and payload not in hyp.payloads_tested:
                hyp.payloads_tested.append(payload)
                hyp.tests_executed += 1
                if hyp.status == "open":
                    hyp.status = "testing"
                hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def add_evidence_for(self, hypothesis_id: str, evidence: str, outcome: str = "success") -> bool:
        with self._lock:
            hyp = self.get(hypothesis_id)
            if not hyp:
                return False
            hyp.evidence_for.append(str(evidence))
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def add_evidence_against(self, hypothesis_id: str, evidence: str, outcome: str = "failure") -> bool:
        with self._lock:
            hyp = self.get(hypothesis_id)
            if not hyp:
                return False
            hyp.evidence_against.append(str(evidence))
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def register_confirmation_callback(self, callback: Callable[[str, Hypothesis], None]) -> None:
        with self._lock:
            self._confirmation_callbacks.append(callback)

    def confirm(self, hypothesis_id: str, evidence: str, exploitation_details: Dict[str, Any] | None = None) -> bool:
        with self._lock:
            hyp = self.get(hypothesis_id)
            if not hyp:
                return False
            hyp.status = "confirmed"
            
            # Apply tags but DO NOT allow JSON strings to bypass these checks.
            evi = str(evidence)
            weak_phrases = ["seems to", "appears to", "maybe", "probably", "might", "could be"]
            if len(evi) < 50:
                evi = f"[NEEDS_MORE_DETAIL] {evi}"
            if any(phrase in evi.lower() for phrase in weak_phrases):
                evi = f"[WEAK_EVIDENCE] {evi}"

            hyp.evidence_for.append(evi)
            if exploitation_details:
                hyp.details.update(exploitation_details)
                payload = exploitation_details.get("successful_payload") or exploitation_details.get("payload")
                if payload:
                    hyp.successful_payloads.append(str(payload))
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            
            callbacks = list(self._confirmation_callbacks)
            hyp_copy = hyp
            
        for cb in callbacks:
            try:
                cb(hypothesis_id, hyp_copy)
            except Exception:
                pass
        return True

    def reject(self, hypothesis_id: str, reason: str = "") -> bool:
        with self._lock:
            hyp = self.get(hypothesis_id)
            if not hyp:
                return False
            hyp.status = "rejected"
            if reason:
                hyp.evidence_against.append(reason)
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def has_tested(self, surface: str, vuln_class: str, payload: str) -> bool:
        hyp = self.find_by_surface_and_class(surface, vuln_class)
        if not hyp:
            return False
        return payload in hyp.payloads_tested

    def record_result(self, hypothesis_id: str, new_status: str, evidence: str = "") -> bool:
        if new_status == "confirmed":
            return self.confirm(hypothesis_id, evidence)
        elif new_status == "rejected":
            return self.reject(hypothesis_id, evidence)
        elif new_status == "testing":
            with self._lock:
                hyp = self.get(hypothesis_id)
                if not hyp:
                    return False
                hyp.status = "testing"
                if evidence:
                    hyp.evidence_for.append(str(evidence))
                hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def get_open_hypotheses(self) -> List[Hypothesis]:
        with self._lock:
            return [h for h in self._hypotheses.values() if h.status in _ACTIVE_STATUSES]

    def _make_payload_family(self, vuln_class: str, payload: str) -> str:
        return f"{vuln_class}_payload"

    def get_scored_hypotheses(self) -> List[Dict[str, Any]]:
        # Returns simple priority ordering without math
        with self._lock:
            active = [h for h in self._hypotheses.values() if h.status in _ACTIVE_STATUSES]
        if not active:
            return []
        
        scored = []
        for h in active:
            priority = 1000 if h.status == "testing" else 500
            scored.append({
                "hypothesis_id": h.id,
                "surface": h.surface,
                "vuln_class": h.vuln_class,
                "status": h.status,
                "priority_score": priority
            })
        scored.sort(key=lambda x: x["priority_score"], reverse=True)
        return scored

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            hyps = list(self._hypotheses.values())
        if not hyps:
            return {"total": 0, "by_status": {}, "by_class": {}, "message": "No hypotheses in ledger"}
        
        by_status = {}
        by_class = {}
        for h in hyps:
            by_status[h.status] = by_status.get(h.status, 0) + 1
            by_class[h.vuln_class] = by_class.get(h.vuln_class, 0) + 1
            
        confirmed = [h for h in hyps if h.status == "confirmed"]
        
        return {
            "total": len(hyps),
            "by_status": by_status,
            "by_class": by_class,
            "confirmed_count": len(confirmed),
            "top_confirmed": [
                {
                    "id": h.id,
                    "vuln_class": h.vuln_class,
                    "surface": h.surface[:50],
                    "evidence_count": len(h.evidence_for)
                } for h in confirmed[:5]
            ],
            "open_hypotheses": [
                {
                    "id": h.id,
                    "vuln_class": h.vuln_class,
                    "surface": h.surface[:50],
                    "status": h.status,
                    "tests_executed": h.tests_executed
                } for h in hyps if h.status in _ACTIVE_STATUSES
            ][:5]
        }

    def get_prioritized_summary(self, top_n: int = 10) -> List[Dict[str, Any]]:
        return self.get_scored_hypotheses()[:top_n]

    def get_scheduler_report(self) -> Dict[str, Any]:
        return {"mode": "dag", "details": "Deterministic DAG mode enabled"}
