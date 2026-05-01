import threading
import logging
from typing import Any, Dict, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_ACTIVE_STATUSES = {"open", "testing"}

def _surface_matches(s1: str, s2: str) -> bool:
    """Normalize URLs for matching: strip query params and fragments so
    'https://x.com/login?next=/admin' matches 'https://x.com/login'.
    """
    from urllib.parse import urlsplit, urlunsplit

    def _norm(s: str) -> str:
        s = str(s or "").strip().lower()
        # If it looks like a URL, strip query and fragment
        if s.startswith(("http://", "https://")):
            try:
                p = urlsplit(s)
                s = urlunsplit((p.scheme, p.netloc, p.path, "", ""))
            except Exception:
                pass
        return s

    return _norm(s1) == _norm(s2)

class Hypothesis:
    def __init__(self, surface: str, vuln_class: str, hid: str):
        self.id = hid
        self.surface = str(surface or "").strip()
        self.vuln_class = str(vuln_class or "").strip().lower()
        self.status = "open"
        self.confidence = "low"  # low | medium | high | confirmed
        self.payloads_tested: List[str] = []
        self.successful_payloads: List[str] = []
        self.evidence_for: List[str] = []
        self.evidence_against: List[str] = []
        self.details: Dict[str, Any] = {}
        self.tests_executed = 0
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.last_updated = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        # Return copies of mutable containers so callers cannot corrupt internal state.
        return {
            "id": self.id,
            "surface": self.surface,
            "vuln_class": self.vuln_class,
            "status": self.status,
            "confidence": self.confidence,
            "tests_executed": self.tests_executed,
            "payloads_tested": list(self.payloads_tested),
            "successful_payloads": list(self.successful_payloads),
            "evidence_for": list(self.evidence_for),
            "evidence_against": list(self.evidence_against),
            "details": dict(self.details),
            "created_at": self.created_at,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Hypothesis":
        h = cls(data["surface"], data["vuln_class"], data["id"])
        h.status = data.get("status", "open")
        h.confidence = data.get("confidence", "low")
        h.tests_executed = data.get("tests_executed", 0)
        h.payloads_tested = data.get("payloads_tested", [])
        h.successful_payloads = data.get("successful_payloads", [])
        h.evidence_for = data.get("evidence_for", [])
        h.evidence_against = data.get("evidence_against", [])
        h.details = data.get("details", {})
        h.created_at = data.get("created_at", datetime.now(timezone.utc).isoformat())
        h.last_updated = data.get("last_updated", h.created_at)
        return h

class HypothesisLedger:
    def __init__(self) -> None:
        self._hypotheses: Dict[str, Hypothesis] = {}
        self._lock = threading.RLock()
        self._id_counter = 0

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

    def _get_raw(self, hypothesis_id: str) -> Hypothesis | None:
        """Return the internal mutable reference (for use only inside locked methods)."""
        return self._hypotheses.get(hypothesis_id)

    def get_all(self) -> Dict[str, Hypothesis]:
        with self._lock:
            # Return deep copies so callers cannot corrupt internal state.
            return {hid: Hypothesis.from_dict(hyp.to_dict()) for hid, hyp in self._hypotheses.items()}

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        with self._lock:
            hyp = self._hypotheses.get(hypothesis_id)
            return Hypothesis.from_dict(hyp.to_dict()) if hyp is not None else None

    def _find_by_surface_and_class_raw(self, surface: str, vuln_class: str) -> Hypothesis | None:
        vuln_lower = str(vuln_class or "").strip().lower()
        for hyp in self._hypotheses.values():
            if _surface_matches(hyp.surface, surface) and hyp.vuln_class == vuln_lower:
                return hyp
        return None

    def find_by_surface_and_class(self, surface: str, vuln_class: str) -> Hypothesis | None:
        with self._lock:
            raw = self._find_by_surface_and_class_raw(surface, vuln_class)
            return Hypothesis.from_dict(raw.to_dict()) if raw is not None else None

    def add(self, surface: str, vuln_class: str) -> str:
        vuln_lower = str(vuln_class or "").strip().lower()
        with self._lock:
            existing = self._find_by_surface_and_class_raw(surface, vuln_lower)
            if existing:
                return existing.id
            self._id_counter += 1
            hid = f"HYP-{self._id_counter:04d}"
            self._hypotheses[hid] = Hypothesis(surface, vuln_lower, hid)
            return hid

    def record_payload(self, hypothesis_id: str, payload: str) -> bool:
        with self._lock:
            hyp = self._get_raw(hypothesis_id)
            if not hyp:
                return False
            payload = str(payload or "").strip()
            if payload and payload not in hyp.payloads_tested:
                hyp.payloads_tested.append(payload)
                if len(hyp.payloads_tested) > 50:
                    hyp.payloads_tested = hyp.payloads_tested[-50:]
                hyp.tests_executed += 1
                if hyp.status == "open":
                    hyp.status = "testing"
                hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def add_evidence_for(self, hypothesis_id: str, evidence: str, payload: str = "", response_snippet: str = "") -> bool:
        """Record confirming evidence with optional structured context.

        Args:
            evidence: Human-readable description of the finding.
            payload: The exact payload that triggered the evidence (for reproduction).
            response_snippet: A short excerpt from the response that confirms the vuln.
        """
        with self._lock:
            hyp = self._get_raw(hypothesis_id)
            if not hyp:
                return False
            entry = str(evidence)
            if payload:
                entry += f" | payload={payload[:100]}"
            if response_snippet:
                entry += f" | response={response_snippet[:200]}"
            hyp.evidence_for.append(entry)
            if len(hyp.evidence_for) > 20:
                hyp.evidence_for = hyp.evidence_for[-20:]
            # Auto-escalate confidence as evidence accumulates
            if len(hyp.evidence_for) >= 5:
                hyp.confidence = "high"
            elif len(hyp.evidence_for) >= 2:
                hyp.confidence = "medium"
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def add_evidence_against(self, hypothesis_id: str, evidence: str) -> bool:
        with self._lock:
            hyp = self._get_raw(hypothesis_id)
            if not hyp:
                return False
            hyp.evidence_against.append(str(evidence))
            if len(hyp.evidence_against) > 20:
                hyp.evidence_against = hyp.evidence_against[-20:]
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def confirm(self, hypothesis_id: str, evidence: str, exploitation_details: Dict[str, Any] | None = None) -> bool:
        with self._lock:
            hyp = self._get_raw(hypothesis_id)
            if not hyp:
                return False
            hyp.status = "confirmed"
            hyp.confidence = "confirmed"
            hyp.evidence_for.append(str(evidence))
            if len(hyp.evidence_for) > 20:
                hyp.evidence_for = hyp.evidence_for[-20:]
            if exploitation_details:
                hyp.details.update(exploitation_details)
                payload = exploitation_details.get("successful_payload") or exploitation_details.get("payload")
                if payload:
                    hyp.successful_payloads.append(str(payload))
                    if len(hyp.successful_payloads) > 10:
                        hyp.successful_payloads = hyp.successful_payloads[-10:]
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def reject(self, hypothesis_id: str, reason: str = "") -> bool:
        with self._lock:
            hyp = self._get_raw(hypothesis_id)
            if not hyp:
                return False
            hyp.status = "rejected"
            if reason:
                hyp.evidence_against.append(reason)
            hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True

    def has_tested(self, surface: str, vuln_class: str, payload: str) -> bool:
        vuln_lower = str(vuln_class or "").strip().lower()
        with self._lock:
            for hyp in self._hypotheses.values():
                if _surface_matches(hyp.surface, surface) and hyp.vuln_class == vuln_lower:
                    return payload in hyp.payloads_tested
            return False

    def record_result(self, hypothesis_id: str, new_status: str, evidence: str = "") -> bool:
        if new_status == "confirmed":
            return self.confirm(hypothesis_id, evidence)
        elif new_status == "rejected":
            return self.reject(hypothesis_id, evidence)
        elif new_status == "testing":
            with self._lock:
                hyp = self._get_raw(hypothesis_id)
                if not hyp:
                    return False
                hyp.status = "testing"
                if evidence:
                    hyp.evidence_for.append(str(evidence))
                    if len(hyp.evidence_for) > 20:
                        hyp.evidence_for = hyp.evidence_for[-20:]
                hyp.last_updated = datetime.now(timezone.utc).isoformat()
            return True
        return False

    def get_scored_hypotheses(self) -> List[Dict[str, Any]]:
        """Return active hypotheses scored by evidence quality + status.

        A hypothesis with 10 pieces of confirming evidence ranks higher than
        one with 0 evidence, even if both have status 'open'.
        """
        with self._lock:
            active = [h for h in self._hypotheses.values() if h.status in _ACTIVE_STATUSES]
        if not active:
            return []

        scored = []
        for h in active:
            # Base score by status
            base = 1000 if h.status == "testing" else 500
            # Evidence bonus: +50 per confirming piece, capped at +500
            evidence_bonus = min(len(h.evidence_for) * 50, 500)
            # Payload diversity bonus: +20 per unique payload tested
            payload_bonus = min(len(set(h.payloads_tested)) * 20, 200)
            scored.append({
                "hypothesis_id": h.id,
                "surface": h.surface,
                "vuln_class": h.vuln_class,
                "status": h.status,
                "confidence": h.confidence,
                "priority_score": base + evidence_bonus + payload_bonus,
                "evidence_count": len(h.evidence_for),
                "payloads_tested": len(h.payloads_tested),
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




