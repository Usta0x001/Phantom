"""Pure DABS kernel primitives.

This module contains the minimal deterministic state transition and scoring
math for the research kernel. It must stay free of LLM calls, heuristic
ranking, prompt data, and target-semantic inference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


_DABS_DEFAULT_LAMBDA = 0.20

_RELATION_WEIGHTS: dict[str, float] = {
    "chain": 0.45,
    "surface_similarity": 0.35,
    "family_grouping": 0.20,
}


@dataclass(frozen=True)
class StructuredHypothesis:
    """Kernel-compatible hypothesis specification."""

    vuln_class: str
    target_surface: str
    preconditions: tuple[str, ...] = ()
    expected_exploit_path: str = ""
    required_signals: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class DABSDecisionTrace:
    """Deterministic selection trace emitted by the kernel."""

    selected_hypothesis_id: str | None
    scores: list[dict[str, Any]]
    belief_map: dict[str, float]
    scheduler_mode: str
    selection_step: int
    propagation_step: int
    lambda_value: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_hypothesis_id": self.selected_hypothesis_id,
            "scores": list(self.scores),
            "belief_map": dict(self.belief_map),
            "scheduler_mode": self.scheduler_mode,
            "selection_step": self.selection_step,
            "propagation_step": self.propagation_step,
            "lambda": self.lambda_value,
        }


def clamp_belief(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 6)


def initial_belief() -> float:
    return 0.5


def exploration_term(tests_executed: int) -> float:
    return round(1.0 / float(1 + max(0, int(tests_executed))), 6)


def redundancy_penalty(tested_families: int, total_families: int) -> float:
    total = max(1, int(total_families))
    tested = max(0, int(tested_families))
    return round(min(1.0, tested / float(total)), 6)


def score_hypothesis(
    belief: float,
    tests_executed: int,
    tested_families: int,
    total_families: int,
) -> float:
    return round(
        clamp_belief(belief)
        + exploration_term(tests_executed)
        - redundancy_penalty(tested_families, total_families),
        6,
    )


def relation_strength(relation_types: Iterable[str]) -> float:
    strength = 0.0
    seen = {str(item).strip().lower() for item in relation_types if str(item).strip()}
    for relation in seen:
        strength += _RELATION_WEIGHTS.get(relation, 0.0)
    return round(min(1.0, max(0.0, strength)), 6)


def propagate_belief(old_belief: float, relation: float, delta: float, lambda_value: float) -> float:
    updated = float(old_belief) + (float(lambda_value) * float(relation) * float(delta))
    return clamp_belief(updated)


def select_argmax(scored: list[dict[str, Any]]) -> str | None:
    if not scored:
        return None
    best = max(
        scored,
        key=lambda item: (
            float(item.get("priority_score", 0.0)),
            -int(item.get("tests_executed", 0)),
            str(item.get("hypothesis_id", "")),
        ),
    )
    return str(best.get("hypothesis_id")) or None


def propagation_lambda(raw_value: Any = None) -> float:
    try:
        value = float(raw_value if raw_value is not None else _DABS_DEFAULT_LAMBDA)
    except (TypeError, ValueError):
        value = _DABS_DEFAULT_LAMBDA
    return max(0.0, min(1.0, value))
