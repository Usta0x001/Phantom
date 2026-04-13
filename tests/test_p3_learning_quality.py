from phantom.agents.correlation_engine import CorrelationEngine


def test_surface_similarity_prefers_shared_path_prefix_over_root_only_match() -> None:
    engine = CorrelationEngine()

    for _ in range(4):
        engine.record_outcome(
            vuln_class="sqli",
            surface="/api/auth/login::username",
            outcome="confirmed",
            payload_family="union",
        )

    strong = engine.get_surface_success_score("sqli", "/api/auth/login::password")
    weak = engine.get_surface_success_score("sqli", "/admin/settings::id")

    assert strong > weak


def test_chain_patterns_use_explicit_required_any_semantics() -> None:
    engine = CorrelationEngine()

    result = engine.add_finding(vuln_class="xss", surface="/search::q", details={"outcome": "confirmed"})
    suggestions = result.get("new_suggestions", [])

    assert any("XSS to Session Hijacking" in s.get("chain_name", "") for s in suggestions)


def test_supportive_evidence_weight_does_not_overpower_failures() -> None:
    engine = CorrelationEngine()

    for _ in range(6):
        engine.record_outcome("sqli", "/api/profile::id", "testing", "boolean")
    for _ in range(4):
        engine.record_outcome("sqli", "/api/profile::id", "rejected", "boolean")

    score = engine.get_surface_success_score("sqli", "/api/profile::id")
    assert score < 0.6
