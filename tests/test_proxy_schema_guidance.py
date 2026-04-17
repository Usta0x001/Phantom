from phantom.tools.registry import tools


def test_send_request_schema_mentions_private_address_pivot() -> None:
    by_name = {entry.get("name"): entry for entry in tools}
    schema = str(by_name["send_request"].get("xml_schema", ""))

    assert "private/internal" in schema
    assert "python_action" in schema


def test_scope_rules_schema_includes_docker_internal_example() -> None:
    by_name = {entry.get("name"): entry for entry in tools}
    schema = str(by_name["scope_rules"].get("xml_schema", ""))

    assert "*.docker.internal" in schema
    assert "Invalid patterns" in schema
