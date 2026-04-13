from phantom.tools.rbac import ToolRole, check_tool_permission, reset_rbac_context, set_rbac_role


def test_current_tool_rbac_categories_are_explicit() -> None:
    reset_rbac_context()
    set_rbac_role(ToolRole.JUNIOR_PENTESTER)

    assert check_tool_permission("query_hypotheses")[0] is True
    assert check_tool_permission("python_action")[0] is True
    assert check_tool_permission("terminal_execute")[0] is False
    assert check_tool_permission("confirm_hypothesis")[0] is True
