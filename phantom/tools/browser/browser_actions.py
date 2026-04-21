import importlib.util
from typing import TYPE_CHECKING, Any, Literal, NoReturn

from phantom.tools.registry import register_tool


_PLAYWRIGHT_AVAILABLE = importlib.util.find_spec("playwright") is not None


if TYPE_CHECKING:
    from .tab_manager import BrowserTabManager


BrowserAction = Literal[
    "launch",
    "goto",
    "click",
    "type",
    "scroll_down",
    "scroll_up",
    "back",
    "forward",
    "new_tab",
    "switch_tab",
    "close_tab",
    "wait",
    "execute_js",
    "double_click",
    "hover",
    "press_key",
    "save_pdf",
    "get_console_logs",
    "view_source",
    "close",
    "list_tabs",
    # CSS Selector-based actions (more reliable than coordinates)
    "click_selector",
    "fill_selector",
    "wait_for_selector",
    "query_selector_all",
]


def _validate_url(action_name: str, url: str | None) -> None:
    if not url:
        raise ValueError(f"url parameter is required for {action_name} action")


def _validate_coordinate(action_name: str, coordinate: str | None) -> None:
    if not coordinate:
        raise ValueError(f"coordinate parameter is required for {action_name} action")


def _validate_text(action_name: str, text: str | None) -> None:
    if not text:
        raise ValueError(f"text parameter is required for {action_name} action")


def _validate_tab_id(action_name: str, tab_id: str | None) -> None:
    if not tab_id:
        raise ValueError(f"tab_id parameter is required for {action_name} action")


def _validate_js_code(action_name: str, js_code: str | None) -> None:
    if not js_code:
        raise ValueError(f"js_code parameter is required for {action_name} action")


def _validate_duration(action_name: str, duration: float | None) -> None:
    if duration is None:
        raise ValueError(f"duration parameter is required for {action_name} action")


def _validate_key(action_name: str, key: str | None) -> None:
    if not key:
        raise ValueError(f"key parameter is required for {action_name} action")


def _validate_file_path(action_name: str, file_path: str | None) -> None:
    if not file_path:
        raise ValueError(f"file_path parameter is required for {action_name} action")


def _validate_selector(action_name: str, selector: str | None) -> None:
    if not selector:
        raise ValueError(f"selector parameter is required for {action_name} action")


def _resolve_action_name(
    action: str,
    coordinate: str | None = None,
    selector: str | None = None,
) -> str:
    action_name = (action or "").strip().strip('"').strip("'").strip().lower()

    alias_map = {
        "fill": "fill_selector",
        "input": "fill_selector",
        "type_selector": "fill_selector",
        "click_element": "click_selector",
        "tap_selector": "click_selector",
        "wait_selector": "wait_for_selector",
        "query_selector": "query_selector_all",
    }
    action_name = alias_map.get(action_name, action_name)

    if action_name == "click" and not coordinate and selector:
        return "click_selector"
    if action_name == "type" and selector:
        return "fill_selector"

    return action_name


def _handle_navigation_actions(
    manager: "BrowserTabManager",
    action: str,
    url: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action == "launch":
        return manager.launch_browser(url)
    if action == "goto":
        _validate_url(action, url)
        return manager.goto_url(url, tab_id)
    if action == "back":
        return manager.back(tab_id)
    if action == "forward":
        return manager.forward(tab_id)
    raise ValueError(f"Unknown navigation action: {action}")


def _handle_interaction_actions(
    manager: "BrowserTabManager",
    action: str,
    coordinate: str | None = None,
    text: str | None = None,
    key: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action in {"click", "double_click", "hover"}:
        _validate_coordinate(action, coordinate)
        action_map = {
            "click": manager.click,
            "double_click": manager.double_click,
            "hover": manager.hover,
        }
        return action_map[action](coordinate, tab_id)

    if action in {"scroll_down", "scroll_up"}:
        direction = "down" if action == "scroll_down" else "up"
        return manager.scroll(direction, tab_id)

    if action == "type":
        _validate_text(action, text)
        return manager.type_text(text, tab_id)
    if action == "press_key":
        _validate_key(action, key)
        return manager.press_key(key, tab_id)

    raise ValueError(f"Unknown interaction action: {action}")


def _raise_unknown_action(action: str) -> NoReturn:
    raise ValueError(f"Unknown action: {action}")


def _handle_tab_actions(
    manager: "BrowserTabManager",
    action: str,
    url: str | None = None,
    tab_id: str | None = None,
) -> dict[str, Any]:
    if action == "new_tab":
        return manager.new_tab(url)
    if action == "switch_tab":
        _validate_tab_id(action, tab_id)
        return manager.switch_tab(tab_id)
    if action == "close_tab":
        _validate_tab_id(action, tab_id)
        return manager.close_tab(tab_id)
    if action == "list_tabs":
        return manager.list_tabs()
    raise ValueError(f"Unknown tab action: {action}")


def _handle_utility_actions(
    manager: "BrowserTabManager",
    action: str,
    duration: float | None = None,
    js_code: str | None = None,
    file_path: str | None = None,
    tab_id: str | None = None,
    clear: bool = False,
) -> dict[str, Any]:
    if action == "wait":
        _validate_duration(action, duration)
        return manager.wait_browser(duration, tab_id)
    if action == "execute_js":
        _validate_js_code(action, js_code)
        return manager.execute_js(js_code, tab_id)
    if action == "save_pdf":
        _validate_file_path(action, file_path)
        return manager.save_pdf(file_path, tab_id)
    if action == "get_console_logs":
        return manager.get_console_logs(tab_id, clear)
    if action == "view_source":
        return manager.view_source(tab_id)
    if action == "close":
        return manager.close_browser()
    raise ValueError(f"Unknown utility action: {action}")


def _handle_selector_actions(
    manager: "BrowserTabManager",
    action: str,
    selector: str | None = None,
    text: str | None = None,
    tab_id: str | None = None,
    timeout: float | None = None,
    wait_state: str | None = None,
) -> dict[str, Any]:
    """Handle CSS selector-based browser actions."""
    _validate_selector(action, selector)

    # Default timeout is 5 seconds for most actions, 10 for wait_for_selector
    default_timeout = 10.0 if action == "wait_for_selector" else 5.0
    effective_timeout = timeout if timeout is not None else default_timeout

    if action == "click_selector":
        return manager.click_selector(selector, tab_id, effective_timeout)

    if action == "fill_selector":
        _validate_text(action, text)
        return manager.fill_selector(selector, text, tab_id, effective_timeout)

    if action == "wait_for_selector":
        effective_state = wait_state if wait_state else "visible"
        return manager.wait_for_selector(selector, tab_id, effective_timeout, effective_state)

    if action == "query_selector_all":
        return manager.query_selector_all(selector, tab_id)

    raise ValueError(f"Unknown selector action: {action}")


@register_tool(sandbox_execution=True)
def browser_action(
    action: BrowserAction,
    url: str | None = None,
    coordinate: str | None = None,
    text: str | None = None,
    tab_id: str | None = None,
    js_code: str | None = None,
    duration: float | None = None,
    key: str | None = None,
    file_path: str | None = None,
    clear: bool = False,
    # CSS Selector parameters
    selector: str | None = None,
    timeout: float | None = None,
    wait_state: str | None = None,
) -> dict[str, Any]:
    if not _PLAYWRIGHT_AVAILABLE:
        return {
            "error": "Playwright is not installed. Install with: pip install playwright",
            "tab_id": tab_id,
            "screenshot": "",
            "is_running": False,
        }

    from .tab_manager import get_browser_tab_manager

    manager = get_browser_tab_manager()
    resolved_action = _resolve_action_name(action, coordinate, selector)

    try:
        navigation_actions = {"launch", "goto", "back", "forward"}
        interaction_actions = {
            "click",
            "type",
            "double_click",
            "hover",
            "press_key",
            "scroll_down",
            "scroll_up",
        }
        tab_actions = {"new_tab", "switch_tab", "close_tab", "list_tabs"}
        utility_actions = {
            "wait",
            "execute_js",
            "save_pdf",
            "get_console_logs",
            "view_source",
            "close",
        }
        selector_actions = {
            "click_selector",
            "fill_selector",
            "wait_for_selector",
            "query_selector_all",
        }

        if resolved_action in navigation_actions:
            return _handle_navigation_actions(manager, resolved_action, url, tab_id)
        if resolved_action in interaction_actions:
            return _handle_interaction_actions(
                manager,
                resolved_action,
                coordinate,
                text,
                key,
                tab_id,
            )
        if resolved_action in tab_actions:
            return _handle_tab_actions(manager, resolved_action, url, tab_id)
        if resolved_action in utility_actions:
            return _handle_utility_actions(
                manager,
                resolved_action,
                duration,
                js_code,
                file_path,
                tab_id,
                clear,
            )
        if resolved_action in selector_actions:
            return _handle_selector_actions(
                manager,
                resolved_action,
                selector,
                text,
                tab_id,
                timeout,
                wait_state,
            )

        _raise_unknown_action(resolved_action)

    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "tab_id": tab_id,
            "screenshot": "",
            "is_running": False,
        }
