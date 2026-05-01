import json
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any, cast

from phantom.tools.registry import register_tool


WORKSPACE_ROOT = PurePosixPath("/workspace")


def _validate_workspace_path(path: str) -> str:
    """Resolve and validate that a path stays within /workspace.

    Rejects symlinks that escape the workspace boundary, '..' traversal,
    and absolute paths outside /workspace.
    """
    normalized = path.replace("\\", "/").strip()
    posix_path = PurePosixPath(normalized)

    if posix_path.is_absolute():
        if not str(posix_path).startswith("/workspace"):
            raise ValueError(
                f"Path traversal blocked: resolved path '{posix_path}' is outside /workspace"
            )
        candidate = posix_path
    else:
        candidate = WORKSPACE_ROOT / posix_path

    if ".." in candidate.parts:
        raise ValueError(f"Path traversal blocked: '{path}' contains parent traversal")

    return str(candidate)


def _parse_file_editor_output(output: str) -> dict[str, Any]:
    try:
        pattern = r"<oh_aci_output_[^>]+>\n(.*?)\n</oh_aci_output_[^>]+>"
        match = re.search(pattern, output, re.DOTALL)

        if match:
            json_str = match.group(1)
            data = json.loads(json_str)
            return cast("dict[str, Any]", data)
        return {"output": output, "error": None}
    except (json.JSONDecodeError, AttributeError):
        return {"output": output, "error": None}


@register_tool
def str_replace_editor(
    command: str,
    path: str,
    file_text: str | None = None,
    view_range: list[int] | None = None,
    old_str: str | None = None,
    new_str: str | None = None,
    insert_line: int | None = None,
) -> dict[str, Any]:
    from openhands_aci import file_editor

    try:
        path = _validate_workspace_path(path)

        result = file_editor(
            command=command,
            path=path,
            file_text=file_text,
            view_range=view_range,
            old_str=old_str,
            new_str=new_str,
            insert_line=insert_line,
        )

        parsed = _parse_file_editor_output(result)

        if parsed.get("error"):
            return {"error": parsed["error"]}

        return {"content": parsed.get("output", result)}

    except (OSError, ValueError) as e:
        return {"error": f"Error in {command} operation: {e!s}"}


@register_tool
def list_files(
    path: str,
    recursive: bool = False,
) -> dict[str, Any]:
    from openhands_aci.utils.shell import run_shell_cmd

    try:
        path = _validate_workspace_path(path)
        safe_path = shlex.quote(path)
        cmd = f"find {safe_path} -type f -o -type d | head -500" if recursive else f"ls -1a {safe_path}"

        exit_code, stdout, stderr = run_shell_cmd(cmd)

        if exit_code != 0:
            return {"error": f"Error listing directory: {stderr}"}

        items = stdout.strip().split("\n") if stdout.strip() else []

        files = []
        dirs = []

        for item in items:
            if item in {".", ".."}:
                continue

            if "." in item and not item.endswith("/"):
                files.append(item)
            else:
                dirs.append(item)

        return {
            "files": sorted(files),
            "directories": sorted(dirs),
            "total_files": len(files),
            "total_dirs": len(dirs),
            "path": path,
            "recursive": recursive,
        }

    except (OSError, ValueError) as e:
        return {"error": f"Error listing directory: {e!s}"}


@register_tool
def search_files(
    path: str,
    regex: str,
    file_pattern: str = "*",
) -> dict[str, Any]:
    from openhands_aci.utils.shell import run_shell_cmd

    try:
        path = _validate_workspace_path(path)

        if not Path(path).exists():
            return {"error": f"Directory not found: {path}"}

        safe_path = shlex.quote(path)
        safe_regex = shlex.quote(regex)
        safe_pattern = shlex.quote(file_pattern)

        cmd = f"rg --line-number --max-count 500 --glob {safe_pattern} {safe_regex} {safe_path}"

        exit_code, stdout, stderr = run_shell_cmd(cmd)

        if exit_code not in {0, 1}:
            return {"error": f"Error searching files: {stderr}"}
        return {"output": stdout if stdout else "No matches found"}

    except (OSError, ValueError) as e:
        return {"error": f"Error searching files: {e!s}"}


# ruff: noqa: TRY300
