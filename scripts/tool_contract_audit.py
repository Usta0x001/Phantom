#!/usr/bin/env python3
"""Audit Phantom tool contracts across runtime, XML, and code declarations.

Usage:
  python scripts/tool_contract_audit.py --mode default
  python scripts/tool_contract_audit.py --mode full
"""

from __future__ import annotations

import argparse
import ast
import inspect
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL_BLOCK_RE = re.compile(r'<tool\b[^>]*\bname="([^"]+)"[^>]*>(.*?)</tool>', re.DOTALL)

_INTERNAL_SIGNATURE_PARAMS: dict[str, set[str]] = {
    "finish_scan": {"state"},
    "terminal_execute": {"trusted_command"},
}


def _configure_mode(mode: str) -> None:
    if mode == "full":
        os.environ["PHANTOM_TOOL_SUBSET"] = "full"
    elif mode == "default":
        os.environ.pop("PHANTOM_TOOL_SUBSET", None)
    else:
        raise ValueError(f"unsupported mode: {mode}")


def _tools_root() -> Path:
    return Path(__file__).resolve().parent.parent / "phantom" / "tools"


def _collect_xml_declared_tools(tools_root: Path) -> tuple[set[str], list[str]]:
    names: set[str] = set()
    parse_errors: list[str] = []

    for schema_path in tools_root.rglob("*_schema.xml"):
        try:
            text = schema_path.read_text(encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            parse_errors.append(f"{schema_path.name}: {exc}")
            continue

        for match in _TOOL_BLOCK_RE.finditer(text):
            name = str(match.group(1)).strip()
            if name:
                names.add(name)

    return names, parse_errors


def _decorator_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _collect_python_declared_tools(tools_root: Path) -> tuple[set[str], list[str]]:
    names: set[str] = set()
    parse_errors: list[str] = []

    for py_path in tools_root.rglob("*.py"):
        if "__pycache__" in py_path.parts:
            continue
        try:
            source = py_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception as exc:  # noqa: BLE001
            parse_errors.append(f"{py_path.name}: {exc}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(_decorator_name(dec) == "register_tool" for dec in node.decorator_list):
                names.add(node.name)

    return names, parse_errors


def _collect_prompt_function_references(prompt_path: Path) -> set[str]:
    text = prompt_path.read_text(encoding="utf-8")
    refs = set(re.findall(r"<function=([a-zA-Z_][a-zA-Z0-9_]*)>", text))
    refs.update(re.findall(r"&lt;function=([a-zA-Z_][a-zA-Z0-9_]*)&gt;", text))
    return refs


def _signature_contract_errors(runtime_tools: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []

    from phantom.tools.registry import get_tool_param_schema

    for entry in runtime_tools:
        name = str(entry.get("name", "")).strip()
        if not name:
            errors.append("tool entry missing name")
            continue

        xml_schema = str(entry.get("xml_schema", "") or "")
        if "<tool" not in xml_schema:
            errors.append(f"{name}: missing xml schema")
            continue

        if "<description>" not in xml_schema:
            errors.append(f"{name}: missing compact description in runtime schema")

        param_schema = get_tool_param_schema(name) or {}
        xml_params = set(str(p) for p in param_schema.get("params", set()))
        xml_required = set(str(p) for p in param_schema.get("required", set()))

        fn = entry.get("function")
        if fn is None:
            errors.append(f"{name}: missing runtime function object")
            continue

        sig = inspect.signature(fn)
        sig_params: set[str] = set()
        sig_required: set[str] = set()
        has_var_kwargs = False

        for param_name, param in sig.parameters.items():
            if param_name == "agent_state":
                continue
            if param.kind == inspect.Parameter.VAR_KEYWORD:
                has_var_kwargs = True
                continue
            if param.kind == inspect.Parameter.VAR_POSITIONAL:
                continue

            sig_params.add(param_name)
            if param.default is inspect._empty:
                sig_required.add(param_name)

        if not has_var_kwargs:
            extra_xml = sorted(xml_params - sig_params)
            hidden = _INTERNAL_SIGNATURE_PARAMS.get(name, set())
            extra_sig = sorted((sig_params - xml_params) - hidden)
            if extra_xml:
                errors.append(f"{name}: xml params not in signature: {extra_xml}")
            if extra_sig:
                errors.append(f"{name}: signature params missing from xml: {extra_sig}")

        required_missing = sorted(sig_required - xml_required)
        required_over = sorted(xml_required - sig_required)
        if required_missing:
            errors.append(f"{name}: required params not marked required in xml: {required_missing}")
        if required_over and not has_var_kwargs:
            errors.append(f"{name}: xml required params not required by signature: {required_over}")

    return errors


def _run_audit_in_process(mode: str) -> dict[str, Any]:
    _configure_mode(mode)

    from phantom.tools.registry import get_tool_names, tools

    tools_root = _tools_root()
    prompt_path = Path(__file__).resolve().parent.parent / "phantom" / "agents" / "PhantomAgent" / "system_prompt.jinja"

    runtime_names = set(get_tool_names())
    runtime_entries = list(tools)
    xml_names, xml_parse_errors = _collect_xml_declared_tools(tools_root)
    py_names, py_parse_errors = _collect_python_declared_tools(tools_root)
    prompt_refs = _collect_prompt_function_references(prompt_path)

    errors: list[str] = []
    errors.extend(xml_parse_errors)
    errors.extend(py_parse_errors)

    if len(runtime_names) != len(runtime_entries):
        errors.append(
            f"runtime duplicate-name mismatch: get_tool_names={len(runtime_names)} entries={len(runtime_entries)}"
        )

    errors.extend(_signature_contract_errors(runtime_entries))

    runtime_not_in_xml = sorted(runtime_names - xml_names)
    xml_not_in_py = sorted(xml_names - py_names)
    prompt_not_runtime = sorted(prompt_refs - runtime_names)

    if runtime_not_in_xml:
        errors.append(f"runtime tools missing xml declaration: {runtime_not_in_xml}")
    if xml_not_in_py:
        errors.append(f"xml tools missing @register_tool function: {xml_not_in_py}")
    if prompt_not_runtime:
        errors.append(f"prompt references non-runtime tools: {prompt_not_runtime}")

    return {
        "mode": mode,
        "runtime_count": len(runtime_names),
        "python_declared_count": len(py_names),
        "xml_declared_count": len(xml_names),
        "prompt_function_refs_count": len(prompt_refs),
        "runtime_not_in_xml": runtime_not_in_xml,
        "xml_not_in_runtime": sorted(xml_names - runtime_names),
        "python_not_in_runtime": sorted(py_names - runtime_names),
        "prompt_not_runtime": prompt_not_runtime,
        "errors": errors,
    }


def run_audit(mode: str) -> dict[str, Any]:
    script_path = Path(__file__).resolve()
    env = os.environ.copy()
    existing_path = env.get("PYTHONPATH", "")
    root_path = str(_ROOT)
    env["PYTHONPATH"] = (
        f"{root_path}{os.pathsep}{existing_path}" if existing_path else root_path
    )

    proc = subprocess.run(
        [sys.executable, str(script_path), "--mode", mode, "--json"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())

    return json.loads(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Phantom tool contracts")
    parser.add_argument("--mode", choices=["default", "full"], default="default")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = _run_audit_in_process(args.mode)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"mode={report['mode']} runtime={report['runtime_count']} xml={report['xml_declared_count']} python={report['python_declared_count']}")
        if report["errors"]:
            print("errors:")
            for err in report["errors"]:
                print(f"- {err}")

    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
