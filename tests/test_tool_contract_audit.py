import json
import subprocess
import sys


def _run(mode: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "scripts/tool_contract_audit.py", "--mode", mode, "--json"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return json.loads(proc.stdout)


def test_tool_contract_audit_default_mode_has_no_errors() -> None:
    report = _run("default")
    assert report["runtime_count"] > 0
    assert report["xml_declared_count"] >= report["runtime_count"]
    assert not report["errors"]


def test_tool_contract_audit_full_mode_has_no_errors() -> None:
    report = _run("full")
    assert report["runtime_count"] >= 80
    assert report["xml_declared_count"] >= report["runtime_count"]
    assert not report["errors"]


def test_runtime_schemas_include_description_and_example() -> None:
    report = _run("full")
    assert not report["errors"]
