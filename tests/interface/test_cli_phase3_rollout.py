from __future__ import annotations

from typer.testing import CliRunner

from phantom.config.config import Config
from phantom.interface.cli_app import app


runner = CliRunner()


def test_scan_help_includes_preset_and_ui_flags() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--preset" in result.stdout
    assert "--ui" in result.stdout


def test_doctor_command_runs() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "CLI Doctor" in result.stdout


def test_phase5_rollout_default_config_var_present() -> None:
    tracked = Config.tracked_vars()
    assert "PHANTOM_TUI_VARIANT" in tracked
