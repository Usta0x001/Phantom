from __future__ import annotations

import argparse

import pytest

from phantom.interface.tui import PhantomTUIApp


@pytest.mark.asyncio
async def test_tui_app_starts_without_css_parse_errors() -> None:
    import os

    os.environ.setdefault("PHANTOM_LLM", "openai/gpt-4o-mini")
    os.environ.setdefault("LLM_API_KEY", "sk-fake-for-unit-tests")

    args = argparse.Namespace(
        run_name="css-smoke",
        targets_info=[
            {
                "type": "web",
                "details": {"target_url": "https://estin.dz"},
                "original": "estin.dz",
            }
        ],
        instruction="focus on high bugs only",
        scan_mode="deep",
        resume_run=None,
        profile_max_iterations=None,
        local_sources=[],
    )

    app = PhantomTUIApp(args)
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
