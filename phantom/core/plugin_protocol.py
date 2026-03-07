"""
Plugin Protocol Definitions

Architecture Improvement 8: Plugin system for tools, intelligence modules,
and output formatters.

Uses ``typing.Protocol`` with ``@runtime_checkable`` so that third-party
packages can implement these interfaces without subclassing.

NOTE: These protocols define the future plugin API but are not yet consumed
by any runtime code. They are ready for integration once the plugin loader
is wired into the agent loop (see Plugin Roadmap in docs/).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ToolPlugin(Protocol):
    """Protocol for pluggable tool implementations.

    A ToolPlugin wraps an external security tool (scanner, exploit
    framework, etc.) and exposes it to the Phantom agent loop.
    """

    @property
    def name(self) -> str:
        """Unique tool identifier (e.g., 'nmap_scan')."""
        ...

    @property
    def description(self) -> str:
        """Short human-readable description."""
        ...

    @property
    def phase(self) -> str:
        """Scan phase this tool belongs to (e.g., 'reconnaissance')."""
        ...

    async def execute(self, params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        """Run the tool with the given parameters.

        Args:
            params: Tool-specific parameters.
            context: Execution context (state, scope, etc.).

        Returns:
            Result dict with standardized keys.
        """
        ...

    def validate_params(self, params: dict[str, Any]) -> list[str]:
        """Return a list of validation errors (empty if valid)."""
        ...


@runtime_checkable
class IntelligencePlugin(Protocol):
    """Protocol for pluggable intelligence modules.

    Intelligence plugins provide strategic analysis that feeds into
    the planning and decision-making loop.
    """

    @property
    def name(self) -> str:
        ...

    def analyze(self, state: Any, graph: Any) -> dict[str, Any]:
        """Analyze current state and return intelligence insights.

        Returns a dict with at least:
            {"recommendations": [...], "confidence": float}
        """
        ...


@runtime_checkable
class OutputPlugin(Protocol):
    """Protocol for pluggable output / report formatters.

    Output plugins transform scan results into a specific format
    (HTML, PDF, JSON, SARIF, etc.).
    """

    @property
    def format_name(self) -> str:
        """Output format identifier (e.g., 'html', 'sarif')."""
        ...

    def render(self, report_data: dict[str, Any]) -> bytes:
        """Render the report data into the target format.

        Returns raw bytes of the rendered output.
        """
        ...

    @property
    def file_extension(self) -> str:
        """File extension for the output (e.g., '.html', '.json')."""
        ...
