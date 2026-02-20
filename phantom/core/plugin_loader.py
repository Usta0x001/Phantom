"""Lightweight plugin system for user-extensible tool adapters.

Plugins are Python modules placed in ``~/.phantom/plugins/`` or a custom
directory.  Each plugin must expose a ``register(registry)`` function.

Usage::

    from phantom.core.plugin_loader import PluginLoader

    loader = PluginLoader()        # scans ~/.phantom/plugins/
    loader.discover()              # finds .py files
    loader.load_all()              # imports & calls register()
    print(loader.loaded_plugins)   # [PluginInfo(...), ...]
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

_logger = logging.getLogger(__name__)

_DEFAULT_PLUGIN_DIR = Path.home() / ".phantom" / "plugins"
_PLUGINS_ENABLED_ENV = "PHANTOM_ENABLE_PLUGINS"


@dataclass
class PluginInfo:
    """Metadata for a loaded plugin."""

    name: str
    path: str
    version: str = "0.0.0"
    description: str = ""
    loaded_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error: str | None = None


class PluginLoader:
    """Discover and load Phantom plugins from a directory.

    Lifecycle::

        loader = PluginLoader("/path/to/plugins")
        loader.discover()
        loader.load_all()
    """

    def __init__(self, plugin_dir: str | Path | None = None) -> None:
        self.plugin_dir = Path(plugin_dir) if plugin_dir else _DEFAULT_PLUGIN_DIR
        self._discovered: list[Path] = []
        self._loaded: list[PluginInfo] = []
        self._registry_hooks: list[Callable[..., Any]] = []

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self) -> list[Path]:
        """Scan plugin directory for ``.py`` files.  Returns list of paths."""
        self._discovered = []
        if not self.plugin_dir.is_dir():
            _logger.debug("Plugin directory does not exist: %s", self.plugin_dir)
            return []

        for p in sorted(self.plugin_dir.glob("*.py")):
            if p.name.startswith("_"):
                continue
            self._discovered.append(p)
            _logger.debug("Discovered plugin: %s", p.name)

        return list(self._discovered)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_all(self, registry: Any = None) -> list[PluginInfo]:
        """Import every discovered plugin and call its ``register()`` hook.

        Requires ``PHANTOM_ENABLE_PLUGINS=1`` environment variable to be set.

        Parameters:
            registry:  An object passed to each plugin's ``register()``
                       function (typically the tool registry).

        Returns:
            List of ``PluginInfo`` for successfully loaded plugins.
        """
        if os.getenv(_PLUGINS_ENABLED_ENV) != "1":
            _logger.info(
                "Plugin loading disabled. Set %s=1 to enable.",
                _PLUGINS_ENABLED_ENV,
            )
            return []

        if not self._discovered:
            self.discover()

        if self._discovered:
            _logger.warning(
                "SECURITY: Loading %d plugin(s) from %s — "
                "plugins run with full process privileges.",
                len(self._discovered),
                self.plugin_dir,
            )

        for plugin_path in self._discovered:
            info = self._load_one(plugin_path, registry)
            self._loaded.append(info)

        return [p for p in self._loaded if p.error is None]

    def _load_one(self, path: Path, registry: Any) -> PluginInfo:
        module_name = f"phantom_plugin_{path.stem}"
        info = PluginInfo(name=path.stem, path=str(path))

        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                info.error = "Could not create module spec"
                return info

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            # Only register after successful exec
            sys.modules[module_name] = module

            # Extract optional metadata
            info.version = getattr(module, "__version__", "0.0.0")
            info.description = getattr(module, "__description__", "")

            # Call register() hook
            register_fn = getattr(module, "register", None)
            if callable(register_fn):
                register_fn(registry)
                _logger.info("Loaded plugin: %s v%s", info.name, info.version)
            else:
                _logger.warning("Plugin %s has no register() function", info.name)
                info.error = "Missing register() function"

        except Exception as exc:
            info.error = str(exc)
            _logger.error("Failed to load plugin %s: %s", path.name, exc)

        return info

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def loaded_plugins(self) -> list[PluginInfo]:
        return [p for p in self._loaded if p.error is None]

    @property
    def failed_plugins(self) -> list[PluginInfo]:
        return [p for p in self._loaded if p.error is not None]

    @property
    def discovered_count(self) -> int:
        return len(self._discovered)

    def get_plugin(self, name: str) -> PluginInfo | None:
        for p in self._loaded:
            if p.name == name:
                return p
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "plugin_dir": str(self.plugin_dir),
            "discovered": self.discovered_count,
            "loaded": len(self.loaded_plugins),
            "failed": len(self.failed_plugins),
            "plugins": [
                {"name": p.name, "version": p.version, "error": p.error}
                for p in self._loaded
            ],
        }
