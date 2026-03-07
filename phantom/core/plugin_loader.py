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

import hashlib
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
# V2-ARCH-005: Path to directory containing Ed25519 .sig files for plugins
_PLUGIN_SIG_DIR_ENV = "PHANTOM_PLUGIN_SIG_DIR"
# V2-ARCH-005: Ed25519 public key for plugin signature verification
_PLUGIN_PUBKEY_ENV = "PHANTOM_PLUGIN_PUBKEY"


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
        """Scan plugin directory for ``.py`` files.  Returns list of paths.

        PHT-013 FIX: Validates that discovered files:
        - Are not symlinks (prevents symlink-based escapes)
        - Resolve to within the plugin directory (prevents path traversal)
        - Are regular files (not devices, pipes, etc.)
        """
        self._discovered = []
        if not self.plugin_dir.is_dir():
            _logger.debug("Plugin directory does not exist: %s", self.plugin_dir)
            return []

        real_base = self.plugin_dir.resolve()

        for p in sorted(self.plugin_dir.glob("*.py")):
            if p.name.startswith("_"):
                continue

            # PHT-013 FIX: reject symlinks
            if p.is_symlink():
                _logger.warning("Skipping symlink plugin: %s", p)
                continue

            # PHT-013 FIX: reject path traversal (resolved path must stay inside plugin dir)
            # HIGH-24 FIX: Use is_relative_to() instead of string prefix check
            try:
                real_path = p.resolve(strict=True)
                if not real_path.is_relative_to(real_base):
                    _logger.warning("Skipping plugin outside plugin dir: %s -> %s", p, real_path)
                    continue
            except OSError as exc:
                _logger.warning("Skipping unresolvable plugin: %s (%s)", p, exc)
                continue

            # PHT-013 FIX: must be a regular file
            if not real_path.is_file():
                _logger.warning("Skipping non-regular plugin file: %s", p)
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
            # V2-ARCH-005: Verify Ed25519 signature before executing plugin code
            if not self._verify_signature(path):
                info.error = "Signature verification failed"
                _logger.error(
                    "SECURITY: Plugin %s failed signature verification — refusing to load",
                    path.name,
                )
                return info

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

    # ------------------------------------------------------------------
    # Signature Verification (V2-ARCH-005)
    # ------------------------------------------------------------------

    @staticmethod
    def _verify_signature(plugin_path: Path) -> bool:
        """Verify Ed25519 signature of a plugin file.

        Looks for a .sig file alongside the plugin (or in PHANTOM_PLUGIN_SIG_DIR).
        If no public key is configured, verification is skipped with a warning.
        """
        pubkey_hex = os.getenv(_PLUGIN_PUBKEY_ENV)
        if not pubkey_hex:
            _logger.warning(
                "No plugin signing key configured (%s not set) — "
                "skipping signature verification for %s",
                _PLUGIN_PUBKEY_ENV, plugin_path.name,
            )
            return True  # Degrade gracefully — warn but allow

        # Locate .sig file
        sig_dir = os.getenv(_PLUGIN_SIG_DIR_ENV)
        if sig_dir:
            sig_path = Path(sig_dir) / f"{plugin_path.name}.sig"
        else:
            sig_path = plugin_path.with_suffix(".py.sig")

        if not sig_path.is_file():
            _logger.error(
                "Plugin %s has no signature file at %s",
                plugin_path.name, sig_path,
            )
            return False

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
            plugin_bytes = plugin_path.read_bytes()
            sig_bytes = sig_path.read_bytes()
            pub_key.verify(sig_bytes, plugin_bytes)
            _logger.info("Plugin %s signature verified", plugin_path.name)
            return True
        except ImportError:
            _logger.error(
                "cryptography library not available — cannot verify plugin signatures"
            )
            return False
        except Exception as exc:
            _logger.error(
                "Plugin %s signature verification failed: %s",
                plugin_path.name, exc,
            )
            return False
