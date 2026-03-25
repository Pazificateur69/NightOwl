"""Dynamic plugin discovery and loading."""

import importlib
import logging
import pkgutil
from pathlib import Path

from nightowl.core.plugin_base import ScannerPlugin

logger = logging.getLogger("nightowl")


class PluginLoader:
    """Discovers and loads scanner plugins."""

    def __init__(self):
        self._plugins: dict[str, type[ScannerPlugin]] = {}

    def discover_builtin_plugins(self) -> dict[str, type[ScannerPlugin]]:
        """Scan nightowl/modules/ for built-in plugins."""
        import nightowl.modules as modules_pkg

        package_path = Path(modules_pkg.__file__).parent

        for _importer, modname, ispkg in pkgutil.walk_packages(
            [str(package_path)], prefix="nightowl.modules."
        ):
            if ispkg:
                continue
            try:
                module = importlib.import_module(modname)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ScannerPlugin)
                        and attr is not ScannerPlugin
                    ):
                        self._plugins[attr.name] = attr
                        logger.debug(f"Loaded builtin plugin: {attr.name}")
            except Exception as e:
                logger.warning(f"Failed to load module {modname}: {e}")

        return self._plugins

    def discover_external_plugins(self, path: str = "./plugins") -> dict[str, type[ScannerPlugin]]:
        """Scan external plugins directory."""
        plugins_dir = Path(path)
        if not plugins_dir.exists():
            return {}

        import sys
        sys.path.insert(0, str(plugins_dir.parent))

        for py_file in plugins_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            module_name = f"plugins.{py_file.stem}"
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ScannerPlugin)
                        and attr is not ScannerPlugin
                    ):
                        self._plugins[attr.name] = attr
                        logger.info(f"Loaded external plugin: {attr.name}")
            except Exception as e:
                logger.warning(f"Failed to load plugin {py_file.name}: {e}")

        return self._plugins

    def load_all(self, external_path: str = "./plugins") -> dict[str, type[ScannerPlugin]]:
        self.discover_builtin_plugins()
        self.discover_external_plugins(external_path)
        logger.info(f"Total plugins loaded: {len(self._plugins)}")
        return self._plugins

    def get_plugin(self, name: str) -> type[ScannerPlugin] | None:
        return self._plugins.get(name)

    def get_plugins_by_stage(self, stage: str) -> list[type[ScannerPlugin]]:
        return [p for p in self._plugins.values() if p.stage == stage]

    @property
    def all_plugins(self) -> dict[str, type[ScannerPlugin]]:
        return self._plugins
