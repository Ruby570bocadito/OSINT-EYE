"""OSINT EYE - Plugin System"""

import importlib.util
import inspect
import sys
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseModule(ABC):
    """Base class for all OSINT EYE plugins"""

    name: str = "unnamed"
    description: str = ""
    version: str = "1.0.0"
    author: str = "built-in"
    requires_api_key: bool = False

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Execute the module against a target"""
        raise NotImplementedError

    def get_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "requires_api_key": self.requires_api_key,
        }


class _UnavailableBuiltin:
    """Placeholder registered when a built-in module cannot be instantiated.

    Keeps ``has_plugin()`` truthful about the registry (e.g. "network" exists)
    even when its runtime dependency is missing (e.g. the nmap binary).
    """

    def __init__(self, name: str, reason: str):
        self.name = name
        self.description = f"Unavailable built-in module: {reason}"
        self.version = "1.0.0"
        self.author = "built-in"
        self.requires_api_key = False
        self._reason = reason

    def get_info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "requires_api_key": self.requires_api_key,
        }

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "target": target,
            "error": f"Module '{self.name}' is unavailable: {self._reason}",
            "unavailable": True,
        }


class PluginManager:
    """Manage and load OSINT EYE plugins"""

    def __init__(self) -> None:
        self.plugins: dict[str, Any] = {}
        self._builtin_plugins: list[Any] = []

    def register(self, plugin: Any) -> None:
        """Register a plugin instance (must expose ``name`` and ``run``)"""
        name = getattr(plugin, "name", None)
        if not name or not callable(getattr(plugin, "run", None)):
            print(
                f"[!] Skipped invalid plugin "
                f"{type(plugin).__name__} (missing 'name' or 'run')"
            )
            return
        self.plugins[name] = plugin

    def unregister(self, name: str) -> None:
        """Unregister a plugin"""
        if name in self.plugins:
            del self.plugins[name]

    def load_builtin(self) -> None:
        """Load all built-in modules.

        A built-in whose constructor fails (e.g. NetworkScanner without the
        nmap binary installed) no longer aborts the whole load: it is replaced
        by an ``_UnavailableBuiltin`` stub so ``has_plugin()`` stays accurate.
        """
        from modules.certs import CertScanner
        from modules.cve import CVEScanner
        from modules.dns import DNSScanner
        from modules.network import NetworkScanner
        from modules.osint import GitHubScanner, GoogleScanner, WhoisScanner
        from modules.osint.cloud_email import (
            CDNDetector,
            CloudBucketDetector,
            EmailEnumerator,
        )
        from modules.web import WaybackScanner
        from modules.web.web_scanner import WebScanner

        builtin_wrappers = {
            "dns": DNSScanner,
            "certs": CertScanner,
            "wayback": WaybackScanner,
            "web": WebScanner,
            "network": NetworkScanner,
            "whois": WhoisScanner,
            "github": GitHubScanner,
            "google": GoogleScanner,
            "cloud": CloudBucketDetector,
            "emails": EmailEnumerator,
            "cdn_waf": CDNDetector,
            "cve": CVEScanner,
        }

        for name, cls in builtin_wrappers.items():
            try:
                self.plugins[name] = cls()
            except Exception as e:
                reason = str(e) or type(e).__name__
                print(f"[!] Built-in '{name}' unavailable: {reason}")
                self.plugins[name] = _UnavailableBuiltin(name, reason)

    def load_from_directory(self, plugin_dir: str) -> None:
        """Load plugins from a directory.

        Broken plugin files (syntax errors, missing imports, bad classes) are
        reported and skipped without aborting the remaining plugins.
        """
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists() or not plugin_path.is_dir():
            return

        for py_file in sorted(plugin_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            # Unique module name prevents collisions between plugin files and
            # real packages sharing a stem.
            module_name = f"osint_eye_plugin_{uuid.uuid4().hex[:8]}_{py_file.stem}"

            try:
                spec = importlib.util.spec_from_file_location(
                    module_name, str(py_file)
                )
                if spec is None or spec.loader is None:
                    print(f"[!] Failed to load plugin {py_file}: no import spec")
                    continue

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                loaded = 0
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if not issubclass(obj, BaseModule) or obj is BaseModule:
                        continue
                    try:
                        instance = obj()
                    except Exception as e:
                        print(f"[!] Failed to instantiate {obj.__name__}: {e}")
                        continue
                    self.register(instance)
                    loaded += 1

                if loaded == 0:
                    print(f"[!] No BaseModule subclasses found in {py_file}")

            except Exception as e:
                print(f"[!] Failed to load plugin {py_file}: {e}")
            finally:
                # Never leave broken modules registered under sys.modules.
                sys.modules.pop(module_name, None)

    def list_plugins(self) -> list[dict[str, Any]]:
        """List all loaded plugins"""
        result: list[dict[str, Any]] = []
        for name, p in self.plugins.items():
            if hasattr(p, "get_info"):
                result.append({**p.get_info(), "loaded": True})
            else:
                result.append(
                    {
                        "name": name,
                        "description": type(p).__name__,
                        "version": "1.0.0",
                        "author": "built-in",
                        "requires_api_key": False,
                        "loaded": True,
                    }
                )
        return result

    def get_plugin(self, name: str) -> Any | None:
        """Get a plugin by name"""
        return self.plugins.get(name)

    def has_plugin(self, name: str) -> bool:
        return name in self.plugins


class PluginTemplate(BaseModule):
    """Template for creating new plugins"""

    name = "my_custom_scanner"
    description = "Custom scanner template"
    version = "1.0.0"
    author = "built-in"
    requires_api_key = False

    async def run(self, target: str, **kwargs: Any) -> dict[str, Any]:
        """Implement your scanning logic here"""
        results = {
            "target": target,
            "findings": [],
            "metadata": {},
        }

        # Your scanning logic
        # Example:
        # import aiohttp
        # async with aiohttp.ClientSession() as session:
        #     async with session.get(f"https://{target}") as resp:
        #         results["status"] = resp.status

        return results


if __name__ == "__main__":
    pm = PluginManager()
    pm.load_builtin()

    print("Loaded plugins:")
    for plugin in pm.list_plugins():
        print(f"  - {plugin['name']}: {plugin['description']}")
