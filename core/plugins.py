"""OSINT EYE - Plugin System"""

import importlib
import importlib.util
import inspect
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from pathlib import Path


class BaseModule(ABC):
    """Base class for all OSINT EYE plugins"""

    name: str = "unnamed"
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    requires_api_key: bool = False

    @abstractmethod
    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the module against a target"""
        pass

    def get_info(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "requires_api_key": self.requires_api_key,
        }


class PluginManager:
    """Manage and load OSINT EYE plugins"""

    def __init__(self):
        self.plugins: Dict[str, BaseModule] = {}
        self._builtin_plugins = []

    def register(self, plugin: BaseModule):
        """Register a plugin instance"""
        self.plugins[plugin.name] = plugin

    def unregister(self, name: str):
        """Unregister a plugin"""
        if name in self.plugins:
            del self.plugins[name]

    def load_builtin(self):
        """Load all built-in modules"""
        from modules.dns import DNSScanner
        from modules.certs import CertScanner
        from modules.web import WaybackScanner
        from modules.web.web_scanner import WebScanner
        from modules.network import NetworkScanner
        from modules.osint import WhoisScanner, GitHubScanner, GoogleScanner
        from modules.osint.cloud_email import (
            CloudBucketDetector,
            EmailEnumerator,
            CDNDetector,
        )
        from modules.cve import CVEScanner

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
            self.plugins[name] = cls()

    def load_from_directory(self, plugin_dir: str):
        """Load plugins from a directory"""
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            return

        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            try:
                spec = importlib.util.spec_from_file_location(
                    py_file.stem, str(py_file)
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseModule) and obj != BaseModule:
                        instance = obj()
                        self.register(instance)
            except Exception as e:
                print(f"[!] Failed to load plugin {py_file}: {e}")

    def list_plugins(self) -> List[Dict]:
        """List all loaded plugins"""
        result = []
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

    def get_plugin(self, name: str) -> Optional[BaseModule]:
        """Get a plugin by name"""
        return self.plugins.get(name)

    def has_plugin(self, name: str) -> bool:
        return name in self.plugins


class PluginTemplate(BaseModule):
    """Template for creating new plugins"""

    name = "my_custom_scanner"
    description = "Custom scanner template"
    version = "1.0.0"
    author = "Your Name"
    requires_api_key = False

    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
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
