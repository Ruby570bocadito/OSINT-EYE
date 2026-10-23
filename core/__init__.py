"""Core Module for OSINT EYE"""

# Fuente única de la versión del paquete (tarea version-unica):
# pyproject.toml la deriva vía [tool.setuptools.dynamic] attr y el banner de la
# CLI la importa. No duplicar el literal en otros ficheros.
__version__ = "2.1.1"

from .async_engine import AsyncConfig, AsyncSession, AsyncTaskRunner
from .correlator import AssetCorrelator
from .plugins import BaseModule, PluginManager, PluginTemplate
from .scan_diff import AttackChainBuilder, BountyReporter, ScanDiff
from .session_cache import ScanCache, SessionManager

__all__ = [
    "AssetCorrelator",
    "AsyncSession",
    "AsyncConfig",
    "AsyncTaskRunner",
    "ScanCache",
    "SessionManager",
    "PluginManager",
    "BaseModule",
    "PluginTemplate",
    "ScanDiff",
    "AttackChainBuilder",
    "BountyReporter",
]
