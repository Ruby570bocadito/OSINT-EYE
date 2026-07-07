"""Core Module for OSINT EYE"""

from .correlator import AssetCorrelator
from .async_engine import AsyncSession, AsyncConfig, AsyncTaskRunner
from .session_cache import ScanCache, SessionManager
from .plugins import PluginManager, BaseModule, PluginTemplate
from .scan_diff import ScanDiff, AttackChainBuilder, BountyReporter

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
