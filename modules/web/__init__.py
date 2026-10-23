"""Web Module for OSINT EYE"""

from .wayback import WaybackMachine, WaybackScanner
from .web_scanner import (
    EndpointDiscovery,
    SensitiveDataDetector,
    TechDetector,
    WebScanner,
)

__all__ = [
    "WaybackMachine",
    "WaybackScanner",
    "TechDetector",
    "EndpointDiscovery",
    "SensitiveDataDetector",
    "WebScanner",
]
