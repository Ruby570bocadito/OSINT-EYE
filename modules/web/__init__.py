"""Web Module for OSINT EYE"""

from .wayback import WaybackMachine, WaybackScanner
from .web_scanner import (
    TechDetector,
    EndpointDiscovery,
    SensitiveDataDetector,
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
