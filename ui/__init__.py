"""UI Module for OSINT EYE"""

from .rich_cli import RichCLI
from .dashboard import app, load_scan_results, start_dashboard
from .tui_app import OSINTEyeTUI, launch_tui

__all__ = [
    "RichCLI",
    "app",
    "load_scan_results",
    "start_dashboard",
    "OSINTEyeTUI",
    "launch_tui",
]
