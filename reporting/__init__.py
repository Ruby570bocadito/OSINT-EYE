"""Reporting Module for OSINT EYE"""

from .export import CSVExporter, HTMLReporter
from .export_tools import BurpExporter, ConfigProfiles, MetasploitExporter
from .markdown_reporter import MarkdownReporter
from .mitre_mapper import MitreMapper

__all__ = [
    "MarkdownReporter",
    "MitreMapper",
    "CSVExporter",
    "HTMLReporter",
    "PDFReporter",
    "BurpExporter",
    "MetasploitExporter",
    "ConfigProfiles",
]


def __getattr__(name):
    # PDFReporter pulls in reportlab (the [pdf] extra): import it only when
    # actually requested so `import reporting` stays cheap for installs
    # without the extra (PUL-1 packaging request).
    if name == "PDFReporter":
        from .pdf_reporter import PDFReporter

        return PDFReporter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
