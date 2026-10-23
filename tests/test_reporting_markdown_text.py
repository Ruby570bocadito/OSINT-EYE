"""Tests for MarkdownReporter.build_text() (in-memory report) — offline.

Covers the IMP-2 request: the report must be obtainable as TEXT without
writing any file, byte-for-byte identical to what generate() writes.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporting.markdown_reporter import MarkdownReporter  # noqa: E402


RESULTS = {
    "target": "example.com",
    "scan_date": "2026-10-23T12:00:00",
    "depth": "normal",
    "modules": {
        "dns": {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "records": {"A": ["93.184.216.34"]},
        },
        "network": {
            "host": "example.com",
            "services": [
                {"port": 443, "state": "open", "service": "https", "version": ""}
            ],
        },
    },
    "correlation": {
        "attack_surface_score": {"score": 42, "severity": "MEDIUM", "factors": []},
        "attack_graph": {"stats": {"total_nodes": 5, "total_edges": 4}},
    },
}


class TestBuildText:
    def test_report_as_text_without_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        reporter = MarkdownReporter()
        reporter.load_results(RESULTS)
        text = reporter.build_text()

        assert isinstance(text, str) and text.strip()
        assert "example.com" in text
        assert "www.example.com" in text
        # No file must have been created by build_text()
        assert not list(tmp_path.iterdir())

    def test_build_text_matches_generate_byte_for_byte(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        text_reporter = MarkdownReporter()
        text_reporter.load_results(RESULTS)
        text = text_reporter.build_text()

        file_reporter = MarkdownReporter()
        file_reporter.load_results(RESULTS)
        path = file_reporter.generate(str(tmp_path / "report.md"))

        with open(path, encoding="utf-8") as handle:
            assert handle.read() == text

    def test_empty_results_still_render(self):
        reporter = MarkdownReporter()
        assert isinstance(reporter.build_text(), str)
