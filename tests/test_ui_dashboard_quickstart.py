"""Tests for the dashboard quickstart panel (dashboard-vacio-guiado).

When the dashboard has no scans — or only demo data — a guidance panel must
offer the exact CLI commands that produce real data. All offline: template
assertions plus the real Flask route.
"""

import pytest


@pytest.fixture()
def dashboard():
    from ui import dashboard

    dashboard.SCAN_RESULTS.clear()
    dashboard.SCAN_HISTORY.clear()
    dashboard.SCAN_ARCHIVE.clear()
    dashboard.LAST_LOAD_WARNING = None
    return dashboard


@pytest.fixture()
def client(dashboard):
    return dashboard.app.test_client()


@pytest.fixture()
def template_html() -> str:
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "ui" / "dashboard_template.html"
    return path.read_text(encoding="utf-8")


class TestQuickstartPanel:
    def test_panel_declared_hidden(self, template_html):
        assert '<section class="quickstart" id="quickstart" hidden>' \
            in template_html
        assert 'id="qs-commands"' in template_html

    def test_three_exact_cli_commands(self, template_html):
        for cmd in (
            "python osint_eye.py example.com --dashboard",
            "python osint_eye.py example.com --dashboard --monitor",
            "python osint_eye.py example.com --rich",
        ):
            assert cmd in template_html, cmd

    def test_demo_detection_logic_present(self, template_html):
        assert "function maybeShowQuickstart" in template_html
        assert "s.demo" in template_html

    def test_copy_uses_clipboard_api_and_addlistener(self, template_html):
        assert "navigator.clipboard.writeText" in template_html
        # CSP-safe: no inline handlers anywhere
        assert "onclick=" not in template_html

    def test_route_serves_panel(self, client):
        html = client.get("/").get_data(as_text=True)
        for marker in ("id=\"quickstart\"", "id=\"qs-commands\"",
                       "maybeShowQuickstart", "qs-copy"):
            assert marker in html, marker

    def test_no_external_resources_added(self, client):
        html = client.get("/").get_data(as_text=True)
        assert "cdn." not in html
        assert "<script src=" not in html and 'href="http' not in html
