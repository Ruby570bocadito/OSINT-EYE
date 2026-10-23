"""Tests for the dashboard light/dark theme (prefers-color-scheme).

All offline: the template is asserted directly and through the real Flask
route (test client). No network, no browser needed.
"""

import pytest


@pytest.fixture()
def dashboard():
    from ui import dashboard

    dashboard.SCAN_RESULTS.clear()
    dashboard.SCAN_HISTORY.clear()
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


class TestLightThemeDeclaration:
    def test_media_query_declared(self, template_html):
        assert "@media (prefers-color-scheme: light)" in template_html

    def test_light_overrides_core_tokens(self, template_html):
        start = template_html.index("@media (prefers-color-scheme: light)")
        block = template_html[start:start + 900]
        for token in (
            "--bg: #F7F8FA",
            "--surface: #FFFFFF",
            "--text: #1B1E26",
            "--accent: #3A6CDB",
            "--topbar-bg: rgba(255, 255, 255, 0.85)",
        ):
            assert token in block, token

    def test_dark_tokens_stay_the_default(self, template_html):
        root = template_html[template_html.index(":root {"):
                             template_html.index("@media")]
        assert "--bg: #0A0B0E" in root
        assert "--text: #E8EAF0" in root

    def test_color_scheme_follows_preference(self, template_html):
        assert "html { color-scheme: dark; }" in template_html
        light_block = template_html[
            template_html.index("@media (prefers-color-scheme: light)"):]
        assert "color-scheme: light" in light_block


class TestHardcodedColorRegressions:
    def test_topbar_uses_token_not_rgba(self, template_html):
        assert "background: var(--topbar-bg);" in template_html
        # the rgba value may only appear as the dark token definition,
        # never as an inline background property
        assert "background: rgba(10, 11, 14, 0.88)" not in template_html

    def test_no_undefined_panel_bg_var(self, template_html):
        # --panel-bg never existed in :root: the timeline dot silently fell
        # back to a hardcoded dark ring in every theme.
        assert "var(--panel-bg" not in template_html

    def test_graph_export_reads_computed_tokens(self, template_html):
        assert 'cssVar("--border-strong"' in template_html
        assert 'cssVar("--muted"' in template_html


class TestServedTemplate:
    def test_route_serves_theme(self, client):
        html = client.get("/").get_data(as_text=True)
        assert "prefers-color-scheme: light" in html
        assert "var(--topbar-bg)" in html

    def test_theme_added_no_external_resources(self, client):
        html = client.get("/").get_data(as_text=True)
        assert "cdn." not in html
        assert "<script src=" not in html and 'href="http' not in html
