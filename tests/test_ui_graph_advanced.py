"""Static-contract tests for the advanced graph panel (grafo-avanzado).

The graph is pure client-side JS inside the dashboard template; these
offline tests assert the template contract: toolbar present, filter/search/
attack-path/export wiring, inline SVG styles for standalone export, no CDN
and no innerHTML-based rendering (XSS-safe rendering contract).
"""

import pytest


@pytest.fixture()
def dashboard():
    from ui import dashboard

    dashboard.SCAN_RESULTS.clear()
    dashboard.SCAN_HISTORY.clear()
    dashboard.SCAN_ARCHIVE.clear()
    return dashboard


@pytest.fixture()
def html(dashboard):
    return dashboard._template()


class TestGraphToolbar:
    def test_toolbar_elements_present(self, html):
        for marker in (
            'id="g-search"',
            'id="g-paths"',
            'id="g-export-svg"',
            'id="g-export-png"',
            "Find node",
            "Attack paths",
        ):
            assert marker in html, marker

    def test_type_filter_chips(self, html):
        assert "g-chip" in html
        assert "hiddenTypes" in html
        # legend chips toggle filters and re-apply
        assert "gApplyFilters()" in html

    def test_no_cdn_no_external_resources(self, html):
        for bad in (
            "<script src", "<link ", "<iframe", "<img ", "url(http",
            "fetch('http", 'fetch("http', "cdn.", "unpkg", "jsdelivr",
            "googleapis",
        ):
            assert bad not in html.lower()


class TestAttackPaths:
    def test_bfs_implementation_present(self, html):
        assert "gAttackPathSet" in html
        assert "gHubIndex" in html
        assert "gRiskTypes" in html

    def test_hub_is_domain_node_with_fallbacks(self, html):
        # hub prefers the 'domain' node, then max degree; risk types prefer
        # cve/bucket and fall back to port.
        block = html.split("function gHubIndex", 1)[1][:400]
        assert '"domain"' in block
        risk_block = html.split("function gRiskTypes", 1)[1][:400]
        assert '"cve"' in risk_block and '"bucket"' in risk_block and '"port"' in risk_block

    def test_paths_toggle(self, html):
        assert "pathsOn" in html
        assert 'id="g-paths"' in html


class TestGraphExport:
    def test_svg_export_serializes_clone(self, html):
        assert "gExportSvg" in html
        assert "XMLSerializer" in html
        assert "osint_eye_graph.svg" in html

    def test_png_export_uses_canvas_and_data_url(self, html):
        assert "gExportPng" in html
        assert "data:image/svg+xml" in html
        assert "toBlob" in html
        assert "osint_eye_graph.png" in html

    def test_csp_allows_data_images_for_png_pipeline(self, dashboard):
        # PNG export loads the serialized SVG as a data: image — the CSP
        # must keep allowing img-src data:.
        assert "img-src 'self' data:" in dashboard.CSP_POLICY

    def test_svg_has_inline_styles_for_standalone_look(self, html):
        # The serialized SVG keeps its appearance without page CSS.
        assert '.g-edge{stroke:' in html
        assert '.g-label{fill:' in html

    def test_download_uses_blob_object_url(self, html):
        assert "createObjectURL" in html
        assert 'a.download' in html


class TestGraphRenderingSafety:
    def test_no_innerhtml_in_graph_code(self, html):
        block = html.split("/* ---------- graph", 1)[1]
        assert "innerHTML" not in block
        assert "insertAdjacentHTML" not in block

    def test_labels_via_textcontent(self, html):
        # node labels go through textContent (title + label text nodes)
        assert "title.textContent" in html
        assert "t.textContent = label" in html

    def test_toolbar_wired_once_at_boot(self, html):
        assert "wireGraphToolbar" in html
        # static listeners, not re-attached per render
        wire = html.split("(function wireGraphToolbar", 1)[1][:700]
        assert 'addEventListener("input"' in wire
        assert 'addEventListener("click"' in wire
