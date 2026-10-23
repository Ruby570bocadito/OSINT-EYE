"""Offline tests for the Textual TUI (ui/tui_app.py).

Legacy tests (record coercion) were byte-identical relocations from the old
tests/test_core.py and stay untouched. Everything else uses Textual's pilot
harness through asyncio.run — 100 % offline, no network, no real terminal.
"""

import asyncio

import pytest


# ---------------------------------------------------------------------------
# Fixture scan (offline, example.com only)
# ---------------------------------------------------------------------------

FIXTURE_RESULTS = {
    "target": "example.com",
    "scan_date": "2026-10-23T00:00:00",
    "depth": "normal",
    "correlation": {"attack_surface_score": {"score": 62,
                                             "severity": "MEDIUM"}},
    "modules": {
        "dns": {
            "domain": "example.com",
            "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
            "subdomains": ["www.example.com", "api.example.com"],
        },
        "network": {"services": [
            {"port": 80, "protocol": "tcp", "service": "http",
             "state": "open", "version": "nginx 1.24.0"},
            {"port": 22, "protocol": "tcp", "service": "ssh",
             "state": "closed"},
            {"port": 443, "protocol": "tcp", "service": "https",
             "state": "open"},
        ]},
        "web": {"technologies": {"technologies": {"Nginx": {}}}},
        "emails": {"domain": "example.com",
                   "emails_found": ["contact@example.com"]},
        "cve": {"cves": [{"id": "CVE-2024-0001",
                          "severity": [{"severity": "high", "score": 7.5}],
                          "description": "example vulnerability"}]},
        "cloud_buckets": {"found": [
            {"url": "https://example-assets.s3.amazonaws.com/",
             "public": True, "provider": "AWS S3"}],
            "public": []},
    },
    "mitre": {"findings": [{"technique_id": "T1595",
                            "technique_name": "Active Scanning",
                            "severity": "medium",
                            "tactic": "Reconnaissance"}]},
}


def _assets():
    from ui.dashboard import _collect_assets

    return _collect_assets(FIXTURE_RESULTS)


# ---------------------------------------------------------------------------
# Legacy tests (relocated verbatim from tests/test_core.py)
# ---------------------------------------------------------------------------

class TestTuiRecordCoercion:
    def test_string_value_becomes_single_element_list(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values("1.2.3.4") == ["1.2.3.4"]

    def test_list_values_are_stringified(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values(["a", 1]) == ["a", "1"]

    def test_junk_is_dropped(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values(5) == []
        assert ScanScreen._coerce_record_values(None) == []


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------

class TestAssetFiltering:
    def test_empty_query_returns_everything(self):
        from ui.tui_app import ScanScreen

        assets = _assets()
        assert ScanScreen._filter_assets(assets, "") == assets
        assert ScanScreen._filter_assets(assets, "   ") == assets

    def test_substring_matches_type_name_module_and_detail(self):
        from ui.tui_app import ScanScreen

        assets = _assets()
        by_type = ScanScreen._filter_assets(assets, "cve")
        assert by_type and all(a["type"] == "cve" for a in by_type)

        by_name = ScanScreen._filter_assets(assets, "api.example.com")
        assert any(a["name"] == "api.example.com" for a in by_name)

        by_detail = ScanScreen._filter_assets(assets, "CVSS")
        assert by_detail and all("CVSS" in a["detail"] for a in by_detail)

    def test_query_is_case_insensitive(self):
        from ui.tui_app import ScanScreen

        assets = _assets()
        assert ScanScreen._filter_assets(assets, "NGINX") == \
            ScanScreen._filter_assets(assets, "nginx")

    def test_no_match_is_empty(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._filter_assets(_assets(), "no-such-asset-xyz") == []


class TestOverviewHelpers:
    def test_severity_counts_only_known_severities(self):
        from ui.tui_app import ScanScreen

        counts = ScanScreen._severity_counts(_assets())
        assert set(counts) == {"critical", "high", "medium", "low", "info"}
        assert sum(counts.values()) == len(_assets())

    def test_type_counts_tallies_every_asset(self):
        from ui.tui_app import ScanScreen

        counts = ScanScreen._type_counts(_assets())
        assert sum(counts.values()) == len(_assets())
        assert counts.get("subdomain", 0) >= 2

    def test_modules_reporting_aggregates_across_modules(self):
        from ui.tui_app import ScanScreen

        rows = ScanScreen._modules_reporting(_assets(), "API.EXAMPLE.COM")
        modules = {m for m, _sev, _d in rows}
        assert "dns" in modules
        assert all(len(m) > 0 for m in modules)

    def test_modules_reporting_unknown_name_is_empty(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._modules_reporting(_assets(), "never-scanned.tld") \
            == []


# ---------------------------------------------------------------------------
# Pilot tests (real widget tree, offline)
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


class TestTuiPilot:
    def _app(self):
        from ui.tui_app import OSINTEyeTUI

        return OSINTEyeTUI(FIXTURE_RESULTS)

    def test_boots_with_tabs_and_populated_assets(self):
        async def scenario():
            app = self._app()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                from textual.widgets import DataTable, TabbedContent

                tabs = app.screen.query_one("#tabs", TabbedContent)
                assert tabs.tab_count == 5
                table = app.screen.query_one("#assets-table", DataTable)
                assert table.row_count == len(_assets())

        _run(scenario())

    def test_digit_keys_jump_tabs(self):
        async def scenario():
            app = self._app()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                from textual.widgets import TabbedContent

                tabs = app.screen.query_one("#tabs", TabbedContent)
                await pilot.press("3")
                await pilot.pause()
                assert tabs.active == "tab-dns"
                await pilot.press("5")
                await pilot.pause()
                assert tabs.active == "tab-findings"

        _run(scenario())

    def test_find_shortcut_focuses_filter(self):
        async def scenario():
            app = self._app()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                from textual.widgets import Input

                await pilot.press("ctrl+f")
                await pilot.pause()
                focused = app.focused
                assert isinstance(focused, Input)
                assert focused.id == "asset-filter"

        _run(scenario())

    def test_filter_narrows_assets_table(self):
        async def scenario():
            app = self._app()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                from textual.widgets import DataTable, Input

                app.screen.query_one("#asset-filter", Input).value = "cve"
                await pilot.pause()
                table = app.screen.query_one("#assets-table", DataTable)
                assert 0 < table.row_count < len(_assets())
                assert all(
                    "cve" in str(table.get_row_at(i)[1]).lower()
                    for i in range(table.row_count)
                )

        _run(scenario())

    def test_row_selected_opens_detail_screen_and_esc_closes(self):
        async def scenario():
            app = self._app()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                from textual.widgets import DataTable
                from ui.tui_app import AssetDetailScreen

                table = app.screen.query_one("#assets-table", DataTable)
                table.focus()
                await pilot.pause()
                await pilot.press("enter")
                await pilot.pause()
                assert isinstance(app.screen, AssetDetailScreen)

                await pilot.press("escape")
                await pilot.pause()
                assert not isinstance(app.screen, AssetDetailScreen)

        _run(scenario())

    def test_detail_lists_every_reporting_module(self):
        async def scenario():
            app = self._app()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                from textual.widgets import Static
                from ui.tui_app import AssetDetailScreen

                detail = AssetDetailScreen({"type": "subdomain",
                                            "name": "api.example.com",
                                            "module": "dns",
                                            "severity": "info",
                                            "detail": ""},
                                           _assets())
                await app.push_screen(detail)
                await pilot.pause()
                card = app.screen.query_one("#detail-card", Static)
                text = str(card.render())
                assert "api.example.com" in text
                assert "dns" in text

        _run(scenario())
