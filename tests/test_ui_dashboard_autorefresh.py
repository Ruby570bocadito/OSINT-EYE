"""Tests for the dashboard auto-refresh feature (dashboard-autorefresco).

All offline: Flask test client, tmp_path files, a controllable fake clock
for the watcher loop (no real sleeps beyond the wait-timeout cut short by
the stop event).
"""

import json
import re
import threading
import time

import pytest


@pytest.fixture()
def dashboard():
    from ui import dashboard

    dashboard.SCAN_RESULTS.clear()
    dashboard.SCAN_HISTORY.clear()
    dashboard.LAST_LOAD_WARNING = None
    dashboard.DASHBOARD_CONFIG.update(
        {"auto_refresh": False, "interval_s": 60, "watch_paths": []}
    )
    return dashboard


@pytest.fixture()
def client(dashboard):
    return dashboard.app.test_client()


class TestClampInterval:
    def test_bounds(self, dashboard):
        assert dashboard._clamp_interval(0) == 5
        assert dashboard._clamp_interval(-10) == 5
        assert dashboard._clamp_interval(10 ** 9) == 3600
        assert dashboard._clamp_interval(30) == 30

    def test_garbage_defaults_to_60(self, dashboard):
        assert dashboard._clamp_interval(None) == 60
        assert dashboard._clamp_interval("abc") == 60


class TestConfigEndpoint:
    def test_default_off(self, client):
        resp = client.get("/api/dashboard/config")
        assert resp.status_code == 200
        assert resp.get_json() == {"auto_refresh": False, "interval_s": 60}

    def test_monitor_mode_on(self, dashboard, client):
        dashboard.DASHBOARD_CONFIG["auto_refresh"] = True
        dashboard.DASHBOARD_CONFIG["interval_s"] = 7
        data = client.get("/api/dashboard/config").get_json()
        assert data == {"auto_refresh": True, "interval_s": 7}

    def test_interval_clamped_in_endpoint(self, dashboard, client):
        dashboard.DASHBOARD_CONFIG["auto_refresh"] = True
        dashboard.DASHBOARD_CONFIG["interval_s"] = 1  # below minimum
        data = client.get("/api/dashboard/config").get_json()
        assert data["interval_s"] == 5


class TestStartDashboardConfig:
    def test_monitor_enables_refresh(self, dashboard, monkeypatch):
        started = {}

        def fake_run(host, port, debug):
            started["host"] = host

        monkeypatch.setattr(dashboard.app, "run", fake_run)
        dashboard.start_dashboard(monitor=True, interval=12)
        assert dashboard.DASHBOARD_CONFIG["auto_refresh"] is True
        assert dashboard.DASHBOARD_CONFIG["interval_s"] == 12

    def test_watch_paths_enable_refresh_and_thread(self, dashboard, monkeypatch):
        calls = {"watch": None}

        class FakeThread:
            def __init__(self, target=None, args=None, daemon=None, name=None):
                calls["target"] = target
                calls["args"] = args
                calls["daemon"] = daemon

            def start(self):
                calls["started"] = True

        monkeypatch.setattr(dashboard.threading, "Thread", FakeThread)
        monkeypatch.setattr(dashboard.app, "run", lambda *a, **k: None)
        dashboard.start_dashboard(watch_paths=["/tmp/scan.json"], interval=5)
        assert dashboard.DASHBOARD_CONFIG["auto_refresh"] is True
        assert dashboard.DASHBOARD_CONFIG["watch_paths"] == ["/tmp/scan.json"]
        assert calls["started"] is True
        assert calls["daemon"] is True

    def test_default_start_keeps_static_behavior(self, dashboard, monkeypatch):
        monkeypatch.setattr(dashboard.app, "run", lambda *a, **k: None)
        dashboard.start_dashboard()
        assert dashboard.DASHBOARD_CONFIG["auto_refresh"] is False
        assert dashboard.DASHBOARD_CONFIG["watch_paths"] == []


class TestReloadScanResults:
    def test_reload_upserts_history_without_duplicates(self, dashboard, tmp_path):
        scan = {
            "target": "example.com",
            "scan_date": "2026-10-23T10:00:00",
            "depth": "normal",
            "modules": {"dns": {"subdomains": ["a.example.com"]}},
        }
        path = tmp_path / "scan.json"
        path.write_text(json.dumps(scan), encoding="utf-8")

        t1 = dashboard.load_scan_results(str(path))
        assert t1 == "example.com"
        assert len(dashboard.SCAN_HISTORY) == 1

        scan["scan_date"] = "2026-10-23T11:00:00"
        scan["modules"]["dns"]["subdomains"].append("b.example.com")
        path.write_text(json.dumps(scan), encoding="utf-8")

        t2 = dashboard.reload_scan_results(str(path))
        assert t2 == "example.com"
        assert len(dashboard.SCAN_HISTORY) == 1  # replaced, not appended
        entry = dashboard.SCAN_HISTORY[0]
        assert entry["date"] == "2026-10-23T11:00:00"
        assert entry["refreshed_at"]
        assert "b.example.com" in dashboard.SCAN_RESULTS["example.com"]["modules"]["dns"]["subdomains"]

    def test_missing_file_never_raises(self, dashboard):
        # Tolerant loading falls back to demo data stored under 'demo'.
        assert dashboard.reload_scan_results("/nonexistent/nope.json") == "demo"

    def test_hostile_content_never_raises(self, dashboard, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        dashboard.reload_scan_results(str(path))  # must not raise
        assert dashboard.LAST_LOAD_WARNING

    def test_history_entries_carry_refreshed_at(self, dashboard, tmp_path):
        scan = {"target": "x.org", "modules": {}}
        path = tmp_path / "x.json"
        path.write_text(json.dumps(scan), encoding="utf-8")
        dashboard.load_scan_results(str(path))
        assert dashboard.SCAN_HISTORY[0]["refreshed_at"]


class TestWatchLoop:
    def test_reloads_when_mtime_changes(self, dashboard, tmp_path, monkeypatch):
        # Shrink the clamp floor so the watcher's first pass fires quickly.
        monkeypatch.setattr(dashboard, "_MIN_REFRESH_INTERVAL", 1)
        scan = {"target": "watched.com", "modules": {"dns": {"subdomains": []}}}
        path = tmp_path / "w.json"
        path.write_text(json.dumps(scan), encoding="utf-8")

        dashboard.reload_scan_results(str(path))  # prime
        assert dashboard.SCAN_RESULTS["watched.com"]["modules"]["dns"]["subdomains"] == []

        stop = threading.Event()
        worker = threading.Thread(
            target=dashboard._watch_loop,
            args=([str(path)], 1, stop),
            daemon=True,
        )
        worker.start()
        subs = []
        try:
            # Give the loop its first (mtime-priming) pass, then change data.
            time.sleep(1.3)
            scan["modules"]["dns"]["subdomains"] = ["new.watched.com"]
            path.write_text(json.dumps(scan), encoding="utf-8")

            deadline = time.time() + 5
            while time.time() < deadline:
                subs = dashboard.SCAN_RESULTS["watched.com"]["modules"]["dns"]["subdomains"]
                if subs == ["new.watched.com"]:
                    break
                time.sleep(0.05)
            assert subs == ["new.watched.com"]
        finally:
            stop.set()
            worker.join(timeout=3)

    def test_stop_event_breaks_promptly(self, dashboard):
        stop = threading.Event()
        worker = threading.Thread(
            target=dashboard._watch_loop, args=([], 3600, stop), daemon=True
        )
        worker.start()
        time.sleep(0.1)
        stop.set()
        worker.join(timeout=2)
        assert not worker.is_alive()


class TestScansEndpointRefreshFields:
    def test_scans_lists_refreshed_at_and_flags(self, dashboard, client, tmp_path):
        scan = {"target": "example.com", "modules": {}}
        path = tmp_path / "s.json"
        path.write_text(json.dumps(scan), encoding="utf-8")
        dashboard.load_scan_results(str(path))

        data = client.get("/api/scans").get_json()
        assert data["total"] == 1
        assert data["scans"][0]["refreshed_at"]
        assert data["auto_refresh"] is False

        dashboard.DASHBOARD_CONFIG["auto_refresh"] = True
        dashboard.DASHBOARD_CONFIG["interval_s"] = 9
        data = client.get("/api/scans").get_json()
        assert data["auto_refresh"] is True
        assert data["interval_s"] == 9


class TestTemplateAutoRefresh:
    """Static contract of the client-side polling (100% offline, no CDN)."""

    @pytest.fixture()
    def html(self, dashboard):
        return dashboard._template()

    def test_no_external_resources(self, html):
        # w3.org namespace identifiers are fine — they are not loads.
        # Forbidden: remote scripts/styles/frames/images or CDN fetches.
        for bad in (
            "<script src", "<link ", "<iframe", "<img ", "url(http",
            "fetch('http", 'fetch("http', "cdn.", "unpkg", "jsdelivr",
            "googleapis",
        ):
            assert bad not in html.lower()

    def test_live_chip_present_and_hidden_by_default(self, html):
        tag = re.search(r'<div[^>]*id="live-chip"[^>]*>', html)
        assert tag, "live-chip element missing"
        assert "hidden" in tag.group(0)

    def test_polling_wiring_exists(self, html):
        assert "/api/dashboard/config" in html
        assert "initLiveRefresh" in html
        assert "pollTick" in html
        assert "setInterval" in html
        # selection preserved across refreshes
        assert "loadTargets(currentTarget)" in html

    def test_failure_shutdown_and_pause(self, html):
        assert "OFFLINE" in html
        assert "PAUSED" in html
        assert "visibilitychange" in html  # pauses on hidden tab
