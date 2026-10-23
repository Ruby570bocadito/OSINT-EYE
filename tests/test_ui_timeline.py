"""Tests for the surface timeline endpoints (timeline-historico).

All offline: Flask test client, scans injected into dashboard.SCAN_RESULTS.
The timeline chains per-target deltas over the canonical asset view
(_collect_assets): new = present now, absent before; removed = the reverse.
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


def _scan(target, date, subs, ports=None, score=0, severity="LOW"):
    return {
        "target": target,
        "scan_date": date,
        "depth": "normal",
        "modules": {
            "dns": {"subdomains": list(subs)},
            "network": {
                "services": [
                    {"port": p, "protocol": "tcp", "state": "open"} for p in (ports or [])
                ]
            },
            "web": {"technologies": {"technologies": []}},
            "emails": {"emails_found": []},
            "cve": {"cves": []},
            "cloud_buckets": {"found": [], "public": []},
            "certs": {"subdomains": []},
            "permutation": {"subdomains": []},
        },
        "correlation": {
            "attack_surface_score": {"score": score, "severity": severity, "factors": []}
        },
        "mitre": {"findings": [], "total_findings": 0},
        "attack_chains": [],
        "graph": {"nodes": [], "edges": []},
    }


def _load(dashboard, scan):
    # Real storage path: archives per (target, scan_date) and upserts history.
    dashboard._store_scan(scan)


class TestBuildTimeline:
    def test_chains_deltas_across_same_target(self, dashboard):
        _load(dashboard, _scan("example.com", "2026-10-23T08:00:00", ["a.example.com"]))
        _load(dashboard, _scan("example.com", "2026-10-23T10:00:00",
                               ["a.example.com", "b.example.com", "c.example.com"]))
        _load(dashboard, _scan("example.com", "2026-10-23T12:00:00", ["a.example.com"]))

        events = dashboard._build_timeline()
        assert len(events) == 3
        # oldest first
        assert [e["date"] for e in events] == [
            "2026-10-23T08:00:00", "2026-10-23T10:00:00", "2026-10-23T12:00:00",
        ]
        first, second, third = events
        # first scan: everything is new, nothing removed (no previous state)
        assert first["new_count"] == 1
        assert first["removed_count"] == 0
        # second scan: b and c appeared
        assert second["new_count"] == 2
        assert {a["name"] for a in second["new"]} == {"b.example.com", "c.example.com"}
        assert second["removed_count"] == 0
        # third scan: b and c disappeared
        assert third["new_count"] == 0
        assert {a["name"] for a in third["removed"]} == {"b.example.com", "c.example.com"}

    def test_independent_chains_per_target(self, dashboard):
        _load(dashboard, _scan("one.com", "2026-10-23T08:00:00", ["x.one.com"]))
        _load(dashboard, _scan("two.com", "2026-10-23T09:00:00", ["x.two.com"]))
        _load(dashboard, _scan("one.com", "2026-10-23T10:00:00", ["x.one.com", "y.one.com"]))

        events = dashboard._build_timeline(targets=["one.com"])
        assert len(events) == 2
        assert all(e["target"] == "one.com" for e in events)
        assert events[1]["new_count"] == 1  # y.one.com — x.one.com not re-counted

    def test_counts_and_score_exposed(self, dashboard):
        _load(dashboard, _scan("example.com", "2026-10-23T08:00:00",
                               ["a.example.com"], ports=[443, 80], score=42,
                               severity="HIGH"))
        event = dashboard._build_timeline()[0]
        assert event["counts"]["subdomains"] == 1
        assert event["counts"]["ports"] == 2
        assert event["score"] == 42
        assert event["severity"] == "high"
        assert event["total_assets"] == 3

    def test_malformed_dates_sort_last_resort(self, dashboard):
        _load(dashboard, _scan("example.com", "not-a-date", ["a.example.com"]))
        _load(dashboard, _scan("example.com", "2026-10-23T08:00:00", ["b.example.com"]))
        events = dashboard._build_timeline()
        assert events[0]["date"] == "2026-10-23T08:00:00"  # parseable first
        assert events[1]["date"] == "not-a-date"

    def test_history_entry_without_results_skipped(self, dashboard):
        dashboard.SCAN_HISTORY.append(
            {"target": "ghost.com", "date": "2026-10-23T00:00:00",
             "depth": "normal", "demo": False, "warning": None}
        )
        assert dashboard._build_timeline() == []


class TestTimelineEndpoints:
    def test_global_timeline_endpoint(self, dashboard, client):
        _load(dashboard, _scan("example.com", "2026-10-23T08:00:00", ["a.example.com"]))
        data = client.get("/api/timeline").get_json()
        assert data["events"] == 1
        assert data["timeline"][0]["target"] == "example.com"

    def test_target_timeline_endpoint(self, dashboard, client):
        _load(dashboard, _scan("example.com", "2026-10-23T08:00:00", ["a.example.com"]))
        data = client.get("/api/scan/example.com/timeline").get_json()
        assert data["target"] == "example.com"
        assert len(data["timeline"]) == 1

    def test_unknown_target_404_json(self, dashboard, client):
        resp = client.get("/api/scan/never-loaded.dev/timeline")
        assert resp.status_code == 404
        assert "error" in resp.get_json()

    def test_never_500_on_hostile_shapes(self, dashboard, client):
        dashboard.SCAN_RESULTS["evil.com"] = {
            "target": "evil.com",
            "scan_date": None,
            "modules": "not-a-dict",
            "correlation": "not-a-dict",
            "mitre": [],
            "graph": [],
        }
        dashboard.SCAN_HISTORY.append(
            {"target": "evil.com", "date": None, "depth": None, "demo": False}
        )
        resp = client.get("/api/timeline")
        assert resp.status_code == 200
        event = resp.get_json()["timeline"][0]
        assert event["counts"]["subdomains"] == 0
        assert event["score"] == 0

    def test_slash_target_timeline_reachable(self, dashboard, client):
        # H-005 follow-up: timeline honors the <path:target> routing too.
        from urllib.parse import quote

        target = "http://127.0.0.1:8599"
        _load(dashboard, _scan(target, "2026-10-23T08:00:00", ["a.example.com"]))
        resp = client.get(f"/api/scan/{quote(target, safe='')}/timeline")
        assert resp.status_code == 200
        assert resp.get_json()["timeline"][0]["target"] == target


class TestTemplateTimeline:
    @pytest.fixture()
    def html(self, dashboard):
        return dashboard._template()

    def test_panel_and_wiring_exist(self, html):
        assert 'id="timeline-body"' in html
        assert "Surface Timeline" in html
        assert "renderTimeline(target)" in html
        assert "/timeline" in html
        assert 'id="timeline-meta"' in html

    def test_rendering_is_textcontent_only(self, html):
        # No CDN and no innerHTML anywhere in the timeline renderer.
        tl_block = html.split("renderTimeline", 1)[1][:2200]
        assert "innerHTML" not in tl_block
        assert "insertAdjacentHTML" not in tl_block

    def test_empty_state_wired(self, html):
        assert 'setEmpty($("timeline-body"), "No scans loaded")' in html
