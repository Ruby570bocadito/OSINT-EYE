"""Offline tests for the Flask dashboard (ui/dashboard.py) via its test client.

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
import json
import os


class TestDashboard:
    def setup_method(self):
        from ui import dashboard

        dashboard.SCAN_RESULTS.clear()
        dashboard.SCAN_HISTORY.clear()
        dashboard.LAST_LOAD_WARNING = None

    def test_load_missing_path_falls_back_to_demo(self, tmp_path, monkeypatch):
        from ui import dashboard

        monkeypatch.chdir(tmp_path)
        target = dashboard.load_scan_results("missing_scan_results")
        assert target == "demo"
        assert dashboard.SCAN_RESULTS["demo"]["demo"] is True
        assert dashboard.LAST_LOAD_WARNING

    def test_load_without_json_extension(self, tmp_path, monkeypatch):
        from ui import dashboard

        data = {"target": "example.com", "scan_date": "2024-01-01T00:00:00", "depth": "normal", "modules": {}}
        (tmp_path / "osint_eye_example.json").write_text(json.dumps(data))
        monkeypatch.chdir(tmp_path)

        target = dashboard.load_scan_results("osint_eye_example")  # sin .json
        assert target == "example.com"
        assert dashboard.SCAN_RESULTS["example.com"]["target"] == "example.com"

    def test_load_most_recent_match(self, tmp_path, monkeypatch):
        from ui import dashboard

        for name in ("osint_eye_a.json", "osint_eye_b.json"):
            (tmp_path / name).write_text(json.dumps({"target": name}))
        os.utime(tmp_path / "osint_eye_b.json", (2000000000, 2000000000))
        monkeypatch.chdir(tmp_path)

        target = dashboard.load_scan_results("totally_unknown_prefix")
        assert target == "osint_eye_b.json"  # newest osint_eye_*.json wins

    def test_load_invalid_json_falls_back_to_demo(self, tmp_path, monkeypatch):
        from ui import dashboard

        (tmp_path / "broken.json").write_text("{not valid json")
        monkeypatch.chdir(tmp_path)
        target = dashboard.load_scan_results("broken.json")
        assert target == "demo"
        assert dashboard.SCAN_RESULTS["demo"]["demo"] is True

    def test_api_never_500(self):
        from ui import dashboard

        client = dashboard.app.test_client()
        assert client.get("/api/scans").get_json()["total"] == 0
        assert client.get("/api/scan/ghost").status_code == 404
        assert client.get("/api/scan/ghost/subdomains").status_code == 404
        assert client.get("/api/scan/ghost/ports").status_code == 404
        assert client.get("/api/scan/ghost/graph").status_code == 404
        assert client.get("/api/scan/ghost/mitre").status_code == 404
        assert client.get("/api/scan/ghost/summary").status_code == 404

        dashboard.load_scan_results("definitely_missing_file")
        assert client.get("/api/scans").get_json()["total"] == 1

        for endpoint in (
            "/api/scan/demo",
            "/api/scan/demo/subdomains",
            "/api/scan/demo/ports",
            "/api/scan/demo/graph",
            "/api/scan/demo/mitre",
            "/api/scan/demo/chains",
            "/api/scan/demo/summary",
        ):
            resp = client.get(endpoint)
            assert resp.status_code == 200, endpoint

        summary = client.get("/api/scan/demo/summary").get_json()
        assert summary["subdomains"] == 0
        assert summary["open_ports"] == 0

    def test_summary_subdomains_counts_certs_and_permutation(self):
        """KPI 'Subdomains' must agree with the findings explorer.

        Regression: the summary endpoint only counted ``dns.subdomains``, so a
        scan whose subdomains came from certificate transparency (``certs``)
        displayed 0 while the graph showed hundreds of subdomain nodes.
        """
        import json

        from ui import dashboard

        results = {
            "target": "mozilla.org",
            "scan_date": "2026-10-23T00:00:00",
            "depth": "normal",
            "modules": {
                "dns": {"subdomains": ["a.mozilla.org", "b.mozilla.org"]},
                "certs": {"subdomains": ["b.mozilla.org", "c.mozilla.org", "d.mozilla.org"]},
                "permutation": {"subdomains": ["e.mozilla.org"]},
            },
        }
        dashboard.SCAN_RESULTS["mozilla.org"] = results
        client = dashboard.app.test_client()
        summary = client.get("/api/scan/mozilla.org/summary").get_json()
        # dedup across sources: a, b, c, d, e -> 5 (b counted once)
        assert summary["subdomains"] == 5
        # consistency with the canonical asset view
        assets = dashboard._collect_assets(results)
        subs_assets = [a for a in assets if a["type"] == "subdomain"]
        assert summary["subdomains"] == len(set(a["name"] for a in subs_assets))

    def test_subdomain_count_helper_defensive(self):
        from ui import dashboard

        assert dashboard._subdomain_count({}) == 0
        assert dashboard._subdomain_count(None) == 0
        assert dashboard._subdomain_count({"certs": {"subdomains": "not-a-list"}}) == 0
        assert dashboard._subdomain_count({"dns": {"subdomains": [1, {"x": 2}, "ok.com"]}}) == 1
