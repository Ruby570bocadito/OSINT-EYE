"""Tests for the dashboard scan-export endpoint (JSON / CSV / MD).

All offline: scans are injected directly into dashboard.SCAN_RESULTS.
"""

import csv
import io
import json

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


SCAN = {
    "target": "example.com",
    "scan_date": "2026-10-23T00:00:00",
    "depth": "normal",
    "modules": {
        "dns": {"subdomains": ["www.example.com"]},
        "cve": {"cves": [{"id": "CVE-2024-9999",
                           "severity": [{"score": 9.1, "severity": "CRITICAL"}],
                           "description": "RCE flaw"}]},
    },
}


class TestExportEndpoint:
    def test_export_404_for_unknown_target(self, client):
        assert client.get("/api/scan/ghost/export?format=json").status_code == 404

    def test_export_rejects_unknown_format(self, dashboard, client):
        dashboard.SCAN_RESULTS["example.com"] = SCAN
        resp = client.get("/api/scan/example.com/export?format=xlsx")
        assert resp.status_code == 400
        assert "json, csv, md" in resp.get_json()["error"]

    def test_export_json_returns_full_scan(self, dashboard, client):
        dashboard.SCAN_RESULTS["example.com"] = SCAN
        resp = client.get("/api/scan/example.com/export?format=json")
        assert resp.status_code == 200
        assert resp.mimetype == "application/json"
        body = json.loads(resp.get_data(as_text=True))
        assert body["target"] == "example.com"
        assert "osint_eye_" in resp.headers["Content-Disposition"]

    def test_export_csv_rows_and_escaping(self, dashboard, client):
        hostile = {
            "target": "evil",
            "modules": {
                "emails": {"emails_found": ["=HYPERLINK(\"http://x\",\"pwn\")"]},
            },
        }
        dashboard.SCAN_RESULTS["evil"] = hostile
        resp = client.get("/api/scan/evil/export?format=csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"

        rows = list(csv.reader(io.StringIO(resp.get_data(as_text=True))))
        assert rows[0] == ["severity", "type", "asset", "module", "detail"]
        email_row = next(r for r in rows if r[2].endswith("pwn\")"))
        assert email_row[2].startswith("'")  # formula neutralized

    def test_export_csv_contains_assets(self, dashboard, client):
        dashboard.SCAN_RESULTS["example.com"] = SCAN
        resp = client.get("/api/scan/example.com/export?format=csv")
        text = resp.get_data(as_text=True)
        assert "www.example.com" in text
        assert "CVE-2024-9999" in text
        assert "critical" in text

    def test_export_md_uses_shared_reporter(self, dashboard, client):
        dashboard.SCAN_RESULTS["example.com"] = SCAN
        resp = client.get("/api/scan/example.com/export?format=md")
        assert resp.status_code == 200
        assert resp.mimetype == "text/markdown"
        text = resp.get_data(as_text=True)
        assert text.startswith("#")  # canonical markdown headings
        assert "example.com" in text

    def test_export_md_never_fails_on_hostile_scan(self, dashboard, client):
        dashboard.SCAN_RESULTS["weird"] = {"target": "weird", "modules": None}
        resp = client.get("/api/scan/weird/export?format=md")
        assert resp.status_code == 200
        assert len(resp.get_data()) > 0

    def test_export_csv_empty_scan_is_header_only(self, dashboard, client):
        dashboard.SCAN_RESULTS["empty"] = {"target": "empty", "modules": {}}
        resp = client.get("/api/scan/empty/export?format=csv")
        rows = list(csv.reader(io.StringIO(resp.get_data(as_text=True))))
        assert rows == [["severity", "type", "asset", "module", "detail"]]


class TestSafeDownloadName:
    def test_traversal_and_crlf_neutralized(self):
        from ui.dashboard import _safe_download_name

        for hostile in ("../../etc/passwd", "a\r\nX-Injected: 1", "  ._-_.  ", None):
            name = _safe_download_name(hostile, "json")
            assert name.startswith("osint_eye_") and name.endswith(".json")
            assert "\r" not in name and "\n" not in name
            assert "/" not in name and "\\" not in name
            assert name.count("osint_eye_") == 1

    def test_normal_target_unchanged(self):
        from ui.dashboard import _safe_download_name

        assert _safe_download_name("example.com", "csv") == "osint_eye_example.com.csv"


class TestExportTemplate:
    def test_template_serves_export_buttons(self, client):
        html = client.get("/").get_data(as_text=True)
        for marker in ('data-fmt="json"', 'data-fmt="csv"', 'data-fmt="md"', 'id="export-group"'):
            assert marker in html, marker
