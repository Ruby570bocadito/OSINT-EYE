"""Tests for the dashboard scan-comparison (diff) endpoint.

All offline: scans are injected directly into dashboard.SCAN_RESULTS.
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


SCAN_OLD = {
    "target": "old.example.com",
    "modules": {
        "dns": {"subdomains": ["www.example.com", "staging.example.com"]},
        "certs": {"subdomains": []},
        "permutation": {"subdomains": []},
        "network": {
            "services": [
                {"host": "example.com", "port": 443, "protocol": "tcp", "state": "open",
                 "service": "https", "version": "nginx 1.24"},
                {"host": "example.com", "port": 22, "protocol": "tcp", "state": "open",
                 "service": "ssh", "version": "OpenSSH 8.9"},
            ]
        },
        "web": {"technologies": {"technologies": ["Nginx", "PHP"]}},
        "emails": {"emails_found": ["info@example.com"]},
        "cve": {"cves": [{"id": "CVE-2024-1111", "severity": [{"score": 7.5, "severity": "HIGH"}]}]},
        "cloud_buckets": {"found": [{"url": "old.s3.amazonaws.com", "provider": "s3"}]},
    },
    "correlation": {"attack_surface_score": {"score": 40, "severity": "MEDIUM"}},
}

SCAN_NEW = {
    "target": "new.example.com",
    "modules": {
        "dns": {"subdomains": ["www.example.com", "api.example.com"]},
        "certs": {"subdomains": []},
        "permutation": {"subdomains": []},
        "network": {
            "services": [
                {"host": "example.com", "port": 443, "protocol": "tcp", "state": "open",
                 "service": "https", "version": "nginx 1.27"},
                {"host": "example.com", "port": 8443, "protocol": "tcp", "state": "open",
                 "service": "https-alt", "version": "tomcat"},
            ]
        },
        "web": {"technologies": {"technologies": ["Nginx", "React"]}},
        "emails": {"emails_found": ["info@example.com", "dev@example.com"]},
        "cve": {"cves": [{"id": "CVE-2024-1111", "severity": []},
                          {"id": "CVE-2024-2222", "severity": [{"score": 9.8, "severity": "CRITICAL"}]}]},
        "cloud_buckets": {"found": [{"url": "old.s3.amazonaws.com", "provider": "s3"},
                                     {"url": "new-public.s3.amazonaws.com", "provider": "s3"}]},
    },
    "correlation": {"attack_surface_score": {"score": 58, "severity": "HIGH"}},
}


class TestDiffEndpoint:
    def test_diff_404_for_unknown_target(self, client):
        assert client.get("/api/scan/ghost/diff?against=other").status_code == 404

    def test_diff_400_without_or_bad_against(self, dashboard, client):
        dashboard.SCAN_RESULTS["a"] = SCAN_OLD
        assert client.get("/api/scan/a/diff").status_code == 400
        assert client.get("/api/scan/a/diff?against=not-loaded").status_code == 400
        body = client.get("/api/scan/a/diff?against=not-loaded").get_json()
        assert "against" in body["error"]

    def test_diff_direction_and_content(self, dashboard, client):
        dashboard.SCAN_RESULTS["old.example.com"] = SCAN_OLD
        dashboard.SCAN_RESULTS["new.example.com"] = SCAN_NEW

        data = client.get("/api/scan/new.example.com/diff?against=old.example.com").get_json()
        assert data["from"] == "old.example.com"
        assert data["to"] == "new.example.com"

        assert data["new_subdomains"] == ["api.example.com"]
        assert data["removed_subdomains"] == ["staging.example.com"]

        new_ports = {(p["host"], p["port"]) for p in data["new_ports"]}
        closed = {(p["host"], p["port"]) for p in data["closed_ports"]}
        assert new_ports == {("example.com", 8443)}
        assert closed == {("example.com", 22)}
        assert data["changed_services"] == [
            {"host": "example.com", "port": 443, "service": "https",
             "old_version": "nginx 1.24", "new_version": "nginx 1.27"}
        ]

        assert data["new_technologies"] == ["React"]
        assert data["removed_technologies"] == ["PHP"]
        assert data["new_emails"] == ["dev@example.com"]

        assert [c["id"] for c in data["new_cves"]] == ["CVE-2024-2222"]
        assert [b["url"] for b in data["new_cloud_buckets"]] == ["new-public.s3.amazonaws.com"]

        assert data["score_change"] == {"before": 40, "after": 58, "delta": 18}

    def test_diff_reverse_direction_mirrors(self, dashboard, client):
        dashboard.SCAN_RESULTS["old.example.com"] = SCAN_OLD
        dashboard.SCAN_RESULTS["new.example.com"] = SCAN_NEW

        data = client.get("/api/scan/old.example.com/diff?against=new.example.com").get_json()
        assert data["new_subdomains"] == ["staging.example.com"]
        assert data["removed_subdomains"] == ["api.example.com"]
        assert data["score_change"] == {"before": 58, "after": 40, "delta": -18}

    def test_diff_never_500_on_hostile_shapes(self, dashboard, client):
        hostile_a = {"target": "a", "modules": "flat-string", "correlation": 7}
        hostile_b = {
            "target": "b",
            "modules": {
                "dns": {"subdomains": "not-a-list"},
                "network": {"services": [{"port": "no-host-ok"}]},
                "web": {"technologies": {"technologies": [{"unhashable": True}]}},
                "emails": {"emails_found": [42, None]},
                "cve": {"cves": ["string-entry"]},
                "cloud_buckets": {"found": 9},
            },
            "correlation": {"attack_surface_score": "high"},
        }
        dashboard.SCAN_RESULTS["a"] = hostile_a
        dashboard.SCAN_RESULTS["b"] = hostile_b

        resp = client.get("/api/scan/b/diff?against=a")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["from"] == "a" and data["to"] == "b"
        for key in ("new_subdomains", "removed_subdomains", "new_ports", "closed_ports",
                    "changed_services", "new_technologies", "removed_technologies",
                    "new_emails", "new_cves", "new_cloud_buckets"):
            assert isinstance(data[key], list), key
        assert isinstance(data["score_change"], dict)

    def test_diff_same_scan_yields_no_changes(self, dashboard, client):
        dashboard.SCAN_RESULTS["same"] = SCAN_NEW
        data = client.get("/api/scan/same/diff?against=same").get_json()
        assert data["new_subdomains"] == []
        assert data["score_change"]["delta"] == 0

    def test_diff_tolerates_missing_modules(self, dashboard, client):
        dashboard.SCAN_RESULTS["empty"] = {"target": "empty"}
        data = client.get("/api/scan/empty/diff?against=empty").get_json()
        assert data["new_subdomains"] == []
        assert data["score_change"] == {"before": 0, "after": 0, "delta": 0}


class TestDiffTemplate:
    def test_template_serves_comparison_controls(self, client):
        html = client.get("/").get_data(as_text=True)
        for marker in ('id="diff-from"', 'id="diff-to"', 'id="diff-run"', "Scan Comparison"):
            assert marker in html, marker
