"""Tests for the dashboard findings-explorer endpoint and filter contract.

All offline: scans are injected directly into dashboard.SCAN_RESULTS, no
network, no fixtures on disk beyond tmp_path where a file is convenient.
"""

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


RICH_SCAN = {
    "target": "example.com",
    "scan_date": "2026-10-23T00:00:00",
    "depth": "normal",
    "modules": {
        "dns": {"subdomains": ["www.example.com", "api.example.com"]},
        "certs": {"subdomains": ["www.example.com", "mail.example.com"]},
        "permutation": {"subdomains": ["api.example.com"]},
        "network": {
            "services": [
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.24"},
                {"port": 8080, "protocol": "tcp", "state": "filtered", "service": "http-alt"},
            ]
        },
        "web": {"technologies": {"technologies": ["Nginx", "jQuery"]}},
        "emails": {"emails_found": ["info@example.com"]},
        "cve": {
            "cves": [
                {
                    "id": "CVE-2024-1234",
                    "severity": [{"score": 9.8, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N"}],
                    "description": "Critical remote code execution flaw  " * 8,
                },
                {"id": "CVE-2024-5678", "severity": []},
            ]
        },
        "cloud_buckets": {
            "found": [
                {"url": "example-backup.s3.amazonaws.com", "provider": "s3", "public": True, "listable": True},
                {"url": "example-internal.s3.amazonaws.com", "provider": "s3", "public": False},
                "malformed-entry",
            ]
        },
    },
    "mitre": {
        "findings": [
            {"technique_id": "T1595", "technique_name": "Active Scanning", "tactic": "reconnaissance", "severity": "HIGH"},
            {"technique_id": "T1592", "technique_name": "Gather Victim Host Info", "tactic": "reconnaissance", "severity": "WEIRD"},
        ]
    },
}


class TestAssetsEndpoint:
    def test_assets_404_for_unknown_target(self, client):
        assert client.get("/api/scan/ghost/assets").status_code == 404

    def test_assets_aggregates_all_sources(self, dashboard, client):
        dashboard.SCAN_RESULTS["example.com"] = RICH_SCAN
        data = client.get("/api/scan/example.com/assets").get_json()

        assert data["target"] == "example.com"
        assert data["count"] == len(data["assets"])

        by_type = {}
        for asset in data["assets"]:
            by_type.setdefault(asset["type"], []).append(asset)

        # subdomains keep their source module (filter dimension)
        assert {a["name"] for a in by_type["subdomain"]} == {
            "www.example.com", "api.example.com", "mail.example.com",
        }
        assert {a["module"] for a in by_type["subdomain"]} == {"dns", "certs", "permutation"}

        # only open ports, version kept as detail
        assert [(a["name"], a["detail"]) for a in by_type["port"]] == [
            ("443/tcp", "https nginx 1.24"),
        ]

        assert {a["name"] for a in by_type["tech"]} == {"Nginx", "jQuery"}
        assert [a["name"] for a in by_type["email"]] == ["info@example.com"]

        # CVE severity normalized to lowercase buckets
        cve_by_name = {a["name"]: a for a in by_type["cve"]}
        assert cve_by_name["CVE-2024-1234"]["severity"] == "critical"
        assert "CVSS 9.8" in cve_by_name["CVE-2024-1234"]["detail"]
        assert cve_by_name["CVE-2024-5678"]["severity"] == "info"

        # public bucket is a high finding; closed one stays info; malformed skipped
        bucket_by_name = {a["name"]: a for a in by_type["bucket"]}
        assert bucket_by_name["example-backup.s3.amazonaws.com"]["severity"] == "high"
        assert "listable" in bucket_by_name["example-backup.s3.amazonaws.com"]["detail"]
        assert bucket_by_name["example-internal.s3.amazonaws.com"]["severity"] == "info"

        # MITRE severities normalized; unknown labels fall back to info
        tech_by_name = {a["name"]: a for a in by_type["technique"]}
        assert tech_by_name["T1595 Active Scanning"]["severity"] == "high"
        assert tech_by_name["T1592 Gather Victim Host Info"]["severity"] == "info"

    def test_assets_sorted_by_severity_then_type_then_name(self, dashboard, client):
        dashboard.SCAN_RESULTS["example.com"] = RICH_SCAN
        assets = client.get("/api/scan/example.com/assets").get_json()["assets"]

        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        keys = [(rank[a["severity"]], a["type"], a["name"].lower()) for a in assets]
        assert keys == sorted(keys)

    def test_assets_dedupes_within_same_type_and_module(self, dashboard, client):
        dashboard.SCAN_RESULTS["example.com"] = {
            "modules": {
                "dns": {"subdomains": ["dup.example.com", "dup.example.com", "once.example.com"]},
            }
        }
        assets = client.get("/api/scan/example.com/assets").get_json()["assets"]
        names = [a["name"] for a in assets]
        assert names.count("dup.example.com") == 1
        assert names.count("once.example.com") == 1

    def test_assets_never_500_on_malformed_data(self, dashboard, client):
        hostile = {
            "target": "hostile",
            "modules": {
                "dns": "not-a-dict",
                "network": {"services": "flat-string"},
                "web": {"technologies": {"technologies": 42}},
                "emails": {"emails_found": [1, {"subdomain": "weird"}, None]},
                "cve": {"cves": ["plain-string", 17, {"no_id": True}]},
                "cloud_buckets": {"found": 3},
            },
            "mitre": "not-a-dict",
        }
        dashboard.SCAN_RESULTS["hostile"] = hostile
        resp = client.get("/api/scan/hostile/assets")
        assert resp.status_code == 200
        assets = resp.get_json()["assets"]
        # scalars and shapeless entries are skipped; the only extractable
        # row comes from _as_str_list's documented dict-with-name tolerance
        assert [a["name"] for a in assets] == ["weird"]
        assert all(a["type"] == "email" for a in assets)

    def test_assets_empty_modules(self, dashboard, client):
        dashboard.SCAN_RESULTS["empty"] = {"target": "empty", "modules": {}}
        data = client.get("/api/scan/empty/assets").get_json()
        assert data["assets"] == []
        assert data["count"] == 0

    def test_tech_dict_shape_still_supported(self, dashboard, client):
        dashboard.SCAN_RESULTS["t"] = {
            "modules": {"web": {"technologies": {"technologies": {"React": True, "Nginx": 1}}}}
        }
        assets = client.get("/api/scan/t/assets").get_json()["assets"]
        assert {a["name"] for a in assets} == {"React", "Nginx"}


class TestTemplateFilters:
    def test_template_serves_filter_controls(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        for marker in (
            'id="f-search"',
            'id="f-severity"',
            'id="f-type"',
            'id="f-module"',
            'id="f-clear"',
            "Findings Explorer",
        ):
            assert marker in html, marker

    def test_template_has_no_external_resources(self, client):
        html = client.get("/").get_data(as_text=True)
        assert "cdn." not in html
        assert "unpkg" not in html and "jsdelivr" not in html
        assert "<script src=" not in html and 'href="http' not in html

    def test_load_scan_results_feeds_assets_endpoint(self, dashboard, client, tmp_path, monkeypatch):
        scan_path = tmp_path / "osint_eye_assets_test.json"
        scan_path.write_text(json.dumps(RICH_SCAN))
        monkeypatch.chdir(tmp_path)

        dashboard.load_scan_results("osint_eye_assets_test")
        data = client.get("/api/scan/example.com/assets").get_json()
        assert data["count"] > 0
        assert any(a["type"] == "cve" for a in data["assets"])
