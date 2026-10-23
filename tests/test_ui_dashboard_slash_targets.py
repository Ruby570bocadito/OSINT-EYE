"""Regression tests for H-005: scan targets containing slashes (URL-shaped
targets, hostile JSON targets) were unreachable through /api/scan/<target>
routes because the string converter never matches slashes.

Fix: all /api/scan/... routes use <path:target>; the client already sends
encodeURIComponent(target) and Werkzeug decodes %2F after routing. All
offline — Flask test client, scans injected in memory.
"""

import json
from urllib.parse import quote

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


def _inject(dashboard, target, **extra):
    scan = {
        "target": target,
        "scan_date": "2026-10-23T00:00:00",
        "depth": "normal",
        "modules": {
            "dns": {"subdomains": ["www.example.com"]},
            "network": {
                "services": [
                    {"port": 443, "protocol": "tcp", "state": "open", "service": "https"}
                ]
            },
            "web": {"technologies": {"technologies": ["nginx"]}},
            "emails": {"emails_found": ["a@example.com"]},
            "cve": {"cves": [{"id": "CVE-2024-0001", "severity": [{"severity": "high", "score": 7.5}], "description": "x"}]},
            "cloud_buckets": {"found": [], "public": []},
            "certs": {"subdomains": []},
            "permutation": {"subdomains": []},
        },
        "graph": {"nodes": [], "edges": []},
        "mitre": {"findings": [], "total_findings": 0},
        "attack_chains": [],
    }
    scan.update(extra)
    dashboard.SCAN_RESULTS[target] = scan
    dashboard.SCAN_HISTORY.append(
        {"target": target, "date": scan["scan_date"], "depth": "normal",
         "demo": False, "warning": None, "refreshed_at": scan["scan_date"]}
    )
    return scan


_SUBROUTES = (
    "summary",
    "subdomains",
    "ports",
    "graph",
    "mitre",
    "chains",
    "assets",
)


class TestSlashTargetsReachable:
    @pytest.mark.parametrize(
        "target",
        [
            "http://127.0.0.1:8599",          # the benign H-005 case
            "https://target.example.com/x",   # URL with path
            "<script>alert(1)</script>evil.com",  # hostile JSON target
            "example.com/",                    # trailing slash
            "a/b/c",                           # multi-slash
        ],
    )
    def test_all_subroutes_serve_slash_targets(self, dashboard, client, target):
        _inject(dashboard, target)
        enc = quote(target, safe="")

        listed = client.get("/api/scans").get_json()
        assert any(s["target"] == target for s in listed["scans"])

        resp = client.get(f"/api/scan/{enc}")
        assert resp.status_code == 200
        assert resp.get_json()["target"] == target

        for route in _SUBROUTES:
            resp = client.get(f"/api/scan/{enc}/{route}")
            assert resp.status_code == 200, f"{route} -> {resp.status_code}"
            assert resp.get_json() is not None

        resp = client.get(f"/api/scan/{enc}/export?format=json")
        assert resp.status_code == 200
        assert json.loads(resp.get_data(as_text=True))["target"] == target

    def test_diff_between_slash_targets(self, dashboard, client):
        _inject(dashboard, "http://old.example.com", modules={
            "dns": {"subdomains": ["a.example.com"]}, "network": {"services": []},
            "web": {"technologies": {"technologies": []}}, "emails": {"emails_found": []},
            "cve": {"cves": []}, "cloud_buckets": {"found": []},
            "certs": {"subdomains": []}, "permutation": {"subdomains": []},
        })
        _inject(dashboard, "http://new.example.com", modules={
            "dns": {"subdomains": ["a.example.com", "b.example.com"]}, "network": {"services": []},
            "web": {"technologies": {"technologies": []}}, "emails": {"emails_found": []},
            "cve": {"cves": []}, "cloud_buckets": {"found": []},
            "certs": {"subdomains": []}, "permutation": {"subdomains": []},
        })
        enc_new = quote("http://new.example.com", safe="")
        enc_old = quote("http://old.example.com", safe="")
        resp = client.get(f"/api/scan/{enc_new}/diff?against={enc_old}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["from"] == "http://old.example.com"
        assert data["to"] == "http://new.example.com"


class TestPlainTargetsUnbroken:
    @pytest.mark.parametrize("target", ["example.com", "192.0.2.1", "2001:db8::1"])
    def test_plain_targets_still_served(self, dashboard, client, target):
        _inject(dashboard, target)
        enc = quote(target, safe="")
        resp = client.get(f"/api/scan/{enc}")
        assert resp.status_code == 200
        for route in _SUBROUTES:
            assert client.get(f"/api/scan/{enc}/{route}").status_code == 200

    def test_unknown_target_is_honest_404(self, client):
        resp = client.get(f"/api/scan/{quote('http://never-loaded.dev', safe='')}")
        assert resp.status_code == 404
        assert "error" in resp.get_json()


class TestNoServerErrors:
    def test_pathological_anchor_never_500(self, dashboard, client):
        # A target shaped like a sub-route anchor resolves to the sub-route
        # of the shorter target (documented residual edge): honest 404 or
        # the wrong-but-safe lookup — never a 500 and never a crash.
        _inject(dashboard, "a.com")
        resp = client.get("/api/scan/a.com/summary")       # normal case
        assert resp.status_code == 200
        resp = client.get("/api/scan/" + quote("x.com/summary", safe="") + "/ports")
        assert resp.status_code in (200, 404)

    def test_double_slash_prefix_never_500(self, dashboard, client):
        # Werkzeug path converters never match a leading slash: a target
        # starting with '/' stays unreachable — documented residual, the
        # answer is the plain 404 JSON (merge_slashes is off, no 308 dance).
        _inject(dashboard, "//evil.com")
        resp = client.get("/api/scan/" + quote("//evil.com", safe=""))
        assert resp.status_code == 404
        assert "error" in resp.get_json()

    def test_scan_with_slash_target_via_load(self, dashboard, client, tmp_path):
        # End-to-end through the real loading path (H-005 repro).
        scan = {
            "target": "http://127.0.0.1:8599",
            "depth": "quick",
            "modules": {"dns": {"subdomains": []}, "network": {"services": []},
                        "web": {"technologies": {"technologies": []}},
                        "emails": {"emails_found": []}, "cve": {"cves": []},
                        "cloud_buckets": {"found": []}, "certs": {"subdomains": []},
                        "permutation": {"subdomains": []}},
        }
        path = tmp_path / "e2e_dash.json"
        path.write_text(json.dumps(scan), encoding="utf-8")
        target = dashboard.load_scan_results(str(path))
        assert target == "http://127.0.0.1:8599"

        assert client.get("/api/scans").status_code == 200
        resp = client.get("/api/scan/" + quote(target, safe=""))
        assert resp.status_code == 200
        resp = client.get("/api/scan/" + quote(target, safe="") + "/summary")
        assert resp.status_code == 200
