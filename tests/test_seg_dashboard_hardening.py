"""Offline regression tests for dashboard API hardening (SEG).

Covers ui/dashboard.py: security headers on every response, no-store on the
API, the size cap and recursion guard on load_scan_results, and that
<path> URL parameters can never reach the filesystem (dict lookup only).
No network: Flask's test client and tmp files only.
"""

import json
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ui.dashboard as dashboard_module
from ui.dashboard import app, load_scan_results


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    dashboard_module.SCAN_RESULTS.clear()
    dashboard_module.SCAN_HISTORY.clear()
    dashboard_module.LAST_LOAD_WARNING = None
    with app.test_client() as client:
        yield client
    dashboard_module.SCAN_RESULTS.clear()
    dashboard_module.SCAN_HISTORY.clear()
    dashboard_module.LAST_LOAD_WARNING = None


# --- security headers --------------------------------------------------------

def test_security_headers_on_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_api_responses_are_no_store(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_index_served_without_jinja_execution(client):
    """The template is static HTML; it must be served verbatim."""
    resp = client.get("/")
    assert b"OSINT EYE" in resp.data


# --- <target> parameters never touch the filesystem --------------------------

@pytest.mark.parametrize("path", [
    "/api/scan/../../etc/passwd",
    "/api/scan/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/api/scan/..%2F..%2Fetc%2Fpasswd/subdomains",
    "/api/scan/whatever%00.json",
])
def test_traversal_targets_never_route(client, path):
    """Path separators never reach <target>; routing rejects them outright."""
    resp = client.get(path)
    assert resp.status_code == 404
    # Never a crash and never a filesystem-backed answer.
    assert resp.status_code != 500


def test_unknown_target_returns_json_error(client):
    resp = client.get("/api/scan/definitely-not-loaded/summary")
    assert resp.status_code == 404
    assert b"error" in resp.data


# --- load_scan_results guards ------------------------------------------------

def test_load_valid_scan_still_works(client, tmp_path):
    scan = {"target": "example.com", "scan_date": "2026-10-23T12:00:00",
            "depth": "quick", "modules": {}}
    path = tmp_path / "osint_eye_scan.json"
    path.write_text(json.dumps(scan), encoding="utf-8")
    target = load_scan_results(str(path))
    assert target == "example.com"
    assert dashboard_module.SCAN_RESULTS["example.com"]["target"] == "example.com"
    assert dashboard_module.LAST_LOAD_WARNING is None


def test_oversized_scan_file_refused(client, tmp_path, monkeypatch):
    path = tmp_path / "big.json"
    path.write_text(json.dumps({"target": "big.example", "pad": "x" * 200}),
                    encoding="utf-8")
    monkeypatch.setattr(dashboard_module, "MAX_SCAN_FILE_BYTES", 50)
    target = load_scan_results(str(path))
    assert dashboard_module.SCAN_RESULTS[target]["demo"] is True
    assert "larger than" in dashboard_module.LAST_LOAD_WARNING
    assert "big.example" not in dashboard_module.SCAN_RESULTS


def test_deeply_nested_json_refused_not_crash(client, tmp_path):
    path = tmp_path / "nested.json"
    depth = 20000
    path.write_text("[" * depth + "]" * depth, encoding="utf-8")
    target = load_scan_results(str(path))
    assert dashboard_module.SCAN_RESULTS[target]["demo"] is True
    assert "Could not read" in dashboard_module.LAST_LOAD_WARNING


def test_malformed_json_refused_not_crash(client, tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    target = load_scan_results(str(path))
    assert dashboard_module.SCAN_RESULTS[target]["demo"] is True


def test_non_object_json_refused(client, tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    target = load_scan_results(str(path))
    assert dashboard_module.SCAN_RESULTS[target]["demo"] is True
    assert "does not contain a JSON object" in dashboard_module.LAST_LOAD_WARNING


def test_missing_file_falls_back_to_demo(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # avoid picking up stray repo json files
    target = load_scan_results(str(tmp_path / "nope.json"))
    assert dashboard_module.SCAN_RESULTS[target]["demo"] is True
    assert "not found" in dashboard_module.LAST_LOAD_WARNING


def test_start_dashboard_defaults_are_local_only():
    """The dashboard must bind to loopback with debug off by default."""
    import inspect
    signature = inspect.signature(dashboard_module.start_dashboard)
    assert signature.parameters["host"].default == "127.0.0.1"
    assert signature.parameters["debug"].default is False
