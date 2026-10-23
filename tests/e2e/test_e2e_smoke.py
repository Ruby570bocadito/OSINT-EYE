"""E2E offline smoke tests (TEST, ROADMAP: e2e-smoke).

Runs the real CLI as a subprocess without external network:
- --help and --modules must work from a cold start,
- malformed targets must never traceback,
- a --depth quick web scan against a local loopback HTTP fixture must
  produce real results (the initial target is the operator's explicit
  choice; redirect hops into private space stay blocked by the SSRF
  guard),
- the produced JSON must load into the dashboard API.
"""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CLI = os.path.join(REPO_ROOT, "osint_eye.py")


def run_cli(args, timeout=120, cwd=REPO_ROOT):
    return subprocess.run(
        [sys.executable, CLI, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# --- local fixtures ----------------------------------------------------------

class _NginxFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>local fixture for e2e</body></html>")

    def log_message(self, *args):
        pass


class _RedirectFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.end_headers()

    def log_message(self, *args):
        pass


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


# --- CLI smoke ---------------------------------------------------------------

def test_cli_help_from_cold_start():
    result = run_cli(["--help"])
    assert result.returncode == 0
    assert "OSINT EYE" in result.stdout
    assert "usage:" in result.stdout


def test_cli_modules_catalog():
    result = run_cli(["--modules"])
    assert result.returncode == 0
    for module in ("dns", "certs", "wayback", "web", "graph", "mitre"):
        assert module in result.stdout


@pytest.mark.parametrize("bad_target", [
    "not_a_domain!!",
    "HTTPS://Example.COM",
    "https://example.com/ruta",
    "example.com/path?x=1",
])
def test_malformed_targets_never_traceback(bad_target):
    result = run_cli([
        bad_target, "--depth", "quick", "--no-ai", "--no-cache",
        "--modules", "dns",
    ])
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined
    assert "KeyboardInterrupt" not in combined


# --- quick scan against a local HTTP fixture ---------------------------------

def test_quick_scan_local_fixture_produces_web_results(tmp_path):
    server, thread = _serve(_NginxFixture)
    try:
        out_base = tmp_path / "e2e_scan"
        result = run_cli([
            f"http://127.0.0.1:{server.server_address[1]}",
            "--modules", "web", "--depth", "quick",
            "--no-ai", "--no-cache", "-o", str(out_base),
        ], cwd=tmp_path)
        assert result.returncode == 0, result.stdout[-500:] + result.stderr[-500:]
        assert "Traceback" not in (result.stdout + result.stderr)

        data = json.loads((out_base.with_suffix(".json")).read_text())
        tech = data["modules"]["web"]["technologies"]
        assert tech.get("status_code") == 200
        assert "error" not in tech
        assert "Nginx" in tech["technologies"]
    finally:
        _stop(server, thread)


def test_quick_scan_local_fixture_blocks_metadata_redirect(tmp_path):
    """E2E regression: a redirect to the cloud metadata service must be
    refused by the SSRF guard while the scan itself keeps running."""
    server, thread = _serve(_RedirectFixture)
    try:
        out_base = tmp_path / "e2e_ssr"
        result = run_cli([
            f"http://127.0.0.1:{server.server_address[1]}",
            "--modules", "web", "--depth", "quick",
            "--no-ai", "--no-cache", "-o", str(out_base),
        ], cwd=tmp_path)
        assert result.returncode == 0
        assert "Traceback" not in (result.stdout + result.stderr)

        data = json.loads((out_base.with_suffix(".json")).read_text())
        tech = data["modules"]["web"]["technologies"]
        assert "SSRF" in tech.get("error", "")
        # The metadata service was never fetched: no headers of a 200 answer.
        assert tech.get("status_code") is None
    finally:
        _stop(server, thread)


# --- dashboard consumes the produced JSON ------------------------------------

def test_dashboard_api_serves_local_scan_json(tmp_path):
    from ui.dashboard import app, load_scan_results
    import ui.dashboard as dashboard_module

    server, thread = _serve(_NginxFixture)
    try:
        out_base = tmp_path / "e2e_dash"
        result = run_cli([
            f"http://127.0.0.1:{server.server_address[1]}",
            "--modules", "web", "--depth", "quick",
            "--no-ai", "--no-cache", "-o", str(out_base),
        ], cwd=tmp_path)
        assert result.returncode == 0
    finally:
        _stop(server, thread)

    dashboard_module.SCAN_RESULTS.clear()
    dashboard_module.SCAN_HISTORY.clear()
    # Rewrite the target key to a plain domain: URL-form targets contain
    # slashes and are unreachable through /api/scan/<target> routing
    # (see docs/agentes/hallazgos/H-005-dashboard-target-con-slash.md).
    scan_path = out_base.with_suffix(".json")
    data = json.loads(scan_path.read_text())
    data["target"] = "fixture.local"
    scan_path.write_text(json.dumps(data))
    target = load_scan_results(str(scan_path))
    with app.test_client() as client:
        resp = client.get(f"/api/scan/{target}")
        assert resp.status_code == 200
        payload = resp.get_json()
        assert payload["modules"]["web"]["technologies"]["status_code"] == 200
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
