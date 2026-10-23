"""Offline tests for the extended security headers audit
(modules/web/headers_audit.py): CORS, cookies, severities, wiring.

HTTP responses are mocked at ``requests.Session.request`` level; no
network is touched.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import requests

from modules.web.headers_audit import SecurityHeadersAuditor

URL = "https://example.com"


FULL_SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def _audit_with_headers(headers):
    """Run audit() against a fixed response header map."""
    auditor = SecurityHeadersAuditor()
    response = MagicMock()
    response.headers = dict(headers)
    with patch("requests.Session.request", return_value=response):
        return auditor.audit(URL)


# ─────────────────────────────────────────────────────────────────────────────
# Original contract preserved
# ─────────────────────────────────────────────────────────────────────────────
class TestOriginalContract:
    def test_missing_headers_flagged_with_severities(self):
        result = _audit_with_headers({"Content-Type": "text/html"})
        flagged = {f["header"]: f["severity"] for f in result["missing_headers"]}
        assert flagged["Strict-Transport-Security"] == "HIGH"
        assert flagged["Content-Security-Policy"] == "MEDIUM"
        assert flagged["X-Frame-Options"] == "MEDIUM"
        assert flagged["Referrer-Policy"] == "LOW"

    def test_information_disclosure_reported(self):
        result = _audit_with_headers({"Server": "nginx/1.19"})
        assert any(d["header"] == "Server" for d in result["information_disclosure"])
        assert result["information_disclosure"][0]["severity"] == "LOW"

    def test_hsts_misconfiguration_deductions(self):
        headers = dict(FULL_SECURE_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=3600"
        result = _audit_with_headers(headers)
        issues = {f["issue"] for f in result["misconfigured_headers"]}
        assert any("max-age too low" in i for i in issues)
        assert any("includeSubDomains" in i for i in issues)
        assert result["score"] == 85  # 100 -10 -5

    def test_hardened_server_gets_grade_a(self):
        result = _audit_with_headers(FULL_SECURE_HEADERS)
        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["missing_headers"] == []

    def test_score_never_negative_and_grades_map(self):
        result = _audit_with_headers({"Server": "x", "X-Powered-By": "y"})
        assert result["score"] >= 0
        assert result["grade"] in ("A", "B", "C", "D", "F")

    def test_ssl_failure_is_a_finding_not_a_downgrade(self):
        auditor = SecurityHeadersAuditor()
        with patch(
            "requests.Session.request",
            side_effect=requests.exceptions.SSLError("bad cert"),
        ):
            result = auditor.audit(URL)
        assert result["error"].startswith("TLS certificate verification failed")
        assert result["score"] == 0
        assert result["grade"] == "F"

    def test_network_failure_is_graceful(self):
        auditor = SecurityHeadersAuditor()
        with patch("requests.Session.request", side_effect=ConnectionError("boom")):
            result = auditor.audit(URL)
        assert "error" in result
        assert result["grade"] is None


# ─────────────────────────────────────────────────────────────────────────────
# CORS analysis (new)
# ─────────────────────────────────────────────────────────────────────────────
class TestCors:
    def test_wildcard_origin_is_flagged_medium(self):
        headers = dict(FULL_SECURE_HEADERS)
        headers["Access-Control-Allow-Origin"] = "*"
        result = _audit_with_headers(headers)
        assert len(result["cors_findings"]) == 1
        finding = result["cors_findings"][0]
        assert finding["severity"] == "MEDIUM"
        assert result["score"] == 90

    def test_wildcard_with_credentials_is_high(self):
        headers = dict(FULL_SECURE_HEADERS)
        headers["Access-Control-Allow-Origin"] = "*"
        headers["Access-Control-Allow-Credentials"] = "true"
        result = _audit_with_headers(headers)
        assert result["cors_findings"][0]["severity"] == "HIGH"
        assert result["score"] == 85

    def test_specific_origin_with_credentials_flagged(self):
        headers = dict(FULL_SECURE_HEADERS)
        headers["Access-Control-Allow-Origin"] = "https://trusted.example"
        headers["Access-Control-Allow-Credentials"] = "true"
        result = _audit_with_headers(headers)
        assert result["cors_findings"][0]["severity"] == "MEDIUM"
        assert result["score"] == 90

    def test_restricted_cors_is_clean(self):
        headers = dict(FULL_SECURE_HEADERS)
        headers["Access-Control-Allow-Origin"] = "https://trusted.example"
        result = _audit_with_headers(headers)
        assert result["cors_findings"] == []
        assert result["score"] == 100


# ─────────────────────────────────────────────────────────────────────────────
# Cookie analysis (new)
# ─────────────────────────────────────────────────────────────────────────────
class TestCookies:
    def test_unprotected_cookie_produces_three_findings(self):
        headers = dict(FULL_SECURE_HEADERS)
        headers["Set-Cookie"] = "sessionid=abc123; Path=/"
        result = _audit_with_headers(headers)
        flags = {f["flag"] for f in result["cookie_findings"]}
        assert flags == {"Secure", "HttpOnly", "SameSite"}
        assert all(f["cookie"] == "sessionid" for f in result["cookie_findings"])
        assert result["score"] == 100 - 5 - 5 - 3

    def test_hardened_cookie_is_clean(self):
        headers = dict(FULL_SECURE_HEADERS)
        headers["Set-Cookie"] = (
            "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
        )
        result = _audit_with_headers(headers)
        assert result["cookie_findings"] == []
        assert result["score"] == 100

    def test_no_cookies_no_findings(self):
        result = _audit_with_headers({})
        assert result["cookie_findings"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Back-compat + wiring
# ─────────────────────────────────────────────────────────────────────────────
class TestCompatAndWiring:
    def test_modules_dns_reexport_is_the_same_class(self):
        from modules.dns import SecurityHeadersAuditor as Legacy

        assert Legacy is SecurityHeadersAuditor

    def test_web_scanner_wires_headers_audit(self):
        from modules.web.web_scanner import WebScanner

        scanner = WebScanner()
        scanner.tech_detector = MagicMock()
        scanner.tech_detector.detect.return_value = {"technologies": set(), "headers": {}}
        scanner.endpoint_discovery = MagicMock()
        scanner.endpoint_discovery.discover_apis.return_value = {}
        scanner.sensitive_detector = MagicMock()
        scanner.sensitive_detector.scan_url.return_value = {}

        with patch(
            "modules.web.headers_audit.SecurityHeadersAuditor"
        ) as auditor_cls:
            auditor_cls.return_value.audit.return_value = {
                "url": URL, "score": 90, "grade": "A",
            }
            results = scanner.scan("example.com")

        assert results["headers_audit"] == {"url": URL, "score": 90, "grade": "A"}
        auditor_cls.return_value.audit.assert_called_once_with("https://example.com")

    def test_web_scanner_audit_failure_degrades(self):
        from modules.web.web_scanner import WebScanner

        scanner = WebScanner()
        scanner.tech_detector = MagicMock()
        scanner.tech_detector.detect.return_value = {}
        scanner.endpoint_discovery = MagicMock()
        scanner.endpoint_discovery.discover_apis.return_value = {}
        scanner.sensitive_detector = MagicMock()
        scanner.sensitive_detector.scan_url.return_value = {}

        with patch(
            "modules.web.headers_audit.SecurityHeadersAuditor",
            side_effect=RuntimeError("boom"),
        ):
            results = scanner.scan("example.com")

        assert "error" in results["headers_audit"]
