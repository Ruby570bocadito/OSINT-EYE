"""Offline regression tests for the SSRF guard (SEG).

`modules/web/ssrf_guard.py` must refuse every URL or redirect hop whose
host resolves to loopback/private/link-local/multicast/reserved space
(cloud metadata 169.254.169.254 included), and the collectors wired to it
must degrade gracefully when a hop is refused. No network: hostnames are
resolved through a monkeypatched `_resolve` and HTTP is simulated with
scripted fake sessions.
"""

import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import modules.dns.subdomain_permutator as permutator_module
import modules.web.ssrf_guard as ssrf_guard
from modules.web.ssrf_guard import SSRFBlockedError, is_public_http_url, safe_get
from modules.web.web_scanner import TechDetector
from modules.osint.cloud_email import CDNDetector
from modules.dns.subdomain_permutator import SubdomainTakeoverDetector


# --- fakes (offline stand-ins for requests objects) -------------------------

class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()
        self.url = ""
        self.history = []

    @property
    def is_redirect(self):
        return "Location" in self.headers and self.status_code in (301, 302, 303, 307, 308)

    @property
    def is_permanent_redirect(self):
        return "Location" in self.headers and self.status_code in (301, 308)


class FakeSession:
    """Scripted session: one FakeResponse per request, records every URL."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.requested = []

    def get(self, url, timeout=None, allow_redirects=True, **kwargs):
        # safe_get must manage redirects itself, hop by hop.
        assert allow_redirects is False, "safe_get must disable auto redirects"
        self.requested.append(url)
        response = self._responses.pop(0)
        response.url = url
        return response


# --- is_public_http_url ------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://100.100.100.200/metadata/v1",  # some cloud metadata services
    "http://metadata.google.internal/",    # non-resolvable here → refused
    "http://127.0.0.1/",
    "http://127.8.8.8/",
    "http://10.0.0.5/",
    "http://172.16.0.9/",
    "http://192.168.1.1/",
    "http://0.0.0.0/",
    "http://100.64.1.1/",
    "http://198.18.0.3/",
    "http://224.0.0.1/",
    "http://240.0.0.1/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:10.0.0.1]/",
])
def test_non_public_literal_urls_refused(url):
    assert is_public_http_url(url) is False


@pytest.mark.parametrize("url", [
    "http://93.184.216.34/",
    "http://8.8.8.8/",
    "http://1.1.1.1/",
    "http://[2620:fe::fe]/",
    "https://203.0.114.10/x",  # TEST-NET-3 ends at 203.0.113.255; 114 is public
])
def test_public_literal_urls_accepted(url):
    assert is_public_http_url(url) is True


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://8.8.8.8/",
    "gopher://127.0.0.1",
    "http:///no-host",
    "http://[::1",
    "not a url",
])
def test_malformed_or_non_http_urls_refused(url):
    assert is_public_http_url(url) is False


def test_hostname_resolving_to_metadata_refused():
    with patch.object(ssrf_guard, "_resolve", lambda host: {"169.254.169.254"}):
        assert is_public_http_url("http://attacker.example/") is False


def test_hostname_with_one_private_answer_refused():
    with patch.object(ssrf_guard, "_resolve",
                      lambda host: {"93.184.216.34", "10.0.0.1"}):
        assert is_public_http_url("http://mixed.example/") is False


def test_hostname_resolving_public_accepted():
    with patch.object(ssrf_guard, "_resolve", lambda host: {"93.184.216.34"}):
        assert is_public_http_url("http://target.example/") is True


def test_unresolvable_hostname_refused():
    with patch.object(ssrf_guard, "_resolve", lambda host: None):
        assert is_public_http_url("http://does-not-resolve.example/") is False


# --- safe_get ----------------------------------------------------------------

def test_safe_get_returns_response_without_redirects():
    session = FakeSession([FakeResponse(200, text="ok")])
    resp = safe_get(session, "http://93.184.216.34/")
    assert resp.status_code == 200
    assert session.requested == ["http://93.184.216.34/"]
    assert resp.history == []


def test_safe_get_follows_public_redirect_chain():
    script = [
        FakeResponse(302, {"Location": "http://93.184.216.34/b/"}),
        FakeResponse(301, {"Location": "http://93.184.216.34/c/"}),
        FakeResponse(200, text="done"),
    ]
    session = FakeSession(script)
    resp = safe_get(session, "http://93.184.216.34/a/")
    assert resp.status_code == 200
    assert len(session.requested) == 3
    assert [h.url for h in resp.history] == [
        "http://93.184.216.34/a/",
        "http://93.184.216.34/b/",
    ]


def test_safe_get_blocks_private_redirect_and_never_requests_it():
    session = FakeSession([
        FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/"}),
        FakeResponse(200, text="metadata leak"),  # must stay unconsumed
    ])
    with pytest.raises(SSRFBlockedError):
        safe_get(session, "http://93.184.216.34/redirect")
    assert session.requested == ["http://93.184.216.34/redirect"]


def test_safe_get_blocks_relative_redirect_to_private_host():
    session = FakeSession([
        FakeResponse(302, {"Location": "//10.0.0.1/admin"}),
        FakeResponse(200, text="leak"),  # must stay unconsumed
    ])
    with pytest.raises(SSRFBlockedError):
        safe_get(session, "http://93.184.216.34/")
    assert session.requested == ["http://93.184.216.34/"]


def test_safe_get_blocks_scheme_downgrade_via_redirect():
    session = FakeSession([
        FakeResponse(302, {"Location": "file:///etc/passwd"}),
        FakeResponse(200),  # must stay unconsumed
    ])
    with pytest.raises(SSRFBlockedError):
        safe_get(session, "http://93.184.216.34/")
    assert session.requested == ["http://93.184.216.34/"]


def test_safe_get_rejects_non_public_initial_url():
    session = FakeSession([FakeResponse(200)])
    with pytest.raises(SSRFBlockedError):
        safe_get(session, "http://127.0.0.1:8080/")
    assert session.requested == []


def test_safe_get_too_many_redirects():
    script = [
        FakeResponse(302, {"Location": f"http://93.184.216.34/hop{i}/"})
        for i in range(10)
    ] + [FakeResponse(200)]
    session = FakeSession(script)
    with pytest.raises(SSRFBlockedError):
        safe_get(session, "http://93.184.216.34/start/")
    assert len(session.requested) == ssrf_guard.MAX_REDIRECTS + 1


def test_safe_get_malformed_location_blocked():
    session = FakeSession([
        FakeResponse(302, {"Location": "http://["}),
        FakeResponse(200),  # must stay unconsumed
    ])
    with pytest.raises(SSRFBlockedError):
        safe_get(session, "http://93.184.216.34/")


def test_safe_get_redirect_without_location_returns_response():
    session = FakeSession([FakeResponse(302)])
    resp = safe_get(session, "http://93.184.216.34/")
    assert resp.status_code == 302


# --- wiring: collectors degrade gracefully and never touch private hops ------

def test_tech_detector_refuses_private_redirect():
    detector = TechDetector(timeout=5)
    session = FakeSession([
        FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/"}),
        FakeResponse(200),  # must stay unconsumed
    ])
    detector.session = session
    result = detector.detect("http://93.184.216.34/")
    assert "SSRF" in result["error"]
    assert session.requested == ["http://93.184.216.34/"]


def test_cdn_detector_refuses_private_redirect():
    detector = CDNDetector(timeout=5)
    session = FakeSession([
        FakeResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/"}),
        FakeResponse(200),  # must stay unconsumed
    ])
    detector.session = session
    result = detector.detect("http://93.184.216.34/")
    assert "SSRF" in result["error"]
    assert session.requested == ["http://93.184.216.34/"]


def test_takeover_check_blocked_redirect_reports_not_vulnerable():
    detector = SubdomainTakeoverDetector()

    def _blocked(session, url, **kwargs):
        raise SSRFBlockedError("SSRF guard: refusing non-public URL")

    with patch.object(permutator_module, "safe_get", _blocked):
        result = detector.check_takeover("dangling.example")
    assert result["vulnerable"] is False
    assert result["service"] is None


def test_takeover_check_still_detects_signatures():
    detector = SubdomainTakeoverDetector()
    seen = []

    def _ok(session, url, **kwargs):
        seen.append(url)
        return FakeResponse(200, text="NoSuchBucket. The specified bucket does not exist.")

    with patch.object(permutator_module, "safe_get", _ok):
        result = detector.check_takeover("dangling.example")
    assert result["vulnerable"] is True
    assert result["signature"] == "NoSuchBucket"
    assert seen == ["https://dangling.example"]
