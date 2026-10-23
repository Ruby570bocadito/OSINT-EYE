"""Offline tests for reverse IP neighbours + virtual host discovery
(modules/network/reverse_ip.py).

HTTP is a fake client keyed by Host header; DNS resolution is always
monkeypatched (IP targets or stubbed resolvers). No network anywhere.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules.network.reverse_ip import (
    ReverseIPVHostScanner,
    extract_title,
    parse_reverse_ip,
)

IP = "93.184.216.34"
DOMAIN = "example.com"


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """Hard offline guarantee: any accidental DNS call fails loudly."""

    def deny(*args, **kwargs):
        raise OSError("dns disabled in tests")

    monkeypatch.setattr("modules.network.reverse_ip.socket.gethostbyname", deny)
    monkeypatch.setattr("modules.network.reverse_ip.socket.gethostbyaddr", deny)


class FakeHTTP:
    """Answers reverse-IP lookups and Host-header probes from a map."""

    def __init__(self, reverse_text="", probes=None):
        # probes: {host: (status, body, server)}
        self.probes = probes or {}
        self.reverse_text = reverse_text
        self.reverse_calls = 0
        self.hosts_seen = []

    def get(self, url, headers=None, params=None, timeout=None, **kwargs):
        if url.startswith("https://api.hackertarget.com"):
            self.reverse_calls += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.text = self.reverse_text
            return resp
        host = (headers or {}).get("Host")
        self.hosts_seen.append(host)
        status, body, server = self.probes.get(host, (None, None, None))
        if status is None:
            raise OSError("connection refused")
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        resp.headers = {"Server": server} if server else {}
        return resp


class DenyScope:
    """Scope double: denies anything except the entries in `ok`."""

    def __init__(self, ok):
        self.ok = set(ok)
        self.discarded = []

    def allows(self, target):
        return target in self.ok

    def discard(self, target, module=""):
        self.discarded.append((target, module))


# ─────────────────────────────────────────────────────────────────────────────
# Reverse IP parsing
# ─────────────────────────────────────────────────────────────────────────────
class TestParseReverseIp:
    def test_parses_hostname_lines(self):
        text = "www.other.com\nmail.other.com\n93-184-216-34.static.host.net\n"
        assert parse_reverse_ip(text) == [
            "www.other.com",
            "mail.other.com",
            "93-184-216-34.static.host.net",
        ]

    def test_drops_error_messages_and_junk(self):
        text = "error check your API rate limit\nsomething with spaces\n-\n"
        assert parse_reverse_ip(text) == []

    def test_empty_answer(self):
        assert parse_reverse_ip("") == []
        assert parse_reverse_ip(None) == []

    def test_dedupes_and_lowercases(self):
        assert parse_reverse_ip("WWW.x.com\nwww.x.com\n") == ["www.x.com"]


# ─────────────────────────────────────────────────────────────────────────────
# Title helper
# ─────────────────────────────────────────────────────────────────────────────
class TestExtractTitle:
    def test_extracts_and_normalises(self):
        assert extract_title("<html><title>  Hi\n there </title>") == "Hi there"

    def test_none_when_missing(self):
        assert extract_title("<p>no title</p>") is None
        assert extract_title("") is None


# ─────────────────────────────────────────────────────────────────────────────
# Full scan
# ─────────────────────────────────────────────────────────────────────────────
BASE_BODY = "<html><title>Default</title>hello</html>"

def _scanner(http, labels=None):
    return ReverseIPVHostScanner(
        http=http, labels=labels if labels is not None else ["www", "mail"], max_workers=2
    )


class TestScan:
    def test_ip_target_reverse_and_vhosts(self, monkeypatch):
        monkeypatch.setattr(
            "modules.network.reverse_ip.socket.gethostbyaddr",
            lambda ip: ("ptr.example.net", [], [ip]),
        )
        http = FakeHTTP(
            reverse_text="one.neighbour.net\ntwo.neighbour.net\nerror line!\n",
            probes={
                IP: (200, BASE_BODY, "nginx"),
                "ptr.example.net": (200, "<html><title> PTR host </title>zzzz", "apache"),
            },
        )
        scanner = _scanner(http, labels=[])
        result = scanner.scan(IP)
        assert result["target"] == IP
        assert result["ip"] == IP
        assert result["reverse_ip"]["status"] == "ok"
        assert result["reverse_ip"]["neighbors"] == ["one.neighbour.net", "two.neighbour.net"]
        vhosts = result["vhosts"]
        assert vhosts["status"] == "ok"
        assert vhosts["baseline"]["title"] == "Default"
        assert vhosts["tested"] == 1  # the PTR name, self-derived
        assert vhosts["found"][0]["host"] == "ptr.example.net"
        assert result["summary"]["vhosts_found"] == 1
        assert result["summary"]["neighbors"] == 2

    def test_explicit_candidates_added(self):
        http = FakeHTTP(
            reverse_text="",
            probes={
                IP: (200, BASE_BODY, "nginx"),
                "app.example.com": (200, "<html><title>App</title>" + "z" * 400, "nginx"),
            },
        )
        result = _scanner(http, labels=[]).scan(IP, candidates=["app.example.com"])
        assert result["vhosts"]["tested"] == 1
        assert result["vhosts"]["found"][0]["host"] == "app.example.com"

    def test_identical_response_is_not_a_vhost(self):
        http = FakeHTTP(
            reverse_text="",
            probes={
                IP: (200, BASE_BODY, "nginx"),
                "clone.example.com": (200, BASE_BODY, "nginx"),
            },
        )
        result = _scanner(http, labels=[]).scan(IP, candidates=["clone.example.com"])
        assert result["vhosts"]["found"] == []

    def test_reverse_ip_rate_limit_degrades(self):
        http = FakeHTTP(reverse_text="error check your API rate limit", probes={IP: (200, BASE_BODY, "nginx")})
        result = _scanner(http, labels=[]).scan(IP)
        assert result["reverse_ip"]["status"] == "error"
        assert "unparseable" in result["reverse_ip"]["reason"]
        assert result["vhosts"]["status"] == "ok"  # vhost probing unaffected

    def test_reverse_ip_http_error_degrades(self):
        http = FakeHTTP(reverse_text="", probes={IP: (200, BASE_BODY, "nginx")})
        http.reverse_text = ""
        # Simulate a 5xx by patching the fake's reverse answer status.
        orig_get = http.get

        def get(url, **kwargs):
            if url.startswith("https://api.hackertarget.com"):
                resp = MagicMock()
                resp.status_code = 429
                resp.text = "rate limited"
                return resp
            return orig_get(url, **kwargs)

        http.get = get
        result = _scanner(http, labels=[]).scan(IP)
        assert result["reverse_ip"]["status"] == "error"
        assert "429" in result["reverse_ip"]["reason"]

    def test_baseline_failure_means_no_vhost_probing(self):
        http = FakeHTTP(reverse_text="one.neighbour.net", probes={})
        result = _scanner(http, labels=["www"]).scan(IP, candidates=["www.example.com"])
        assert result["vhosts"]["status"] == "error"
        assert "baseline" in result["vhosts"]["reason"]
        assert result["vhosts"]["tested"] == 0

    def test_scope_denies_entry(self):
        http = FakeHTTP(reverse_text="", probes={})
        scope = DenyScope(ok=set())  # everything denied
        result = _scanner(http).scan(IP, scope=scope)
        assert result["ip"] is None
        assert result["reverse_ip"]["status"] == "error"  # untouched default
        assert http.reverse_calls == 0  # never queried

    def test_scope_allows_entry_filters_candidates(self, monkeypatch):
        monkeypatch.setattr(
            "modules.network.reverse_ip.socket.gethostbyname", lambda h: IP
        )
        http = FakeHTTP(
            reverse_text="",
            probes={
                IP: (200, BASE_BODY, "nginx"),
                f"www.{DOMAIN}": (200, "<title>WWW</title>" + "y" * 300, "nginx"),
            },
        )
        scope = DenyScope(ok={DOMAIN, IP, f"www.{DOMAIN}", f"mail.{DOMAIN}"})
        scanner = ReverseIPVHostScanner(http=http, labels=["www", "mail", "dev"], max_workers=2)
        result = scanner.scan(DOMAIN, scope=scope)
        # example.com/www/mail allowed; dev.example.com denied by scope
        assert result["vhosts"]["tested"] == 3
        assert any(f["host"] == f"www.{DOMAIN}" for f in result["vhosts"]["found"])
        assert scope.discarded == [(f"dev.{DOMAIN}", "reverse_ip_vhosts")]

    def test_unresolvable_target_degrades_cleanly(self):
        # The autouse _no_dns fixture makes every resolution fail.
        http = FakeHTTP()
        result = _scanner(http).scan(DOMAIN)
        assert result["ip"] is None
        assert "resolve" in result["errors"]
        assert http.reverse_calls == 0

    def test_ip_target_with_no_candidates_reports_reason(self):
        http = FakeHTTP(reverse_text="", probes={IP: (200, BASE_BODY, "nginx")})
        result = _scanner(http, labels=[]).scan(IP)
        assert result["vhosts"]["status"] == "ok"
        assert "no vhost candidates" in result["vhosts"]["reason"]

    def test_no_exception_when_source_down(self):
        http = MagicMock()
        http.get.side_effect = OSError("network down")
        result = _scanner(http, labels=[]).scan(IP)
        assert result["reverse_ip"]["status"] == "error"
        assert "network down" in result["reverse_ip"]["reason"]
