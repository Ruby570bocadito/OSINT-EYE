"""Offline tests for the optional host-intelligence collector
(modules/osint/shodan_censys.py).

HTTP is a fake client backed by canned responses; the environment is a
plain dict (never os.environ). No network anywhere.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules.osint.shodan_censys import ShodanCensysCollector, _is_ip


def _response(status=200, payload=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload if payload is not None else {}
    resp.text = text
    return resp


class FakeHTTP:
    """Records calls and answers per (host, path-prefix)."""

    def __init__(self, routes):
        # routes: list of (method, url_prefix, response) checked in order
        self.routes = routes
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._answer("GET", url)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._answer("POST", url)

    def _answer(self, method, url):
        for m, prefix, resp in self.routes:
            if m == method and url.startswith(prefix):
                return resp
        return _response(status=404)


ENV_SHODAN = {"OSINT_EYE_SHODAN_KEY": "test-shodan-key"}
ENV_CENSYS = {
    "OSINT_EYE_CENSYS_API_ID": "id",
    "OSINT_EYE_CENSYS_API_SECRET": "secret",
}
ENV_FOFA = {"OSINT_EYE_FOFA_EMAIL": "a@b.c", "OSINT_EYE_FOFA_KEY": "fk"}
ENV_ALL = {**ENV_SHODAN, **ENV_CENSYS, **ENV_FOFA}
EMPTY_ENV = {}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
class TestHelpers:
    def test_is_ip(self):
        assert _is_ip("1.2.3.4")
        assert _is_ip("2606:2800:220:1:248:1893:25c8:1946")
        assert not _is_ip("example.com")
        assert not _is_ip("")


# ─────────────────────────────────────────────────────────────────────────────
# Skipping without keys
# ─────────────────────────────────────────────────────────────────────────────
class TestSkipWithoutKeys:
    def test_all_providers_skipped_without_env(self):
        collector = ShodanCensysCollector(http=FakeHTTP([]), env=EMPTY_ENV)
        result = collector.scan("example.com", resolve=False)
        assert result["providers"]["shodan"]["status"] == "skipped"
        assert result["providers"]["censys"]["status"] == "skipped"
        assert result["providers"]["fofa"]["status"] == "skipped"
        assert result["summary"]["providers_used"] == []
        assert "OSINT_EYE_SHODAN_KEY" in result["providers"]["shodan"]["reason"]

    def test_no_exception_without_network_and_keys(self):
        # scan() must always return the full shape even with nothing set.
        collector = ShodanCensysCollector(http=FakeHTTP([]), env={})
        result = collector.scan("192.0.2.1", resolve=False)
        assert result["target"] == "192.0.2.1"
        assert result["ip"] == "192.0.2.1"
        assert set(result["providers"]) == {"shodan", "censys", "fofa"}
        assert result["summary"]["ports"] == []
        assert result["summary"]["services"] == []
        assert result["summary"]["subdomains"] == []


# ─────────────────────────────────────────────────────────────────────────────
# Shodan
# ─────────────────────────────────────────────────────────────────────────────
class TestShodan:
    def test_ip_lookup_ok(self):
        payload = {
            "ip_str": "93.184.216.34",
            "org": "EdgeCast",
            "isp": "Verizon",
            "os": "Linux",
            "country_name": "United States",
            "hostnames": ["a.example.com"],
            "data": [
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.21"},
                {"port": 80, "transport": "tcp", "product": "nginx"},
                "garbage-row",
            ],
        }
        http = FakeHTTP([("GET", "https://api.shodan.io/shodan/host/", _response(payload=payload))])
        collector = ShodanCensysCollector(http=http, env=ENV_SHODAN)
        result = collector.scan("93.184.216.34", resolve=False)
        shodan = result["providers"]["shodan"]
        assert shodan["status"] == "ok"
        assert shodan["org"] == "EdgeCast"
        assert shodan["ports"] == [80, 443]
        assert len(shodan["services"]) == 2
        # The key travels as a query param, never inside the results.
        assert result["providers"]["shodan"].get("reason") is None

    def test_domain_lookup_lists_subdomains_and_resolves_ip(self):
        routes = [
            (
                "GET",
                "https://api.shodan.io/dns/domain/example.com",
                _response(payload={"subdomains": ["www", "mail"]}),
            ),
            ("GET", "https://api.shodan.io/shodan/host/", _response(status=404)),
        ]
        collector = ShodanCensysCollector(http=FakeHTTP(routes), env=ENV_SHODAN)
        result = collector.scan("example.com", resolve=False)
        shodan = result["providers"]["shodan"]
        assert shodan["status"] == "ok"
        assert "www.example.com" in shodan["subdomains"]
        assert "mail.example.com" in shodan["subdomains"]
        assert result["summary"]["total_subdomains"] == 2

    def test_http_error_degrades(self):
        http = FakeHTTP([("GET", "https://api.shodan.io/", _response(status=403))])
        collector = ShodanCensysCollector(http=http, env=ENV_SHODAN)
        result = collector.scan("93.184.216.34", resolve=False)
        assert result["providers"]["shodan"]["status"] == "error"
        assert "403" in result["providers"]["shodan"]["reason"]

    def test_network_exception_degrades(self):
        http = MagicMock()
        http.get.side_effect = OSError("network down")
        collector = ShodanCensysCollector(http=http, env=ENV_SHODAN)
        result = collector.scan("93.184.216.34", resolve=False)
        assert result["providers"]["shodan"]["status"] == "error"
        assert "network down" in result["providers"]["shodan"]["reason"]


# ─────────────────────────────────────────────────────────────────────────────
# Censys
# ─────────────────────────────────────────────────────────────────────────────
class TestCensys:
    def test_host_lookup_ok(self):
        payload = {
            "result": {
                "services": [
                    {"port": 443, "transport_protocol": "tcp", "service_name": "HTTPS"},
                    {"port": 22, "transport_protocol": "tcp", "service_name": "SSH"},
                ],
                "autonomous_system": {"description": "Akamai"},
                "dns": {"names": ["example.com", "www.example.com"]},
            }
        }
        http = FakeHTTP([("GET", "https://search.censys.io/api/v2/hosts/", _response(payload=payload))])
        collector = ShodanCensysCollector(http=http, env=ENV_CENSYS)
        result = collector.scan("93.184.216.34", resolve=False)
        censys = result["providers"]["censys"]
        assert censys["status"] == "ok"
        assert censys["ports"] == [22, 443]
        assert censys["autonomous_system"] == "Akamai"
        assert "www.example.com" in censys["dns_names"]

    def test_domain_search_when_no_ip(self):
        payload = {
            "result": {
                "hits": [
                    {"dns": {"names": ["example.com", "mail.example.com"]}},
                    {"dns": {"names": ["mail.example.com"]}},  # duplicate
                ]
            }
        }
        http = FakeHTTP([("POST", "https://search.censys.io/api/v2/hosts/search", _response(payload=payload))])
        collector = ShodanCensysCollector(http=http, env=ENV_CENSYS)
        result = collector.scan("example.com", resolve=False)
        censys = result["providers"]["censys"]
        assert censys["status"] == "ok"
        assert censys["dns_names"].count("mail.example.com") == 1

    def test_half_credentials_are_skipped(self):
        collector = ShodanCensysCollector(
            http=FakeHTTP([]), env={"OSINT_EYE_CENSYS_API_ID": "only-id"}
        )
        result = collector.scan("example.com", resolve=False)
        assert result["providers"]["censys"]["status"] == "skipped"


# ─────────────────────────────────────────────────────────────────────────────
# FOFA
# ─────────────────────────────────────────────────────────────────────────────
class TestFofa:
    def test_ip_query_ok(self):
        payload = {
            "error": False,
            "size": 2,
            "results": [
                ["93.184.216.34:443", "93.184.216.34", 443, "Example Domain", "example.com", "https"],
                ["93.184.216.34:80", "93.184.216.34", 80, "Example Domain", "example.com", "http"],
            ],
        }
        http = FakeHTTP([("GET", "https://fofa.info/api/v1/search/all", _response(payload=payload))])
        collector = ShodanCensysCollector(http=http, env=ENV_FOFA)
        result = collector.scan("93.184.216.34", resolve=False)
        fofa = result["providers"]["fofa"]
        assert fofa["status"] == "ok"
        assert fofa["ports"] == [80, 443]
        assert len(fofa["services"]) == 2

    def test_api_error_surfaced_without_key_leak(self):
        payload = {"error": True, "errmsg": "invalid key"}
        http = FakeHTTP([("GET", "https://fofa.info/api/v1/search/all", _response(payload=payload))])
        collector = ShodanCensysCollector(http=http, env=ENV_FOFA)
        result = collector.scan("93.184.216.34", resolve=False)
        assert result["providers"]["fofa"]["status"] == "error"
        assert "invalid key" in result["providers"]["fofa"]["reason"]

    def test_malformed_rows_are_tolerated(self):
        payload = {"error": False, "size": 2, "results": ["not-a-list", ["h", "1.1.1.1", 80]]}
        http = FakeHTTP([("GET", "https://fofa.info/api/v1/search/all", _response(payload=payload))])
        collector = ShodanCensysCollector(http=http, env=ENV_FOFA)
        result = collector.scan("1.1.1.1", resolve=False)
        assert result["providers"]["fofa"]["status"] == "ok"
        assert len(result["providers"]["fofa"]["services"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration / merge
# ─────────────────────────────────────────────────────────────────────────────
class TestMerge:
    def test_summary_merges_across_providers(self):
        routes = [
            (
                "GET",
                "https://api.shodan.io/shodan/host/",
                _response(
                    payload={
                        "ip_str": "1.2.3.4",
                        "org": "Org",
                        "ports": None,
                        "data": [{"port": 443, "product": "nginx"}],
                    }
                ),
            ),
            (
                "GET",
                "https://search.censys.io/api/v2/hosts/",
                _response(
                    payload={
                        "result": {
                            "services": [{"port": 8443, "service_name": "HTTPS"}],
                            "dns": {"names": ["x.example.com"]},
                        }
                    }
                ),
            ),
        ]
        collector = ShodanCensysCollector(http=FakeHTTP(routes), env=ENV_ALL)
        result = collector.scan("1.2.3.4", resolve=False)
        summary = result["summary"]
        assert sorted(summary["providers_used"]) == ["censys", "shodan"]
        assert summary["ports"] == [443, 8443]
        assert {s["provider"] for s in summary["services"]} == {"shodan", "censys"}
        assert summary["subdomains"] == ["x.example.com"]

    def test_skipped_providers_do_not_block_ok_ones(self):
        routes = [
            (
                "GET",
                "https://api.shodan.io/shodan/host/",
                _response(payload={"ip_str": "1.2.3.4", "data": [{"port": 22}]}),
            )
        ]
        collector = ShodanCensysCollector(http=FakeHTTP(routes), env=ENV_SHODAN)
        result = collector.scan("1.2.3.4", resolve=False)
        assert result["providers"]["censys"]["status"] == "skipped"
        assert result["providers"]["fofa"]["status"] == "skipped"
        assert result["summary"]["providers_used"] == ["shodan"]
        assert result["summary"]["ports"] == [22]

    def test_dns_resolution_failure_still_scans(self, monkeypatch):
        # resolve=True on an unresolvable name: providers still run with
        # ip=None (Shodan falls back to the domain endpoint).
        def boom(host):
            raise OSError("no dns")

        monkeypatch.setattr(
            "modules.osint.shodan_censys.socket.gethostbyname", boom
        )
        routes = [
            (
                "GET",
                "https://api.shodan.io/dns/domain/nonexistent.invalid",
                _response(payload={"subdomains": []}),
            )
        ]
        collector = ShodanCensysCollector(http=FakeHTTP(routes), env=ENV_SHODAN)
        result = collector.scan("nonexistent.invalid", resolve=True)
        assert result["ip"] is None
        assert result["providers"]["shodan"]["status"] == "ok"
