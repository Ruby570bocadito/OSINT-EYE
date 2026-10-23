"""ASN/netblock enumeration suite (100% offline).

Parsers against canned payloads; orchestration with a stubbed HTTPClient
and a stubbed resolver.
"""

import pytest

from core.scope import Scope
from modules.network.asn import (
    ASNEnumerator,
    parse_asn_from_network_info,
    parse_holder,
    parse_prefixes,
    parse_rdap_network,
)

NETWORK_INFO = {"data": {"asn": 15169, "block": {"desc": "Google LLC"}}}
AS_OVERVIEW = {"data": {"holder": "GOOGLE, US"}}
ANNOUNCED = {
    "data": {
        "prefixes": [
            {"prefix": "142.250.0.0/15"},
            {"prefix": "8.8.8.0/24"},
            {"prefix": "142.250.0.0/15"},  # duplicate
            {"prefix": "2607:f8b0::/32"},
        ]
    }
}
RDAP_NET = {
    "handle": "NET-8-8-8-0-1",
    "name": "GOOGLE",
    "country": "US",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "type": "DIRECT ALLOCATION",
    " remarks": "ignored",
}


class TestParsers:
    def test_parse_asn(self):
        assert parse_asn_from_network_info(NETWORK_INFO) == "AS15169"
        assert parse_asn_from_network_info({}) is None
        assert parse_asn_from_network_info({"data": {"asn": "no"}}) is None
        assert parse_asn_from_network_info({"data": {"asn": 0}}) is None

    def test_parse_holder(self):
        assert parse_holder(AS_OVERVIEW) == "GOOGLE, US"
        assert parse_holder({}) is None
        assert parse_holder({"data": {"holder": "   "}}) is None

    def test_parse_prefixes_dedupes_and_sorts(self):
        prefixes = parse_prefixes(ANNOUNCED)
        assert prefixes == ["142.250.0.0/15", "2607:f8b0::/32", "8.8.8.0/24"]
        assert parse_prefixes({}) == []
        assert parse_prefixes({"data": {"prefixes": None}}) == []

    def test_parse_rdap_network(self):
        network = parse_rdap_network(RDAP_NET)
        assert network["name"] == "GOOGLE"
        assert network["country"] == "US"
        assert network["start_address"] == "8.8.8.0"
        assert network["end_address"] == "8.8.8.255"
        assert network["network_type"] == "DIRECT ALLOCATION"
        assert network["handle"] == "NET-8-8-8-0-1"
        # Malformed keys are ignored.
        assert parse_rdap_network({}) == {}


class TestScanOrchestration:
    def _patch_session(self, monkeypatch, scanner, pages):
        calls = []

        def fake_get(url, timeout=None):
            calls.append(url)
            status, payload = pages[url]
            return type(
                "Resp", (), {"status_code": status, "json": lambda s, p=payload: p}
            )()

        monkeypatch.setattr(scanner.session, "get", fake_get)
        return calls

    def test_full_success(self, monkeypatch):
        scanner = ASNEnumerator()
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://rdap.org/ip/8.8.8.8": (200, RDAP_NET),
                "https://stat.ripe.net/data/network-info/data.json?ip=8.8.8.8": (
                    200,
                    NETWORK_INFO,
                ),
                "https://stat.ripe.net/data/as-overview/data.json?resource=AS15169": (
                    200,
                    AS_OVERVIEW,
                ),
                "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169": (
                    200,
                    ANNOUNCED,
                ),
            },
        )

        results = scanner.scan("8.8.8.8")

        assert results["ip"] == "8.8.8.8"
        assert results["asn"] == "AS15169"
        assert results["holder"] == "GOOGLE, US"
        assert results["prefix_count"] == 3
        assert results["prefixes"] == ["142.250.0.0/15", "2607:f8b0::/32", "8.8.8.0/24"]
        assert results["network"]["name"] == "GOOGLE"
        assert sorted(results["sources"]) == ["rdap", "ripestat"]
        assert results["errors"] == {}

    def test_ripestat_failure_keeps_rdap(self, monkeypatch):
        scanner = ASNEnumerator()
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://rdap.org/ip/8.8.8.8": (200, RDAP_NET),
                "https://stat.ripe.net/data/network-info/data.json?ip=8.8.8.8": (
                    500,
                    {},
                ),
            },
        )

        results = scanner.scan("8.8.8.8")

        assert results["network"]["name"] == "GOOGLE"
        assert results["asn"] is None
        assert results["prefixes"] == []
        assert results["errors"]["ripestat.network-info"] == "HTTP 500"

    def test_rdap_failure_keeps_ripestat(self, monkeypatch):
        scanner = ASNEnumerator()
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://rdap.org/ip/8.8.8.8": (503, {}),
                "https://stat.ripe.net/data/network-info/data.json?ip=8.8.8.8": (
                    200,
                    NETWORK_INFO,
                ),
                "https://stat.ripe.net/data/as-overview/data.json?resource=AS15169": (
                    200,
                    AS_OVERVIEW,
                ),
                "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169": (
                    200,
                    ANNOUNCED,
                ),
            },
        )

        results = scanner.scan("8.8.8.8")

        assert results["network"] == {}
        assert results["errors"]["rdap"] == "HTTP 503"
        assert results["asn"] == "AS15169"
        assert results["prefix_count"] == 3

    def test_unresolvable_domain_degrades(self, monkeypatch):
        scanner = ASNEnumerator()

        import modules.network.asn as asn_module

        def fake_gethostbyname(host):
            raise OSError("NXDOMAIN")

        monkeypatch.setattr(asn_module.socket, "gethostbyname", fake_gethostbyname)

        def must_not_fetch(url, timeout=None):
            raise AssertionError("no lookup without a resolved IP")

        monkeypatch.setattr(scanner.session, "get", must_not_fetch)

        results = scanner.scan("missing.example.com")

        assert results["ip"] is None
        assert "resolve" in results["errors"]
        assert results["prefixes"] == []

    def test_domain_resolved_then_looked_up(self, monkeypatch):
        scanner = ASNEnumerator()

        import modules.network.asn as asn_module

        monkeypatch.setattr(
            asn_module.socket, "gethostbyname", lambda host: "8.8.8.8"
        )
        self._patch_session(
            monkeypatch,
            scanner,
            {
                "https://rdap.org/ip/8.8.8.8": (200, RDAP_NET),
                "https://stat.ripe.net/data/network-info/data.json?ip=8.8.8.8": (
                    200,
                    NETWORK_INFO,
                ),
                "https://stat.ripe.net/data/as-overview/data.json?resource=AS15169": (
                    200,
                    AS_OVERVIEW,
                ),
                "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS15169": (
                    200,
                    ANNOUNCED,
                ),
            },
        )

        results = scanner.scan("dns.google")

        assert results["ip"] == "8.8.8.8"
        assert results["asn"] == "AS15169"

    def test_out_of_scope_never_resolved(self, monkeypatch):
        scanner = ASNEnumerator()

        def must_not_resolve(host):
            raise AssertionError("out-of-scope target must not be resolved")

        import modules.network.asn as asn_module

        monkeypatch.setattr(asn_module.socket, "gethostbyname", must_not_resolve)

        scope = Scope(includes=["other.com"])
        results = scanner.scan("example.com", scope=scope)

        assert results["ip"] is None
        assert results["asn"] is None
        assert scope.discarded[0]["module"] == "asn_enum"

    def test_connection_error_degrades_per_source(self, monkeypatch):
        scanner = ASNEnumerator()

        def fake_get(url, timeout=None):
            raise ConnectionError("unreachable")

        monkeypatch.setattr(scanner.session, "get", fake_get)

        results = scanner.scan("8.8.8.8")

        assert results["ip"] == "8.8.8.8"  # literal IP, no DNS needed
        assert "unreachable" in results["errors"]["rdap"]
        assert "unreachable" in results["errors"]["ripestat.network-info"]
        assert results["sources"] == []
