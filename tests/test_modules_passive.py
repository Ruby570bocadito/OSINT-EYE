"""Offline tests for passive subdomain sources (modules/dns/passive_sources.py).

No network: HTTP responses are fixed fixtures injected through a mocked
HTTPClient, covering happy paths, malformed payloads, source failures and
the merge/dedupe behaviour of DNSScanner in "full" mode.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules.dns.passive_sources import (
    SOURCES,
    PassiveSubdomainEnumerator,
    valid_subdomain,
)

DOMAIN = "example.com"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures: one fixed remote answer per source
# ─────────────────────────────────────────────────────────────────────────────
def _client_returning(text=None, json_data=None, status_code=200):
    """HTTPClient stand-in whose .get returns the fixed answer."""
    client = MagicMock()
    resp = MagicMock()
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
        resp.text = ""
    else:
        resp.text = text or ""
    client.get.return_value = resp
    return client


HACKERTARGET_TEXT = (
    "sub1.example.com,93.184.216.34\n"
    "Sub2.example.com,93.184.216.34\n"
    "www.example.com,93.184.216.34\n"
    "\n"
)
OTX_JSON = {
    "passive_dns": [
        {"hostname": "api.example.com", "address": "93.184.216.34"},
        {"hostname": "sub1.example.com", "address": "93.184.216.34"},
        {"hostname": "*.wild.example.com", "address": "93.184.216.34"},
    ]
}
ANUBIS_JSON = [
    "dev.example.com",
    "sub1.example.com",
    "not-a-sub.example.org",  # foreign domain → must be discarded
    42,                        # non-string → must be discarded
]
RAPIDDNS_HTML = """
<html><table>
<tr><td>mail.example.com</td><td>2024-06-01</td></tr>
<tr><td>sub1.example.com</td><td>2024-06-01</td></tr>
<tr><td>evil<script>alert(1)</script>.example.com</td></tr>
</table></html>
"""
CERTSPOTTER_JSON = [
    {"dns_names": ["vpn.example.com", "example.com", "other.example.net"]},
    {"dns_names": ["vpn.example.com"]},
    "garbage-entry",
]


class TestValidSubdomain:
    def test_accepts_plain_suffix(self):
        assert valid_subdomain("api.example.com", DOMAIN)

    def test_accepts_multi_level(self):
        assert valid_subdomain("a.b.c.example.com", DOMAIN)

    def test_rejects_bare_domain(self):
        assert not valid_subdomain("example.com", DOMAIN)

    def test_rejects_foreign_domain(self):
        assert not valid_subdomain("evil.com", DOMAIN)
        assert not valid_subdomain("example.com.evil.com", DOMAIN)

    def test_rejects_wildcards_and_injection(self):
        assert not valid_subdomain("*.example.com", DOMAIN)
        assert not valid_subdomain("x/<script>.example.com", DOMAIN)
        assert not valid_subdomain("a:8080.example.com", DOMAIN)
        assert not valid_subdomain("a b.example.com", DOMAIN)
        assert not valid_subdomain("a@b.example.com", DOMAIN)

    def test_rejects_non_string_and_garbage(self):
        assert not valid_subdomain(None, DOMAIN)
        assert not valid_subdomain(42, DOMAIN)
        assert not valid_subdomain("", DOMAIN)
        assert not valid_subdomain("." + DOMAIN, DOMAIN)

    def test_accepts_253_char_max_and_rejects_longer(self):
        label = "a" * 60
        host = f"{label}.{label}.{label}.{DOMAIN}"
        assert valid_subdomain(host, DOMAIN)
        long_host = ("x" * 60 + ".") * 6 + DOMAIN
        assert not valid_subdomain(long_host, DOMAIN)


# ─────────────────────────────────────────────────────────────────────────────
# Per-source parsing (fixed responses, no network)
# ─────────────────────────────────────────────────────────────────────────────
class TestSourceParsing:
    @staticmethod
    def _run_source(name, client, domain=DOMAIN):
        enum = PassiveSubdomainEnumerator(sources=[name])
        enum.http = client
        return enum.enumerate(domain)

    def test_hackertarget_parses_lines_and_normalises(self):
        result = self._run_source("hackertarget", _client_returning(HACKERTARGET_TEXT))
        hosts = result["per_source"]["hackertarget"]["hosts"]
        assert hosts == ["sub1.example.com", "sub2.example.com", "www.example.com"]
        assert result["total"] == 3

    def test_alienvault_otx_parses_and_drops_invalid(self):
        result = self._run_source("alienvault_otx", _client_returning(json_data=OTX_JSON))
        hosts = result["per_source"]["alienvault_otx"]["hosts"]
        assert "api.example.com" in hosts
        assert "sub1.example.com" in hosts
        assert not any("wild" in h for h in hosts)  # wildcard rejected
        assert result["per_source"]["alienvault_otx"]["status"] == "ok"

    def test_anubis_parses_list_and_drops_foreign(self):
        result = self._run_source("anubis", _client_returning(json_data=ANUBIS_JSON))
        hosts = result["per_source"]["anubis"]["hosts"]
        assert hosts == ["dev.example.com", "sub1.example.com"]
        assert result["per_source"]["anubis"]["status"] == "ok"

    def test_rapiddns_extracts_from_html(self):
        result = self._run_source("rapiddns", _client_returning(RAPIDDNS_HTML))
        hosts = result["per_source"]["rapiddns"]["hosts"]
        assert "mail.example.com" in hosts
        assert "sub1.example.com" in hosts
        # markup-injected hostnames never survive strict validation
        assert all("<" not in h and ">" not in h for h in hosts)

    def test_certspotter_extracts_dns_names(self):
        result = self._run_source("certspotter", _client_returning(json_data=CERTSPOTTER_JSON))
        hosts = result["per_source"]["certspotter"]["hosts"]
        assert hosts == ["vpn.example.com"]
        assert result["total"] == 1

    def test_http_error_marks_source_as_error(self):
        result = self._run_source("hackertarget", _client_returning(status_code=429))
        entry = result["per_source"]["hackertarget"]
        assert entry["status"] == "error"
        assert "429" in entry["error"]
        assert result["total"] == 0

    def test_malformed_json_is_an_error_not_a_crash(self):
        client = _client_returning(json_data=None)
        resp = client.get.return_value
        resp.status_code = 200
        resp.json.side_effect = ValueError("bad json")
        result = self._run_source("anubis", client)
        assert result["per_source"]["anubis"]["status"] == "error"

    def test_unexpected_payload_shape_is_error(self):
        result = self._run_source("anubis", _client_returning(json_data={"nope": 1}))
        assert result["per_source"]["anubis"]["status"] == "error"


# ─────────────────────────────────────────────────────────────────────────────
# Aggregation behaviour
# ─────────────────────────────────────────────────────────────────────────────
class TestAggregation:
    def test_sources_run_in_parallel_and_dedupe(self, monkeypatch):
        import modules.dns.passive_sources as ps

        fixtures = {
            "hackertarget": ["sub1.example.com", "www.example.com"],
            "alienvault_otx": ["sub1.example.com", "api.example.com"],
            "anubis": ["dev.example.com", "SUB1.example.com"],  # case → dedupe
            "rapiddns": ["mail.example.com", "sub1.example.com"],
            "certspotter": ["vpn.example.com"],
        }
        for name, hosts in fixtures.items():
            monkeypatch.setitem(
                ps.SOURCES, name, (lambda hs: (lambda c, d: list(hs)))(hosts)
            )

        enum = PassiveSubdomainEnumerator()
        result = enum.enumerate(DOMAIN)

        expected = sorted(
            {
                "sub1.example.com",
                "www.example.com",
                "api.example.com",
                "dev.example.com",
                "mail.example.com",
                "vpn.example.com",
            }
        )
        assert result["subdomains"] == expected
        assert result["subdomains"] == sorted(result["subdomains"])
        # dedupe across sources: sub1 appears in 4 fixtures but only once
        assert result["subdomains"].count("sub1.example.com") == 1
        assert result["total"] == 6
        assert set(result["per_source"]) == {
            "hackertarget",
            "alienvault_otx",
            "anubis",
            "rapiddns",
            "certspotter",
        }
        assert all(e["status"] == "ok" for e in result["per_source"].values())

    def test_all_sources_down_still_returns_valid_shape(self):
        enum = PassiveSubdomainEnumerator()
        enum.http = MagicMock()
        enum.http.get.side_effect = ConnectionError("network down")
        result = enum.enumerate(DOMAIN)
        assert result["domain"] == DOMAIN
        assert result["subdomains"] == []
        assert result["total"] == 0
        assert all(
            e["status"] == "error" for e in result["per_source"].values()
        )

    def test_unknown_source_rejected_early(self):
        with pytest.raises(ValueError):
            PassiveSubdomainEnumerator(sources=["no-existe"])

    def test_explicit_source_subset(self):
        enum = PassiveSubdomainEnumerator(sources=["hackertarget"])
        assert enum.source_names == ["hackertarget"]


# ─────────────────────────────────────────────────────────────────────────────
# DNSScanner integration ("full" mode merge + dedupe)
# ─────────────────────────────────────────────────────────────────────────────
class TestDNSScannerIntegration:
    def _scanner_with_fakes(self):
        from modules.dns import DNSScanner

        scanner = DNSScanner(passive=True)
        scanner.resolver = MagicMock()
        scanner.resolver.get_all_records.return_value = {
            "A": ["93.184.216.34"]
        }
        scanner.resolver.check_spf.return_value = {"exists": False}
        scanner.resolver.check_dmarc.return_value = {"exists": False}
        scanner.subenum = MagicMock()
        scanner.subenum.enumerate.return_value = ["www.example.com", "sub1.example.com"]
        scanner.zonetransfer = MagicMock()
        scanner.zonetransfer.check_axfr_enabled.return_value = {"vulnerable": False}
        scanner.passive_enumerator = MagicMock()
        scanner.passive_enumerator.enumerate.return_value = {
            "domain": DOMAIN,
            "subdomains": ["sub1.example.com", "api.example.com"],
            "per_source": {"hackertarget": {"count": 2, "status": "ok"}},
            "total": 2,
        }
        return scanner

    def test_full_scan_merges_and_dedupes(self):
        scanner = self._scanner_with_fakes()
        result = scanner.scan(DOMAIN, "full")
        assert result["subdomains"] == [
            "api.example.com",
            "sub1.example.com",
            "www.example.com",
        ]
        assert result["passive_subdomains"]["total"] == 2

    def test_full_scan_survives_passive_failure(self):
        scanner = self._scanner_with_fakes()
        scanner.passive_enumerator.enumerate.side_effect = RuntimeError("boom")
        result = scanner.scan(DOMAIN, "full")
        # bruteforce results survive (deduped, no passive pollution),
        # passive degrades to an empty shape with the error recorded
        assert set(result["subdomains"]) == {"sub1.example.com", "www.example.com"}
        assert result["passive_subdomains"]["subdomains"] == []
        assert "error" in result["passive_subdomains"]

    def test_passive_disabled_keeps_classic_shape(self):
        from modules.dns import DNSScanner

        scanner = DNSScanner(passive=False)
        assert scanner.passive_enumerator is None
