"""Offline tests for the public breach metadata check
(modules/osint/leak_check.py).

HTTP is a fake client with a canned breach catalogue; no network.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules.osint.leak_check import LeakChecker, parse_breaches, strip_html

DOMAIN = "example.com"


def _resp(status=200, payload=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload if payload is not None else []
    resp.text = ""
    return resp


CATALOGUE = [
    {
        "Name": "ExampleCorp-2019",
        "Title": "Example Corp",
        "Domain": "example.com",
        "BreachDate": "2019-01-01",
        "PwnCount": 1500000,
        "DataClasses": ["Email addresses", "Passwords"],
        "Description": 'A breach of <strong>Example Corp</strong> &quot;services&quot;.',
        "IsVerified": True,
        "IsSensitive": False,
    },
    {
        "Name": "OtherCo",
        "Title": "Other Company Ltd",
        "Domain": "other.com",
        "BreachDate": "2020-05-05",
        "PwnCount": 42000,
        "DataClasses": ["Email addresses"],
        "Description": "Mentions the Example Corporation indirectly.",
        "IsVerified": True,
        "IsSensitive": False,
    },
    {
        "Name": "NoDomain",
        "Title": "Paste collection",
        "Domain": None,
        "BreachDate": "2021-01-01",
        "PwnCount": None,
        "DataClasses": [],
        "Description": "Aggregated pastes.",
        "IsVerified": False,
        "IsSensitive": False,
    },
]


class FakeHTTP:
    def __init__(self, response=None, exc=None):
        self.response = response or _resp(200, CATALOGUE)
        self.exc = exc
        self.calls = []

    def get(self, url, timeout=None, **kwargs):
        self.calls.append(url)
        if self.exc:
            raise self.exc
        return self.response


class TestHelpers:
    def test_strip_html(self):
        assert strip_html('<strong>A</strong> &quot;B&quot;\n C') == 'A "B" C'
        assert strip_html(None) == ""

    def test_parse_breaches_validates(self):
        breaches = parse_breaches(CATALOGUE)
        assert len(breaches) == 3
        assert breaches[0]["domain"] == "example.com"
        assert breaches[0]["description"] == 'A breach of Example Corp "services".'
        # junk entries dropped
        assert parse_breaches(["junk", {"Title": "no name"}, None]) == []
        assert parse_breaches({"not": "a list"}) == []

    def test_parse_breaches_no_html_escapes_leak(self):
        breaches = parse_breaches(CATALOGUE)
        assert "<" not in breaches[0]["description"]
        assert "&quot;" not in breaches[0]["description"]


class TestScan:
    def test_exact_domain_match(self):
        result = LeakChecker(http=FakeHTTP()).scan(DOMAIN)
        assert result["status"] == "ok"
        assert result["catalogue_size"] == 3
        assert [b["name"] for b in result["domain_breaches"]] == ["ExampleCorp-2019"]
        assert result["summary"]["exact_domain_breaches"] == 1
        assert result["summary"]["total_records"] == 1500000
        # domain match excluded from the heuristic layer
        assert all(m["breach"] != "ExampleCorp-2019" for m in result["name_mentions"])

    def test_name_mention_heuristic(self):
        result = LeakChecker(http=FakeHTTP()).scan(DOMAIN)
        mentions = result["name_mentions"]
        assert mentions and mentions[0]["breach"] == "OtherCo"
        assert mentions[0]["matched_name"] == "example"
        assert mentions[0]["field"] == "description"

    def test_short_names_never_match(self):
        # 'm'/'app' style labels would match nearly every description.
        result = LeakChecker(http=FakeHTTP()).scan("m.co", names=["m", "app"])
        assert result["name_mentions"] == []
        assert result["domain_breaches"] == []

    def test_no_matches_at_all(self):
        http = FakeHTTP(_resp(200, [{"Name": "X", "Title": "Unrelated", "Domain": "zzz.io", "Description": "nothing"}]))
        result = LeakChecker(http=http).scan(DOMAIN)
        assert result["status"] == "ok"
        assert result["summary"]["exact_domain_breaches"] == 0
        assert result["summary"]["name_mentions"] == 0

    def test_rate_limit_degrades(self):
        result = LeakChecker(http=FakeHTTP(_resp(429, []))).scan(DOMAIN)
        assert result["status"] == "error"
        assert "catalogue" in result["errors"]
        assert "rate limited" in result["errors"]["catalogue"]

    def test_gated_endpoint_degrades(self):
        result = LeakChecker(http=FakeHTTP(_resp(403, []))).scan(DOMAIN)
        assert result["status"] == "error"
        assert "403" in result["errors"]["catalogue"]

    def test_network_failure_degrades(self):
        result = LeakChecker(http=FakeHTTP(exc=OSError("network down"))).scan(DOMAIN)
        assert result["status"] == "error"
        assert "network down" in result["errors"]["catalogue"]

    def test_malformed_payload_degrades(self):
        http = FakeHTTP(_resp(200, {"unexpected": "dict"}))
        result = LeakChecker(http=http).scan(DOMAIN)
        assert result["status"] == "ok"
        assert result["catalogue_size"] == 0

    def test_scope_denies_entry(self):
        class Scope:
            def allows(self, target):
                return False

            def discard(self, target, module=""):
                pass

        http = FakeHTTP()
        result = LeakChecker(http=http).scan(DOMAIN, scope=Scope())
        assert result["status"] == "error"  # untouched default
        assert http.calls == []  # catalogue never fetched

    def test_notes_present_and_metadata_only(self):
        result = LeakChecker(http=FakeHTTP()).scan(DOMAIN)
        assert any("no credentials" in n for n in result["notes"])

    def test_single_catalogue_request_per_scan(self):
        http = FakeHTTP()
        LeakChecker(http=http).scan(DOMAIN)
        assert len(http.calls) == 1
