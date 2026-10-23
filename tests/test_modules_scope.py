"""Scope enforcement in collector modules (100% offline).

Derived targets (wordlist bruteforce, permutations, vhosts, JS files,
bucket names, endpoint URLs) must pass the operator scope (core.scope)
before anything is resolved or requested. Rejections land in the scope
discard audit log with the module label of the collector.
"""

import asyncio

import pytest

from core.scope import Scope
from modules._scope import allowed, apply_scope
from modules.dns import dns_scanner
from modules.dns.advanced_dns import JavaScriptEndpointDiscovery, VirtualHostBruteforcer
from modules.dns.dns_scanner import SubdomainEnumerator
from modules.dns.subdomain_permutator import SubdomainPermutator
from modules.osint.cloud_email import CloudBucketDetector, EmailEnumerator
from modules.web.web_scanner import EndpointDiscovery, WebScanner


def _record_resolves(monkeypatch, module, queried):
    """Patch socket.gethostbyname in ``module`` to record and 'resolve'."""

    def fake_gethostbyname(host):
        queried.append(host)
        return "93.184.216.34"

    monkeypatch.setattr(module.socket, "gethostbyname", fake_gethostbyname)


class TestScopeHelpers:
    def test_none_scope_allows_everything(self):
        assert allowed(None, "https://anything.example/") is True
        assert apply_scope(None, ["b", "a"], "m") == ["b", "a"]

    def test_rejection_recorded_in_discard_log(self):
        scope = Scope(includes=["example.com"])
        assert allowed(scope, "https://other.com/x", "mod_x") is False
        assert len(scope.discarded) == 1
        entry = scope.discarded[0]
        assert entry["module"] == "mod_x"
        assert entry["target"] == "https://other.com/x"
        assert entry["reason"]

    def test_broken_scope_fails_closed(self):
        class Broken:
            def allows(self, target):
                raise RuntimeError("boom")

        assert allowed(Broken(), "example.com", "m") is False

    def test_apply_scope_filters_and_keeps_order(self):
        scope = Scope(includes=["api.example.com"])
        targets = ["api.example.com", "www.example.com", "api.example.com"]
        assert apply_scope(scope, targets, "m") == ["api.example.com", "api.example.com"]


class TestSubdomainEnumeratorScope:
    def test_out_of_scope_candidates_never_resolved(self, monkeypatch):
        queried = []
        _record_resolves(monkeypatch, dns_scanner, queried)

        enum = SubdomainEnumerator()
        scope = Scope(includes=["api.example.com"])
        found = enum.enumerate("example.com", scope=scope)

        # The bundled wordlist also carries "v2.api", a subdomain of
        # api.example.com — the scope must allow it (domain rule match).
        assert queried and all(
            q == "api.example.com" or q.endswith(".api.example.com")
            for q in queried
        )
        assert found == sorted(set(queried))
        assert enum.wildcard_skipped == 0
        assert scope.discarded, "rejections must be auditable"
        assert all(d["module"] == "dns_bruteforce" for d in scope.discarded)

    def test_no_scope_resolves_all_candidates(self, tmp_path, monkeypatch):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("api\nwww\nmail\n")
        queried = []
        _record_resolves(monkeypatch, dns_scanner, queried)

        enum = SubdomainEnumerator(wordlist_path=str(wordlist))
        found = enum.enumerate("example.com")

        assert sorted(queried) == [
            "api.example.com",
            "mail.example.com",
            "www.example.com",
        ]
        assert found == sorted(queried)

    def test_scope_allowing_apex_keeps_every_candidate(self, monkeypatch):
        wordlist = __import__("pathlib").Path(
            SubdomainEnumerator.DEFAULT_WORDLIST
        )
        if not wordlist.exists():
            pytest.skip("bundled wordlist missing")
        queried = []
        _record_resolves(monkeypatch, dns_scanner, queried)

        enum = SubdomainEnumerator()
        scope = Scope(includes=["example.com"])
        found = enum.enumerate("example.com", scope=scope)

        assert len(queried) > 10
        assert all(q.endswith(".example.com") for q in queried)
        assert not scope.discarded
        assert found == sorted(set(queried))


class TestSubdomainPermutatorScope:
    def test_out_of_scope_permutations_never_resolved(self, monkeypatch):
        queried = []
        _record_resolves(monkeypatch, dns_scanner, queried)

        perm = SubdomainPermutator(threads=10)
        scope = Scope(includes=["api.example.com"])
        found = perm.enumerate("example.com", scope=scope)

        assert queried and all(
            q == "api.example.com" or q.endswith(".api.example.com")
            for q in queried
        )
        assert found == sorted(set(queried))
        assert all(d["module"] == "dns_permutations" for d in scope.discarded)

    def test_no_scope_probes_candidate_fqdn_unchanged(self, monkeypatch):
        queried = []
        _record_resolves(monkeypatch, dns_scanner, queried)

        perm = SubdomainPermutator(threads=10)
        perm.enumerate("a.com")

        assert queried, "expected at least one DNS probe"
        # Regression guard: candidates are full FQDNs and are probed as-is
        # (never doubled like "www.a.com.a.com").
        assert all(q.endswith(".a.com") and not q.endswith(".a.com.a.com") for q in queried)


class TestVirtualHostBruteforcerScope:
    def test_derived_candidates_filtered(self, monkeypatch):
        bf = VirtualHostBruteforcer()
        seen = []

        async def fake_check(ip, hostname, port=80):
            seen.append(hostname)
            return None

        monkeypatch.setattr(bf, "check_vhost", fake_check)

        scope = Scope(includes=["api.example.com"])
        results = asyncio.run(
            bf.bruteforce("192.0.2.10", domain="example.com", scope=scope)
        )

        assert results == []
        derived = [h for h in seen if h.endswith(".example.com") or h == "example.com"]
        assert derived == ["api.example.com"]
        assert all(d["module"] == "vhost_bruteforce" for d in scope.discarded)

    def test_no_scope_probes_every_derived_candidate(self, monkeypatch):
        bf = VirtualHostBruteforcer()
        seen = []

        async def fake_check(ip, hostname, port=80):
            seen.append(hostname)
            return None

        monkeypatch.setattr(bf, "check_vhost", fake_check)
        asyncio.run(bf.bruteforce("192.0.2.10", domain="example.com"))

        assert "www" in seen
        assert "www.example.com" in seen
        assert "example.com" in seen


class TestJavaScriptEndpointDiscoveryScope:
    def test_out_of_scope_js_files_not_fetched(self, monkeypatch):
        disc = JavaScriptEndpointDiscovery()
        js_urls = [
            "https://cdn.jsdelivr.net/npm/lib.js",
            "https://example.com/static/app.js",
        ]
        analyzed = []

        async def fake_fetch(base_url):
            return list(js_urls)

        async def fake_analyze(url):
            analyzed.append(url)
            return {"url": url, "endpoints": [], "internal_urls": [],
                    "secrets": [], "s3_buckets": [], "firebase": []}

        monkeypatch.setattr(disc, "fetch_js_files", fake_fetch)
        monkeypatch.setattr(disc, "analyze_js", fake_analyze)

        scope = Scope(includes=["example.com"])
        res = asyncio.run(disc.scan("https://example.com", scope=scope))

        assert res["js_files"] == ["https://example.com/static/app.js"]
        assert res["js_files_found"] == 1
        assert analyzed == ["https://example.com/static/app.js"]
        assert scope.discarded[0]["module"] == "js_endpoints"
        assert scope.discarded[0]["target"] == "https://cdn.jsdelivr.net/npm/lib.js"

    def test_no_scope_fetches_everything(self, monkeypatch):
        disc = JavaScriptEndpointDiscovery()
        js_urls = ["https://cdn.jsdelivr.net/npm/lib.js"]

        async def fake_fetch(base_url):
            return list(js_urls)

        async def fake_analyze(url):
            return {"url": url, "endpoints": [], "internal_urls": [],
                    "secrets": [], "s3_buckets": [], "firebase": []}

        monkeypatch.setattr(disc, "fetch_js_files", fake_fetch)
        monkeypatch.setattr(disc, "analyze_js", fake_analyze)

        res = asyncio.run(disc.scan("https://example.com"))
        assert res["js_files_found"] == 1


class TestCloudBucketDetectorScope:
    def test_out_of_scope_domain_skips_enumeration(self, monkeypatch):
        det = CloudBucketDetector()

        def must_not_run(*args, **kwargs):
            raise AssertionError("bucket probing must not run out of scope")

        monkeypatch.setattr(det, "_generate_bucket_names", must_not_run)

        scope = Scope(includes=["other.com"])
        res = det.scan("example.com", scope=scope)

        assert res == {
            "domain": "example.com",
            "found": [],
            "public": [],
            "listable": [],
            "total_tested": 0,
        }
        assert scope.discarded[0]["module"] == "cloud_buckets"
        assert scope.discarded[0]["target"] == "example.com"

    def test_in_scope_or_unrestricted_still_probes(self, monkeypatch):
        det = CloudBucketDetector()
        checked = []

        def fake_check(url, provider):
            checked.append(url)
            return {"url": url, "provider": provider, "exists": False,
                    "public": False, "listable": False, "status": 404,
                    "size": None}

        monkeypatch.setattr(det, "_check_bucket", fake_check)
        res = det.scan("example.com", scope=Scope(includes=["example.com"]))

        assert checked, "in-scope domain must be probed"
        assert res["total_tested"] == len(checked)
        assert res["found"] == []


class TestEmailEnumeratorScope:
    def test_derived_page_urls_filtered(self, monkeypatch):
        en = EmailEnumerator()

        class FakeResp:
            text = ""

        fetched = []

        def fake_get(url, timeout=None):
            fetched.append(url)
            return FakeResp()

        monkeypatch.setattr(en.session, "get", fake_get)

        scope = Scope(includes=["example.com"], excludes=["www.example.com"])
        emails = en.extract_from_web("example.com", scope=scope)

        assert emails == set()
        assert fetched == [
            "https://example.com",
            "https://example.com/about",
            "https://example.com/contact",
            "https://example.com/team",
            "https://example.com/careers",
            "https://example.com/privacy",
            "https://example.com/terms",
        ]
        assert any(d["module"] == "email_web" for d in scope.discarded)

    def test_no_scope_requests_every_page(self, monkeypatch):
        en = EmailEnumerator()

        class FakeResp:
            text = ""

        fetched = []

        def fake_get(url, timeout=None):
            fetched.append(url)
            return FakeResp()

        monkeypatch.setattr(en.session, "get", fake_get)
        en.extract_from_web("example.com")
        assert len(fetched) == 8


class TestEndpointDiscoveryScope:
    def test_out_of_scope_urls_never_requested(self, monkeypatch):
        ed = EndpointDiscovery()

        class FakeResp:
            status_code = 404
            content = b""
            headers = {}
            text = ""

        requested = []

        def fake_get(url, timeout=None, allow_redirects=False):
            requested.append(url)
            return FakeResp()

        monkeypatch.setattr(ed.session, "get", fake_get)

        scope = Scope(includes=["other.com"])
        res = ed.discover("https://example.com", paths=["/api", "/admin"], scope=scope)

        assert requested == []
        assert res["total_tested"] == 0
        assert res["found"] == []
        assert all(d["module"] == "web_endpoints" for d in scope.discarded)

    def test_absolute_path_override_outside_scope_not_requested(self, monkeypatch):
        ed = EndpointDiscovery()

        class FakeResp:
            status_code = 200
            content = b"ok"
            headers = {}
            text = "ok"

        requested = []

        def fake_get(url, timeout=None, allow_redirects=False):
            requested.append(url)
            return FakeResp()

        monkeypatch.setattr(ed.session, "get", fake_get)

        scope = Scope(includes=["example.com"])
        res = ed.discover(
            "https://example.com",
            paths=["/api", "https://evil.example.org/secret"],
            scope=scope,
        )

        assert requested == ["https://example.com/api"]
        assert res["total_tested"] == 1
        assert res["found"][0]["url"] == "https://example.com/api"

    def test_in_scope_urls_requested(self, monkeypatch):
        ed = EndpointDiscovery()

        class FakeResp:
            status_code = 404
            content = b""
            headers = {}
            text = ""

        requested = []

        def fake_get(url, timeout=None, allow_redirects=False):
            requested.append(url)
            return FakeResp()

        monkeypatch.setattr(ed.session, "get", fake_get)

        res = ed.discover("https://example.com", paths=["/a", "/b"], scope=None)
        assert len(requested) == 2
        assert res["total_tested"] == 2


class TestWebScannerScope:
    def test_out_of_scope_target_skips_everything(self, monkeypatch):
        ws = WebScanner()

        def must_not_run(*args, **kwargs):
            raise AssertionError("out-of-scope web scan must not request anything")

        monkeypatch.setattr(ws.tech_detector, "detect", must_not_run)
        monkeypatch.setattr(ws.endpoint_discovery, "discover_apis", must_not_run)
        monkeypatch.setattr(ws.sensitive_detector, "scan_url", must_not_run)

        scope = Scope(includes=["other.com"])
        res = ws.scan("example.com", scope=scope)

        assert res["target"] == "https://example.com"
        assert res["technologies"] == {}
        assert res["endpoints"] == {}
        assert res["sensitive_data"] == {}
        assert scope.discarded[0]["module"] == "web"

    def test_in_scope_target_passes_scope_down(self, monkeypatch):
        ws = WebScanner()
        got = {}

        monkeypatch.setattr(ws.tech_detector, "detect", lambda t: {"url": t})
        monkeypatch.setattr(ws.sensitive_detector, "scan_url", lambda t: {})

        def fake_apis(base_url, scope=None):
            got["scope"] = scope
            return {}

        monkeypatch.setattr(ws.endpoint_discovery, "discover_apis", fake_apis)

        import modules.web.headers_audit as headers_audit

        class FakeAuditor:
            def audit(self, url):
                return {"url": url}

        monkeypatch.setattr(headers_audit, "SecurityHeadersAuditor", FakeAuditor)

        scope = Scope(includes=["example.com"])
        res = ws.scan("example.com", scope=scope)

        assert got["scope"] is scope
        assert res["technologies"] == {"url": "https://example.com"}
        assert res["headers_audit"] == {"url": "https://example.com"}
