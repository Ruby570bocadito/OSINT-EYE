"""Offline tests for modules/dns: DNSResolver, permutator, security headers, TLS.

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
from unittest.mock import MagicMock, patch

from tests.conftest import _fake_dns_resolver


class TestDNSResolver:
    def test_resolve_a(self):
        resolver = _fake_dns_resolver({("example.com", "A"): ["93.184.216.34", "93.184.216.35"]})
        results = resolver.resolve("example.com", "A")
        assert len(results) == 2
        for ip in results:
            parts = ip.split(".")
            assert len(parts) == 4

    def test_resolve_mx(self):
        resolver = _fake_dns_resolver({("example.com", "MX"): ["mail.example.com"]})
        results = resolver.resolve("example.com", "MX")
        assert results == ["mail.example.com"]

    def test_resolve_nx(self):
        resolver = _fake_dns_resolver({})
        assert resolver.resolve("thisdomaindoesnotexist12345.com", "A") == []

    def test_check_dmarc(self):
        resolver = _fake_dns_resolver(
            {("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"']}
        )
        result = resolver.check_dmarc("example.com")
        assert isinstance(result, dict)
        assert result["exists"] is True
        assert result["policy"] == "reject"

    def test_check_dmarc_missing(self):
        resolver = _fake_dns_resolver({})
        result = resolver.check_dmarc("example.com")
        assert isinstance(result, dict)
        assert result["exists"] is False

    def test_check_spf(self):
        resolver = _fake_dns_resolver({("example.com", "TXT"): ['"v=SPF1 ip4:1.2.3.4 -all"']})
        result = resolver.check_spf("example.com")
        assert isinstance(result, dict)
        assert result["exists"] is True
        assert result["policy"] == "hardfail"


class TestSubdomainPermutator:
    def test_generate_permutations(self):
        from modules.dns import SubdomainPermutator

        perm = SubdomainPermutator(threads=10)
        perms = perm.generate_permutations("example.com")
        assert len(perms) > 0
        assert "www.example.com" in perms
        assert "api.example.com" in perms

    def test_generate_from_discovered(self):
        from modules.dns import SubdomainPermutator

        perm = SubdomainPermutator(threads=10)
        discovered = ["api.example.com", "mail.example.com"]
        perms = perm.generate_from_discovered("example.com", discovered)
        assert len(perms) > 0


class TestSecurityHeadersAuditor:
    """SecurityHeadersAuditor with a mocked HTTP response (offline)."""

    def test_audit_headers(self):
        from modules.dns import SecurityHeadersAuditor

        response = MagicMock()
        response.headers = {
            "Server": "nginx",
            "X-Powered-By": "PHP/7.4",
            "Strict-Transport-Security": "max-age=3600",
        }
        auditor = SecurityHeadersAuditor()
        with patch("requests.Session.request", return_value=response) as mock_get:
            result = auditor.audit("https://example.com")

        mock_get.assert_called_once()
        assert "url" in result
        assert "score" in result
        assert "grade" in result
        assert "missing_headers" in result
        # Required headers absent from the mocked response → flagged missing
        flagged = {h["header"] for h in result["missing_headers"]}
        assert "Content-Security-Policy" in flagged
        assert "X-Frame-Options" in flagged
        # Dangerous headers present → information disclosure reported
        assert any(d["header"] == "Server" for d in result["information_disclosure"])

    def test_audit_network_failure_is_graceful(self):
        from modules.dns import SecurityHeadersAuditor

        auditor = SecurityHeadersAuditor()
        with patch("requests.Session.request", side_effect=ConnectionError("boom")):
            result = auditor.audit("https://unreachable.invalid")
        assert "error" in result


class TestTLSAnalyzer:
    """TLSAnalyzer with mocked ssl/socket (offline)."""

    def _analyze_with_mocks(self):
        import socket
        import ssl

        from modules.dns import TLSAnalyzer

        ssock = MagicMock()
        ssock.version.return_value = "TLSv1.3"
        ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "version": 3,
            "serialNumber": "04AA",
            "notBefore": "Jun  1 00:00:00 2024 GMT",
            "notAfter": "Aug 30 00:00:00 2024 GMT",
        }

        ctx = MagicMock()
        ctx.wrap_socket.return_value.__enter__.return_value = ssock
        proto_ctx = MagicMock()
        proto_ctx.wrap_socket.return_value.__enter__.return_value = MagicMock()

        with patch.object(socket, "create_connection", MagicMock()), patch.object(
            ssl, "create_default_context", return_value=ctx
        ), patch.object(ssl, "SSLContext", return_value=proto_ctx):
            analyzer = TLSAnalyzer(timeout=1)
            return analyzer.analyze("example.com")

    def test_analyze_structure(self):
        result = self._analyze_with_mocks()
        assert result["host"] == "example.com"
        assert "protocols" in result
        assert "certificate" in result
        assert result["protocols"].get("TLSv1.3") is True
        assert result["certificate"]["subject"]["commonName"] == "example.com"

    def test_unreachable_host_degrades(self):
        import socket

        from modules.dns import TLSAnalyzer

        analyzer = TLSAnalyzer(timeout=1)
        with patch.object(
            socket, "create_connection", side_effect=OSError("unreachable")
        ):
            result = analyzer.analyze("unreachable.invalid")
        assert "error" in result


class TestDNSRecordParsersCaseInsensitive:
    """Real-world SPF/DMARC records are lowercase — matching is case-sensitive
    per RFC (7208/7489) and must not depend on the record's casing."""

    def test_check_spf_realworld_lowercase(self):
        resolver = _fake_dns_resolver(
            {("example.com", "TXT"): ['"v=spf1 include:_spf.google.com ~all"']}
        )
        result = resolver.check_spf("example.com")
        assert result["exists"] is True
        assert result["policy"] == "softfail"
        assert result["record"].startswith("v=spf1")  # verbatim record kept

    def test_check_spf_uppercase_still_works(self):
        resolver = _fake_dns_resolver({("example.com", "TXT"): ['"V=SPF1 -all"']})
        result = resolver.check_spf("example.com")
        assert result["exists"] is True
        assert result["policy"] == "hardfail"

    def test_check_dmarc_lowercase(self):
        resolver = _fake_dns_resolver(
            {("_dmarc.example.com", "TXT"): ['"v=dmarc1; p=quarantine"']}
        )
        result = resolver.check_dmarc("example.com")
        assert result["exists"] is True
        assert result["policy"] == "quarantine"


class TestPermutatorCallIsolation:
    """enumerate() must return only the CURRENT call's results.

    core/monitor.py shares one SubdomainPermutator across targets and
    cycles: the old cumulative return value made every target report the
    other targets' subdomains (false alerts + cache pollution).
    """

    def _permutator(self):
        from modules.dns.subdomain_permutator import SubdomainPermutator

        return SubdomainPermutator(threads=5)

    def test_second_call_does_not_contain_first_target(self):
        perm = self._permutator()
        with patch.object(perm, "_check_subdomain", side_effect=lambda sub, dom: sub):
            first = perm.enumerate("a.com")
            second = perm.enumerate("b.com")

        assert first, "expected at least one resolved candidate"
        assert not any(x.endswith("a.com") for x in second)
        assert all(x.endswith("b.com") for x in second)

    def test_get_stats_stays_cumulative(self):
        perm = self._permutator()
        with patch.object(perm, "_check_subdomain", side_effect=lambda sub, dom: sub):
            perm.enumerate("a.com")
            perm.enumerate("b.com")
        stats = perm.get_stats()
        assert stats["total_found"] > len(
            [s for s in stats["subdomains"] if s.endswith("b.com")]
        )

    def test_osint_eye_run_permutation_shape_unchanged(self):
        from osint_eye import OSINTEye

        engine = OSINTEye(target="example.com", ai=False, cache=False)
        with patch.object(
            engine.permutator, "enumerate", return_value=["api.example.com"]
        ):
            engine.run_permutation()
        assert engine.results["modules"]["permutation"]["subdomains"] == [
            "api.example.com"
        ]
        assert engine.results["modules"]["permutation"]["total_found"] == 1
