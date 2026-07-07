"""Unit tests for OSINT EYE core modules"""

import pytest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestDNSResolver:
    def test_resolve_google(self):
        from modules.dns import DNSResolver

        resolver = DNSResolver()
        results = resolver.resolve("google.com", "A")
        assert len(results) > 0
        for ip in results:
            parts = ip.split(".")
            assert len(parts) == 4

    def test_resolve_mx(self):
        from modules.dns import DNSResolver

        resolver = DNSResolver()
        results = resolver.resolve("google.com", "MX")
        assert len(results) > 0

    def test_resolve_nx(self):
        from modules.dns import DNSResolver

        resolver = DNSResolver()
        results = resolver.resolve("thisdomaindoesnotexist12345.com", "A")
        assert results == []

    def test_check_dmarc(self):
        from modules.dns import DNSResolver

        resolver = DNSResolver()
        result = resolver.check_dmarc("google.com")
        assert isinstance(result, dict)
        assert "exists" in result

    def test_check_spf(self):
        from modules.dns import DNSResolver

        resolver = DNSResolver()
        result = resolver.check_spf("google.com")
        assert isinstance(result, dict)
        assert "exists" in result


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


class TestCertScanner:
    def test_parse_certificates(self):
        from modules.certs import CertTransparency

        ct = CertTransparency()
        test_data = [
            {
                "common_name": "www.example.com",
                "subject_alt_name": "DNS:www.example.com, DNS:example.com",
                "issuer_org": "Let's Encrypt",
                "not_before": "2024-01-01",
                "not_after": "2024-04-01",
                "sha256": "abc123",
            }
        ]
        results = ct._parse_certificates(test_data, "domain")
        assert len(results) > 0
        assert any(r["domain"] == "www.example.com" for r in results)
        assert any(r["domain"] == "example.com" for r in results)


class TestAssetCorrelator:
    def test_ingest_dns(self):
        from core.correlator import AssetCorrelator

        correlator = AssetCorrelator()

        dns_data = {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "records": {
                "A": ["93.184.216.34"],
                "MX": ["mail.example.com"],
                "NS": ["ns1.example.com"],
            },
        }
        correlator.ingest_dns(dns_data)

        assert "www.example.com" in correlator.assets["subdomains"]
        assert "93.184.216.34" in correlator.assets["ips"]
        assert len(correlator.relationships) > 0

    def test_calculate_score(self):
        from core.correlator import AssetCorrelator

        correlator = AssetCorrelator()

        dns_data = {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com", "mail.example.com"],
            "records": {"A": ["93.184.216.34"]},
        }
        correlator.ingest_dns(dns_data)

        score = correlator.calculate_attack_surface_score()
        assert "score" in score
        assert "severity" in score
        assert 0 <= score["score"] <= 100

    def test_export_report(self):
        from core.correlator import AssetCorrelator

        correlator = AssetCorrelator()

        dns_data = {
            "domain": "example.com",
            "subdomains": ["www.example.com"],
            "records": {"A": ["93.184.216.34"]},
        }
        correlator.ingest_dns(dns_data)

        report = correlator.export_report()
        assert "assets" in report
        assert "relationships" in report
        assert "attack_surface_score" in report
        assert "attack_graph" in report


class TestScanCache:
    def test_save_and_retrieve(self):
        from core.session_cache import ScanCache

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            cache = ScanCache(db_path=f.name)

            cache.add_subdomain(
                "example.com", "www.example.com", "dns", "93.184.216.34"
            )
            subs = cache.get_subdomains("example.com")
            assert len(subs) == 1
            assert subs[0]["subdomain"] == "www.example.com"

            stats = cache.get_stats("example.com")
            assert stats["total_subdomains"] == 1

            os.unlink(f.name)

    def test_diff(self):
        from core.session_cache import ScanCache
        from datetime import datetime, timedelta

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            cache = ScanCache(db_path=f.name)

            cache.add_subdomain("example.com", "www.example.com", "dns")
            cache.add_subdomain("example.com", "api.example.com", "permutation")

            since = (datetime.now() - timedelta(hours=1)).isoformat()
            diff = cache.get_diff("example.com", since)
            assert "new_subdomains" in diff

            os.unlink(f.name)


class TestGraphBuilder:
    def test_ingest_and_export(self):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()

        test_data = {
            "modules": {
                "dns": {
                    "domain": "example.com",
                    "subdomains": ["www.example.com"],
                    "records": {"A": ["93.184.216.34"]},
                },
                "network": {
                    "host": "93.184.216.34",
                    "services": [{"port": 80, "state": "open", "service": "http"}],
                },
            }
        }

        builder.ingest_all(test_data)
        assert builder.graph.number_of_nodes() > 0
        assert builder.graph.number_of_edges() > 0

        export = builder.export_json()
        assert "nodes" in export
        assert "edges" in export
        assert "stats" in export


class TestMarkdownReporter:
    def test_generate_report(self):
        from reporting.markdown_reporter import MarkdownReporter

        results = {
            "target": "example.com",
            "scan_date": "2024-01-01T00:00:00",
            "depth": "normal",
            "modules": {
                "dns": {
                    "domain": "example.com",
                    "subdomains": ["www.example.com"],
                    "records": {"A": ["93.184.216.34"]},
                    "spf": {"exists": True},
                    "dmarc": {"exists": True},
                },
                "network": {
                    "host": "93.184.216.34",
                    "status": "up",
                    "services": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "service": "http",
                            "state": "open",
                        }
                    ],
                },
            },
        }

        reporter = MarkdownReporter()
        reporter.load_results(results)

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output = reporter.generate(f.name)
            assert os.path.exists(f.name)

            with open(f.name) as rf:
                content = rf.read()
                assert "example.com" in content
                assert "DNS Findings" in content
                assert "Network Findings" in content

            os.unlink(f.name)


class TestPluginManager:
    def test_load_builtin(self):
        from core.plugins import PluginManager

        pm = PluginManager()
        pm.load_builtin()

        plugins = pm.list_plugins()
        assert len(plugins) > 0

        assert pm.has_plugin("dns")
        assert pm.has_plugin("network")
        assert pm.has_plugin("cve")


class TestAsyncConfig:
    def test_default_config(self):
        from core.async_engine import AsyncConfig

        config = AsyncConfig()
        assert config.max_concurrent == 50
        assert config.timeout == 10
        assert config.stealth is False

    def test_stealth_config(self):
        from core.async_engine import AsyncConfig

        config = AsyncConfig(stealth=True)
        delay = config.get_delay()
        assert 2 <= delay <= 8

    def test_paranoid_config(self):
        from core.async_engine import AsyncConfig

        config = AsyncConfig(paranoid=True)
        delay = config.get_delay()
        assert 30 <= delay <= 120


class TestSecurityHeadersAuditor:
    def test_audit_example_com(self):
        from modules.dns import SecurityHeadersAuditor

        auditor = SecurityHeadersAuditor()
        result = auditor.audit("https://example.com")

        assert "url" in result
        assert "score" in result
        assert "grade" in result
        assert "missing_headers" in result


class TestTLSAnalyzer:
    def test_analyze_google(self):
        from modules.dns import TLSAnalyzer

        analyzer = TLSAnalyzer()
        result = analyzer.analyze("google.com")

        assert "host" in result
        assert "protocols" in result
        assert "certificate" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
