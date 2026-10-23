"""Unit tests for OSINT EYE core/ui/reporting modules.

Fully offline: every network-dependent test (DNS, TLS, HTTP headers) uses
mocks/fixed responses so `pytest -q tests/` runs fast and without network.
"""

import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ─────────────────────────────────────────────────────────────────────────────
# Shared offline fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────
def _fake_dns_resolver(records: dict):
    """Build a DNSResolver whose internal dnspython resolver is mocked.

    ``records`` maps (domain, record_type) → list of answer strings;
    any other query raises NXDOMAIN (i.e. resolved to []).
    """
    import dns.resolver

    from modules.dns import DNSResolver

    resolver = DNSResolver()
    fake = MagicMock()

    def fake_resolve(domain, record_type, *args, **kwargs):
        key = (str(domain), str(record_type))
        if key in records:
            return list(records[key])
        raise dns.resolver.NXDOMAIN()

    fake.resolve.side_effect = fake_resolve
    resolver.resolver = fake
    return resolver


FULL_RESULTS = {
    "target": "example.com",
    "scan_date": "2024-06-01T12:00:00",
    "depth": "normal",
    "modules": {
        "dns": {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
            "spf": {"exists": True, "record": "v=SPF1 -all"},
            "dmarc": {"exists": True, "policy": "reject"},
        },
        "certs": {"subdomains": ["ct.example.com"]},
        "wayback": {"total_snapshots": 1234, "by_year": {"2023": 900, "2022": 334}},
        "network": {
            "host": "93.184.216.34",
            "status": "up",
            "services": [
                {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "version": "nginx 1.24"},
                {"port": 22, "protocol": "tcp", "service": "ssh", "state": "closed"},
            ],
        },
        "web": {"technologies": {"technologies": ["nginx", "Cloudflare"], "url": "https://example.com"}},
        "endpoints": {"found": [{"path": "/login", "status": 200, "size": 1024}], "sensitive": [{"path": "/.env", "status": 200}], "total_found": 1},
        "emails": {"emails_found": ["admin@example.com"]},
        "cloud_buckets": {"found": [{"url": "s3://example-assets", "provider": "aws", "public": True}], "public": [{"url": "s3://example-assets"}]},
        "github": {"total_findings": 2, "findings": [{"type": "aws_key", "match": "AKIAIOSFODNN7", "url": "https://github.com/x/y"}]},
        "cdn_waf": {"cdn": "Cloudflare", "waf": "Cloudflare"},
        "cve": {"cves": [{"id": "CVE-2024-1234", "description": "Critical RCE in nginx", "severity": [{"score": 9.8, "severity": "CRITICAL"}]}]},
        "takeover": {"vulnerable": [{"subdomain": "old.example.com", "service": "aws", "signature": "NoSuchBucket"}]},
    },
    "correlation": {
        "attack_surface_score": {"score": 78, "severity": "HIGH", "factors": ["Open admin panel", "Public buckets"]}
    },
    "mitre": {
        "total_findings": 3,
        "critical_count": 2,
        "findings": [
            {"technique_id": "T1552.001", "technique_name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access", "severity": "CRITICAL"},
            {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "HIGH"},
        ],
    },
    "attack_chains": [
        {
            "name": "Public bucket to data exfiltration",
            "risk_score": 85,
            "difficulty": "Low",
            "steps": [{"step": 1, "action": "Enumerate buckets"}, {"step": 2, "action": "Download objects"}],
        }
    ],
    "ai_analysis": {"risk_score": {"score": 66, "severity": "HIGH"}, "summary": "Focus on exposed .env and buckets."},
    "errors": ["[whois] rate limited"],
}


# ─────────────────────────────────────────────────────────────────────────────
# DNS (mocked — offline)
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
# Core engines (offline)
# ─────────────────────────────────────────────────────────────────────────────
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


class TestScanDiff:
    def test_detects_changes(self):
        from core.scan_diff import ScanDiff

        old = {
            "modules": {
                "dns": {"subdomains": ["www.example.com"]},
                "network": {"services": [{"host": "1.2.3.4", "port": 80, "state": "open", "service": "http", "version": "nginx 1.20"}]},
                "web": {"technologies": {"technologies": ["nginx"]}},
                "emails": {"emails_found": ["old@example.com"]},
                "cve": {"cves": [{"id": "CVE-2023-0001"}]},
                "cloud_buckets": {"found": [{"url": "s3://old"}]},
            },
            "correlation": {"attack_surface_score": {"score": 30}},
        }
        new = {
            "modules": {
                "dns": {"subdomains": ["www.example.com", "api.example.com"]},
                "network": {"services": [{"host": "1.2.3.4", "port": 80, "state": "open", "service": "http", "version": "nginx 1.24"}]},
                "web": {"technologies": {"technologies": ["nginx", "Cloudflare"]}},
                "emails": {"emails_found": ["old@example.com", "new@example.com"]},
                "cve": {"cves": [{"id": "CVE-2023-0001"}, {"id": "CVE-2024-1234"}]},
                "cloud_buckets": {"found": [{"url": "s3://old"}, {"url": "s3://new"}]},
            },
            "correlation": {"attack_surface_score": {"score": 55}},
        }

        diff = ScanDiff().compare(old, new)
        assert diff["new_subdomains"] == ["api.example.com"]
        assert diff["new_technologies"] == ["Cloudflare"]
        assert diff["new_emails"] == ["new@example.com"]
        assert [c["id"] for c in diff["new_cves"]] == ["CVE-2024-1234"]
        assert [b["url"] for b in diff["new_cloud_buckets"]] == ["s3://new"]
        assert diff["changed_services"][0]["new_version"] == "nginx 1.24"
        assert diff["score_change"] == {"before": 30, "after": 55, "delta": 25}

    def test_summary_renders(self):
        from core.scan_diff import ScanDiff

        diff = ScanDiff()
        diff.compare({"modules": {}}, {"modules": {"dns": {"subdomains": ["a.example.com"]}}})
        summary = diff.get_summary()
        assert "new subdomains" in summary


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


# ─────────────────────────────────────────────────────────────────────────────
# Rich CLI (output captured with a recording console)
# ─────────────────────────────────────────────────────────────────────────────
def _record_console():
    from rich.console import Console

    return Console(record=True, width=140, force_terminal=False, highlight=False)


class TestRichCLI:
    def test_print_banner(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_banner()
        out = cli.console.export_text()
        assert "AI-POWERED ATTACK SURFACE INTELLIGENCE" in out
        assert "v2.1" in out

    def test_print_scan_header(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_scan_header("example.com", "deep", stealth=True)
        out = cli.console.export_text()
        assert "example.com" in out
        assert "DEEP" in out
        assert "STEALTH" in out

    def test_print_summary_empty_results(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_summary({})  # must not raise
        cli.print_summary({"target": "example.com", "modules": {}})
        out = cli.console.export_text()
        assert "SCAN SUMMARY" in out
        assert "example.com" in out
        assert "0/100" in out

    def test_print_summary_full_results(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_summary(FULL_RESULTS)
        out = cli.console.export_text()
        assert "example.com" in out
        assert "78/100" in out
        assert "HIGH" in out
        assert "MODULE COVERAGE" in out
        assert "TOP FINDINGS" in out
        assert "CVE-2024-1234" in out

    def test_print_summary_never_keyerror(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        # Malformed shapes must not crash the renderer
        cli.print_summary({"target": "x", "modules": None, "correlation": None, "mitre": None, "attack_chains": None, "ai_analysis": None, "errors": None})
        cli.print_summary({"target": "y", "modules": {"dns": None, "network": {"services": None}}})
        out = cli.console.export_text()
        assert "SCAN SUMMARY" in out

    def test_print_full_results(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_full_results(FULL_RESULTS)
        out = cli.console.export_text()
        assert "FULL RESULTS BY MODULE" in out
        for section in (
            "DNS RECONNAISSANCE",
            "CERT TRANSPARENCY",
            "WAYBACK MACHINE",
            "Open Ports",
            "CVE CORRELATION",
            "MITRE ATT&CK",
            "ATTACK CHAINS",
            "CLOUD STORAGE",
            "EMAIL ADDRESSES",
            "GITHUB LEAKS",
            "SUBDOMAIN TAKEOVER",
            "CDN / WAF DETECTION",
        ):
            assert section in out, f"missing section: {section}"

    def test_print_full_results_markup_safe(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        hostile = {
            "target": "[bold red]not-markup[/]",
            "modules": {
                "dns": {"subdomains": ["<script>alert(1)</script>.evil.com"], "records": {"TXT": ["[it] is not markup"]}}
            },
        }
        cli.print_full_results(hostile)  # must not raise
        out = cli.console.export_text()
        assert "<script>alert(1)</script>.evil.com" in out

    def test_log_helpers(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.log_info("starting")
        cli.log_success("done")
        cli.log_warning("slow")
        cli.log_error("boom")
        cli.print_phase(1, "Recon")
        cli.print_phase_done(1, 1.5)
        out = cli.console.export_text()
        for token in ("starting", "done", "slow", "boom", "PHASE 1"):
            assert token in out


# ─────────────────────────────────────────────────────────────────────────────
# Wizard (prompt answers mocked — offline)
# ─────────────────────────────────────────────────────────────────────────────
class TestInteractiveWizard:
    def test_start_returns_valid_args(self):
        from ui import wizard as wiz

        prompt_answers = iter(
            [
                "example.com, www.example.com",  # targets (deduped)
                "",  # scope limit (none)
                "",  # exclusions (none)
                "deep",  # depth
                "osint_eye_custom",  # output base
            ]
        )
        confirm_answers = iter(
            [True, False, False, True, True, False, False, False, False]
        )  # authorized, ai, cache, stealth, rich, agent, pdf, dashboard, cypher

        with patch.object(wiz.Prompt, "ask", staticmethod(lambda *a, **k: next(prompt_answers))), \
             patch.object(wiz.Confirm, "ask", staticmethod(lambda *a, **k: next(confirm_answers))):
            args = wiz.InteractiveWizard().start()

        assert isinstance(args, list)
        assert all(isinstance(a, str) for a in args)
        assert args[0] == "example.com"
        assert "www.example.com" in args  # second target kept
        assert args[args.index("--depth") + 1] == "deep"
        assert "--no-ai" in args
        assert "--no-cache" in args
        assert "--stealth" in args
        assert "--rich" in args
        assert "--output" in args
        assert args[args.index("--output") + 1] == "osint_eye_custom"

    def test_flags_exist_in_parser_contract(self):
        """Every flag the wizard emits must exist in osint_eye's argparse."""
        valid = {
            "--depth", "--stealth", "--no-ai", "--no-cache", "--rich",
            "--output", "--agent", "--pdf", "--dashboard", "--export-cypher",
        }
        from ui import wizard as wiz

        assert wiz._VALID_FLAGS & valid == valid

    def test_target_parsing(self):
        from ui.wizard import InteractiveWizard

        assert InteractiveWizard._parse_targets("a.com, b.com  c.com") == ["a.com", "b.com", "c.com"]
        assert InteractiveWizard._parse_targets("dup.com dup.com") == ["dup.com"]
        assert InteractiveWizard._parse_targets("") == []


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────
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
                        {"port": 80, "protocol": "tcp", "service": "http", "state": "open"}
                    ],
                },
            },
        }

        reporter = MarkdownReporter()
        reporter.load_results(results)

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            reporter.generate(f.name)
            assert os.path.exists(f.name)

            with open(f.name) as rf:
                content = rf.read()
                assert "example.com" in content
                assert "DNS Findings" in content
                assert "Network Findings" in content

            os.unlink(f.name)

    def test_minimal_results_keep_canonical_sections(self):
        from reporting.markdown_reporter import MarkdownReporter

        reporter = MarkdownReporter()
        reporter.load_results({"target": "minimal.com", "modules": {}})
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            reporter.generate(f.name)
            content = open(f.name).read()
            assert "minimal.com" in content
            assert "## DNS Findings" in content
            assert "## Network Findings" in content
            assert "## Executive Summary" in content
            assert "## Recommendations" in content
            os.unlink(f.name)

    def test_tolerates_none_and_malformed(self):
        from reporting.markdown_reporter import MarkdownReporter

        reporter = MarkdownReporter()
        reporter.load_results(None)
        reporter.load_results({"target": "x", "modules": None, "correlation": {"hidden_relationships": [{"type": "shared-ip"}]}})
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            reporter.generate(f.name)
            content = open(f.name).read()
            assert "## DNS Findings" in content
            assert "## Network Findings" in content
            os.unlink(f.name)

    def test_cve_weird_severity_shapes(self):
        from reporting.markdown_reporter import MarkdownReporter

        reporter = MarkdownReporter()
        reporter.load_results(
            {
                "target": "x",
                "modules": {
                    "cve": {
                        "cves": [
                            {"id": "CVE-1", "severity": []},
                            {"id": "CVE-2", "severity": {"score": 7.5, "severity": "HIGH"}},
                            {"id": "CVE-3", "severity": [{"score": 9.8, "severity": "CRITICAL"}]},
                        ]
                    }
                },
            }
        )
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            reporter.generate(f.name)
            content = open(f.name).read()
            for cve in ("CVE-1", "CVE-2", "CVE-3"):
                assert cve in content
            os.unlink(f.name)


class TestMitreMapper:
    def test_map_findings_real_techniques(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        findings = mapper.map_findings(FULL_RESULTS)
        ids = {f.technique_id for f in findings}
        # Real ATT&CK Enterprise techniques
        assert "T1595.002" in ids  # Active Scanning: Vulnerability Scanning
        assert "T1046" in ids      # Network Service Discovery
        assert "T1552.001" in ids  # Unsecured Credentials: Credentials In Files
        assert "T1530" in ids      # Data from Cloud Storage
        assert "T1190" in ids      # Exploit Public-Facing Application
        assert "T1583.001" in ids  # Acquire Infrastructure: Domains

    def test_map_minimal_results(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        findings = mapper.map_findings({"target": "x", "modules": {}})
        assert findings == []

    def test_export_navigator_layer_valid(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        mapper.map_findings(FULL_RESULTS)
        layer = mapper.export_navigator_layer()

        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["navigator"] == "4.9"
        assert layer["versions"]["layer"] == "4.5"
        assert isinstance(layer["techniques"], list) and layer["techniques"]
        for tech in layer["techniques"]:
            assert tech["techniqueID"].startswith("T")
            assert isinstance(tech["score"], int)
            assert tech["enabled"] is True
        # Sub-techniques keep their full ID
        assert any(t["techniqueID"].count(".") == 1 for t in layer["techniques"])

    def test_export_json_structure(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        mapper.map_findings(FULL_RESULTS)
        data = mapper.export_json()
        assert data["total_findings"] == len(mapper.findings)
        assert data["critical_count"] >= 1
        assert "tactic_summary" in data
        assert "heatmap" in data
        json.dumps(data)  # must be JSON-serialisable


class TestCSVAndHTMLExport:
    def test_export_all(self):
        from reporting.export import CSVExporter

        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "osint_eye_example")
            files = CSVExporter().export_all(FULL_RESULTS, base)
            assert len(files) == 4
            for path in files:
                assert os.path.exists(path)

            with open(files[0]) as f:  # subdomains
                assert "www.example.com" in f.read()

    def test_export_all_minimal_results(self):
        from reporting.export import CSVExporter

        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "min")
            files = CSVExporter().export_all({}, base)
            assert len(files) == 4  # headers-only CSVs, no crash

    def test_html_report(self):
        from reporting.export import HTMLReporter

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            HTMLReporter().generate(FULL_RESULTS, path)
            html = open(path).read()
            assert "example.com" in html
            assert "443" in html and "nginx 1.24" in html
            # Hostile values are escaped, not injected
            hostile = {"target": "<script>x</script>", "modules": {}}
            path2 = os.path.join(tmp, "hostile.html")
            HTMLReporter().generate(hostile, path2)
            html2 = open(path2).read()
            assert "<script>x</script>" not in html2
            assert "&lt;script&gt;" in html2


class TestExportTools:
    def test_burp_xml_is_valid(self):
        from reporting.export_tools import BurpExporter

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "burp.xml")
            BurpExporter().export(FULL_RESULTS, path)
            root = ET.parse(path).getroot()
            assert root.tag == "issues"
            issues = root.findall("issue")
            assert issues, "expected at least one issue"
            for issue in issues:
                assert issue.find("severity").text
                assert issue.find("detail").text is not None

    def test_burp_xml_survives_control_chars(self):
        from reporting.export_tools import BurpExporter

        hostile = {
            "target": "x",
            "modules": {
                "cve": {
                    "cves": [
                        {"id": "CVE-1\x00bad", "description": "desc\x07ription", "severity": [{"score": 9.8, "severity": "CRITICAL"}]}
                    ]
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "burp_hostile.xml")
            BurpExporter().export(hostile, path)
            root = ET.parse(path).getroot()  # well-formed despite control chars
            assert root.tag == "issues"

    def test_msf_json_is_valid(self):
        from reporting.export_tools import MetasploitExporter

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "msf.json")
            MetasploitExporter().export(FULL_RESULTS, path)
            data = json.load(open(path))
            assert data["workspace"] == "example.com"
            assert data["hosts"][0]["host"] == "93.184.216.34"
            assert any(s["port"] == 443 for s in data["services"])
            assert any(v["name"] == "CVE-2024-1234" for v in data["vulns"])
            assert any(n["type"] == "osint.subdomains" for n in data["notes"])

    def test_config_profiles_roundtrip(self):
        from reporting.export_tools import ConfigProfiles

        with tempfile.TemporaryDirectory() as tmp:
            profiles = ConfigProfiles(profiles_dir=tmp)
            profiles.save("quick", {"depth": "quick"})
            assert "quick" in profiles.list_profiles()
            loaded = profiles.load("quick")
            assert loaded["depth"] == "quick"
            assert "created_at" in loaded
            profiles.delete("quick")
            assert "quick" not in profiles.list_profiles()

    def test_default_profiles(self):
        from reporting.export_tools import ConfigProfiles

        profiles = ConfigProfiles(profiles_dir=tempfile.mkdtemp())
        assert profiles.get_default_profile()["depth"] == "normal"
        assert profiles.get_deep_profile()["depth"] == "deep"
        assert profiles.get_stealth_profile()["stealth"] is True


class TestPDFReporter:
    def test_generate_empty_results(self):
        from reporting.pdf_reporter import PDFReporter

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "empty.pdf")
            PDFReporter().generate({}, path)
            assert os.path.exists(path)
            assert os.path.getsize(path) > 0

    def test_generate_full_results(self):
        from reporting.pdf_reporter import PDFReporter

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "full.pdf")
            PDFReporter().generate(FULL_RESULTS, path)
            content = open(path, "rb").read()
            assert content.startswith(b"%PDF")
            assert os.path.getsize(path) > 2000

    def test_generate_unicode_target(self):
        from reporting.pdf_reporter import PDFReporter

        results = dict(FULL_RESULTS)
        results["target"] = "españa-tëst.日本.iso"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "unicode.pdf")
            PDFReporter().generate(results, path)  # must not raise
            assert os.path.getsize(path) > 0

    def test_generate_malformed_shapes(self):
        from reporting.pdf_reporter import PDFReporter

        hostile = {
            "target": "x",
            "modules": {
                "dns": None,
                "network": {"services": None},
                "cve": {"cves": [{"id": "CVE-9", "severity": {"score": 9.1, "severity": "CRITICAL"}, "description": "<b>markup</b>"}]},
                "takeover": {"vulnerable": None},
            },
            "mitre": {"findings": None},
            "attack_chains": None,
            "correlation": None,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hostile.pdf")
            PDFReporter().generate(hostile, path)  # must not raise
            assert os.path.getsize(path) > 0


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard (Flask test client — offline)
# ─────────────────────────────────────────────────────────────────────────────
class TestDashboard:
    def setup_method(self):
        from ui import dashboard

        dashboard.SCAN_RESULTS.clear()
        dashboard.SCAN_HISTORY.clear()
        dashboard.LAST_LOAD_WARNING = None

    def test_load_missing_path_falls_back_to_demo(self, tmp_path, monkeypatch):
        from ui import dashboard

        monkeypatch.chdir(tmp_path)
        target = dashboard.load_scan_results("missing_scan_results")
        assert target == "demo"
        assert dashboard.SCAN_RESULTS["demo"]["demo"] is True
        assert dashboard.LAST_LOAD_WARNING

    def test_load_without_json_extension(self, tmp_path, monkeypatch):
        from ui import dashboard

        data = {"target": "example.com", "scan_date": "2024-01-01T00:00:00", "depth": "normal", "modules": {}}
        (tmp_path / "osint_eye_example.json").write_text(json.dumps(data))
        monkeypatch.chdir(tmp_path)

        target = dashboard.load_scan_results("osint_eye_example")  # sin .json
        assert target == "example.com"
        assert dashboard.SCAN_RESULTS["example.com"]["target"] == "example.com"

    def test_load_most_recent_match(self, tmp_path, monkeypatch):
        from ui import dashboard

        for name in ("osint_eye_a.json", "osint_eye_b.json"):
            (tmp_path / name).write_text(json.dumps({"target": name}))
        os.utime(tmp_path / "osint_eye_b.json", (2000000000, 2000000000))
        monkeypatch.chdir(tmp_path)

        target = dashboard.load_scan_results("totally_unknown_prefix")
        assert target == "osint_eye_b.json"  # newest osint_eye_*.json wins

    def test_load_invalid_json_falls_back_to_demo(self, tmp_path, monkeypatch):
        from ui import dashboard

        (tmp_path / "broken.json").write_text("{not valid json")
        monkeypatch.chdir(tmp_path)
        target = dashboard.load_scan_results("broken.json")
        assert target == "demo"
        assert dashboard.SCAN_RESULTS["demo"]["demo"] is True

    def test_api_never_500(self):
        from ui import dashboard

        client = dashboard.app.test_client()
        assert client.get("/api/scans").get_json()["total"] == 0
        assert client.get("/api/scan/ghost").status_code == 404
        assert client.get("/api/scan/ghost/subdomains").status_code == 404
        assert client.get("/api/scan/ghost/ports").status_code == 404
        assert client.get("/api/scan/ghost/graph").status_code == 404
        assert client.get("/api/scan/ghost/mitre").status_code == 404
        assert client.get("/api/scan/ghost/summary").status_code == 404

        dashboard.load_scan_results("definitely_missing_file")
        assert client.get("/api/scans").get_json()["total"] == 1

        for endpoint in (
            "/api/scan/demo",
            "/api/scan/demo/subdomains",
            "/api/scan/demo/ports",
            "/api/scan/demo/graph",
            "/api/scan/demo/mitre",
            "/api/scan/demo/chains",
            "/api/scan/demo/summary",
        ):
            resp = client.get(endpoint)
            assert resp.status_code == 200, endpoint

        summary = client.get("/api/scan/demo/summary").get_json()
        assert summary["subdomains"] == 0
        assert summary["open_ports"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# OE-QA2 — second QA round: residual bugs, edge cases, parser coverage
# (all offline; network mocked where touched)
# ─────────────────────────────────────────────────────────────────────────────
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


class TestCertIssuers:
    def test_unique_issuers_skips_empty(self):
        from modules.certs import CertTransparency

        ct = CertTransparency()
        certs = [
            {"domain": "www.example.com", "issuer": "", "created": "", "expiry": "", "fingerprint": ""},
            {"domain": "api.example.com", "issuer": "Let's Encrypt", "created": "", "expiry": "", "fingerprint": ""},
        ]
        with patch.object(ct, "search", return_value=certs):
            results = ct.scan("example.com")
        assert results["unique_issuers"] == ["Let's Encrypt"]  # "" filtered out
        assert results["subdomains"] == ["api.example.com", "www.example.com"]


class TestCDNDetectorPrecision:
    """A bare X-Cache header must not brand the server as CloudFront."""

    @staticmethod
    def _detector_with_response(headers, body=""):
        from modules.osint.cloud_email import CDNDetector

        detector = CDNDetector()
        response = MagicMock()
        response.status_code = 200
        response.headers = dict(headers)
        response.text = body
        detector.session = MagicMock()
        detector.session.get.return_value = response
        return detector

    def test_xcache_value_identifies_cloudfront(self):
        detector = self._detector_with_response({"x-cache": "Hit from cloudfront"})
        result = detector.detect("https://example.com")
        assert result["cdn"] == "CloudFront"

    def test_xcache_generic_header_is_not_cloudfront(self):
        detector = self._detector_with_response({"x-cache": "HIT"})
        result = detector.detect("https://example.com")
        assert result["cdn"] is None

    def test_fastly_header_still_detected(self):
        detector = self._detector_with_response({"x-served-by": "cache-fra19183-FRA"})
        result = detector.detect("https://example.com")
        assert result["cdn"] == "Fastly"


class TestNVDMetricFallback:
    """NVD 2.0 payloads carrying ONLY CVSS v2 / v4 metrics used to yield an
    empty severity list (CVE silently ignored by every consumer)."""

    @staticmethod
    def _payload(metrics):
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-1999-0001",
                        "descriptions": [{"lang": "en", "value": "Old service RCE"}],
                        "metrics": metrics,
                        "references": [],
                        "configurations": [],
                    }
                }
            ]
        }

    def test_cvss_v2_only_payload(self):
        from modules.cve.nvd import CVELookup

        lookup = CVELookup(rate_limit_delay=0)
        metrics = {
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "baseSeverity": "HIGH",
                    "cvssData": {
                        "version": "2.0",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "baseScore": 7.5,
                    },
                }
            ]
        }
        parsed = lookup._parse_cve_data(self._payload(metrics))
        assert parsed["severity"], "CVSS v2-only CVE must expose a severity"
        assert parsed["severity"][0]["score"] == 7.5
        assert parsed["severity"][0]["severity"] == "HIGH"

    def test_cvss_v2_severity_inside_cvssdata(self):
        from modules.cve.nvd import CVELookup

        lookup = CVELookup(rate_limit_delay=0)
        metrics = {
            "cvssMetricV2": [
                {
                    "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P"}
                }
            ]
        }
        parsed = lookup._parse_cve_data(self._payload(metrics))
        assert parsed["severity"][0]["score"] == 5.0
        assert parsed["severity"][0]["severity"] == "MEDIUM"

    def test_cvss_v40_fallback(self):
        from modules.cve.nvd import CVELookup

        lookup = CVELookup(rate_limit_delay=0)
        metrics = {
            "cvssMetricV40": [
                {
                    "type": "Secondary",
                    "cvssData": {
                        "version": "4.0",
                        "baseScore": 9.4,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    },
                }
            ]
        }
        parsed = lookup._parse_cve_data(self._payload(metrics))
        assert parsed["severity"][0]["score"] == 9.4
        assert parsed["severity"][0]["severity"] == "CRITICAL"

    def test_v31_still_preferred(self):
        from modules.cve.nvd import CVELookup

        lookup = CVELookup(rate_limit_delay=0)
        metrics = {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
            ],
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}
            ],
        }
        parsed = lookup._parse_cve_data(self._payload(metrics))
        assert len(parsed["severity"]) == 1
        assert parsed["severity"][0]["score"] == 9.8

    def test_metrics_without_cvssdata_does_not_crash(self):
        from modules.cve.nvd import CVELookup

        lookup = CVELookup(rate_limit_delay=0)
        metrics = {"cvssMetricV31": [{"type": "Primary"}]}  # missing cvssData
        parsed = lookup._parse_cve_data(self._payload(metrics))
        assert parsed["severity"] == []


class TestCorrelatorCoverage:
    """The correlator must ingest every module result osint_eye feeds it."""

    def test_ingest_web_dict_shape(self):
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_web({"target": "https://example.com", "technologies": {"technologies": ["nginx", "PHP"]}})
        assert c.assets["technologies"] == {"nginx", "PHP"}
        assert any(r["type"] == "technology_on" for r in c.relationships)

    def test_ingest_web_list_and_garbage_shapes(self):
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_web({"technologies": ["nginx"]})  # plain list
        c.ingest_web({"technologies": 42})  # garbage ignored, no raise
        assert c.assets["technologies"] == {"nginx"}

    def test_ingest_permutation_counts_as_subdomains(self):
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_permutation({"domain": "example.com", "subdomains": ["dev1.example.com"]})
        assert "dev1.example.com" in c.assets["subdomains"]
        assert any(r["type"] == "subdomain_of" for r in c.relationships)

    def test_ingest_github(self):
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_github({"domain": "example.com", "findings": [{"file": ".env.prod", "type": "code"}]})
        assert ".env.prod" in c.assets["github_leaks"]

    def test_ingest_google(self):
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_google(
            {
                "domain": "example.com",
                "login_pages": [{"title": "Login", "url": "https://example.com/login"}],
                "subdomains": ["legacy.example.com"],
            }
        )
        assert "https://example.com/login" in c.assets["dork_results"]
        assert "legacy.example.com" in c.assets["subdomains"]

    def test_ingest_cve(self):
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_cve({"cves": [{"id": "CVE-2024-1234"}, {"id": "CVE-2024-9999"}]})
        assert c.assets["vulnerabilities"] == {"CVE-2024-1234", "CVE-2024-9999"}

    def test_ingest_cdn_waf(self):
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_cdn_waf({"url": "https://example.com", "cdn": "Cloudflare", "waf": None})
        assert c.assets["cdn_providers"] == {"Cloudflare"}
        assert "waf_providers" not in c.assets  # None must not create the key

    def test_ingest_dns_string_record_values(self):
        """records values as a bare string must not explode into characters."""
        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        c.ingest_dns({"domain": "example.com", "records": {"A": "93.184.216.34"}})
        assert c.assets["ips"] == {"93.184.216.34"}
        # the old behaviour would add every single character of the string
        assert "9" not in c.assets["ips"]

    def test_relationships_deduplicated_under_concurrency(self):
        import concurrent.futures

        from core.correlator import AssetCorrelator

        c = AssetCorrelator()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for _ in pool.map(lambda _: c._add_relationship("resolves_to", "example.com", "1.2.3.4"), range(200)):
                pass
        assert len(c.relationships) == 1


class TestRichCLIHelperRegression:
    def test_l_returns_list_not_dict(self):
        from ui.rich_cli import _l

        assert _l(None) == []
        assert _l("abc") == []
        assert _l({"a": 1}) == []
        assert _l([1, 2]) == [1, 2]

    def test_print_full_results_survives_dict_steps(self):
        """A chain whose 'steps' is a dict used to raise TypeError ({}[:3])."""
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        weird = {
            "target": "example.com",
            "attack_chains": [
                {"name": "bad chain", "risk_score": 90, "steps": {"step": 1, "action": "x"}},
                {"name": "bad chain 2", "risk_score": 10, "steps": "not-a-list"},
            ],
            "modules": {
                "wayback": {
                    "total_snapshots": 5,
                    "interesting_urls": {"url": "not-a-list"},
                    "by_year": "2020",
                },
                "mitre": {"findings": {"tactic": "Recon"}},
            },
            "mitre": {"findings": {"tactic": "Recon"}, "total_findings": "x"},
        }
        cli.print_full_results(weird)  # must not raise
        out = cli.console.export_text()
        assert "FULL RESULTS BY MODULE" in out
        assert "bad chain" in out

    def test_gauge_clamps_out_of_range_values(self):
        from ui.rich_cli import _gauge

        assert _gauge(150, width=28).plain.count("█") <= 28
        assert _gauge(-5).plain.count("█") == 0
        assert _gauge("not-a-number").plain.count("█") == 0


class TestRiskScorerShapes:
    """AIEngine.analyze() is fed the modules dict, not a flat payload — the
    scorer must understand both shapes (the modules shape used to score ~0)."""

    def test_modules_shape_scores(self):
        from ai.llm_engine import RiskScorer

        scorer = RiskScorer()
        modules = {
            "dns": {"subdomains": [f"s{i}.example.com" for i in range(5)]},
            "network": {"services": [{"port": 22, "service": "ssh", "state": "open"}]},
            "wayback": {"interesting_urls": [{"url": "https://example.com/.env"}]},
        }
        result = scorer.calculate_risk_score(modules)
        assert result["score"] >= 30
        assert any("subdomains" in f for f in result["factors"])
        assert any("22" in f for f in result["factors"])
        assert any("Wayback" in f for f in result["factors"])

    def test_flat_shape_still_scores(self):
        from ai.llm_engine import RiskScorer

        scorer = RiskScorer()
        result = scorer.calculate_risk_score({"subdomains": ["a.example.com"], "services": [], "wayback": {}})
        assert result["score"] == 2

    def test_non_dict_services_entries_ignored(self):
        from ai.llm_engine import RiskScorer

        scorer = RiskScorer()
        result = scorer.calculate_risk_score({"services": ["http", None, 42]})
        assert result["score"] == 0


class TestMitreMapperGuards:
    def test_map_findings_none_does_not_crash(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        assert mapper.map_findings(None) == []
        assert mapper.map_findings("garbage") == []
        assert mapper.map_findings({"modules": None}) == []


class TestFilenameSanitization:
    """URL-like targets must never leak '/' or ':' into output filenames."""

    def test_sanitize_filename(self):
        from osint_eye import _sanitize_filename

        assert _sanitize_filename("example.com") == "example.com"
        assert "/" not in _sanitize_filename("https://acme.com/x")
        assert ":" not in _sanitize_filename("acme.com:8443")
        assert _sanitize_filename("///") == "unknown"

    def test_export_all_offline_contract_smoke(self, tmp_path, monkeypatch):
        """Full offline export run with a hostile URL-like target."""
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)

        engine = OSINTEye(target="https://bad url/target", ai=False, cache=False)
        engine.results = {
            "target": engine.target,
            "scan_date": "2024-01-01T00:00:00",
            "depth": "normal",
            "modules": {},
            "errors": [],
        }

        exports = engine.export_all(str(tmp_path / "out.json"))

        for key in (
            "json", "markdown", "html", "csv", "mitre_json",
            "mitre_navigator", "bounty_report", "graph", "pdf", "burp", "metasploit",
        ):
            assert key in exports, f"missing export: {key}"

        paths = []
        for value in exports.values():
            paths.extend(value) if isinstance(value, list) else paths.append(value)
        for path in paths:
            assert Path(path).exists(), f"export missing on disk: {path}"

        data = json.loads((tmp_path / "out.json").read_text())
        assert data["target"] == "https://bad url/target"

        # summary rendering over the minimal engine results must also work
        engine.print_summary()


# ─────────────────────────────────────────────────────────────────────────────
# OE-QA2 round 2: residual bugs
# ─────────────────────────────────────────────────────────────────────────────
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


class TestCVEAnalyzerScoreCoercion:
    """Null/malformed CVSS scores must not raise (None >= 9.0 TypeError)."""

    def test_prioritize_cves_with_none_and_garbage_scores(self):
        from modules.cve.nvd import CVEAnalyzer

        analyzer = CVEAnalyzer()
        cves = [
            {"id": "CVE-1", "severity": [{"score": None, "severity": "HIGH"}]},
            {"id": "CVE-2", "severity": [{"score": 5.0, "severity": "MEDIUM"}]},
            {"id": "CVE-3", "severity": [{"score": "garbage", "severity": "LOW"}]},
            {"id": "CVE-4", "severity": []},
        ]
        scored = analyzer.prioritize_cves(cves)
        assert [s["priority_score"] for s in scored] == [5.0, 0.0, 0.0, 0.0]

    def test_analyze_service_buckets_null_score_as_low(self):
        from modules.cve.nvd import CVEAnalyzer

        analyzer = CVEAnalyzer()
        with patch.object(
            analyzer.cve,
            "correlate_cve",
            return_value=[{"id": "CVE-1", "severity": [{"score": None}]}],
        ):
            result = analyzer.analyze_service({"service": "http", "version": "1"})
        assert result["low"] == [{"id": "CVE-1", "severity": [{"score": None}]}]
        assert result["cves_found"] == 1


class TestRichCLICountCoercion:
    def test_print_summary_survives_string_counters(self):
        """Hand-loaded JSON with "total_snapshots": "many" crashed max()/int()."""
        from ui.rich_cli import RichCLI

        cli = RichCLI()
        results = {
            "target": "t",
            "modules": {
                "wayback": {"total_snapshots": "many"},
                "permutation": {"total_found": "lots"},
                "github": {"total_findings": None},
                "endpoints": {"total_found": "12"},
            },
            "correlation": {
                "attack_surface_score": {"score": 10, "severity": "LOW", "factors": []}
            },
            "errors": [],
        }
        cli.print_summary(results)  # must not raise


class TestMonitorPanelMarkupSafety:
    """A closing Rich tag inside a target/webhook used to abort with MarkupError."""

    def test_panel_survives_hostile_targets(self):
        from rich.console import Console
        from osint_eye import _print_monitor_panel

        console = Console(record=True, width=200, force_terminal=False, no_color=True)
        _print_monitor_panel(
            console, ["x[/bold]y.com", "ok.com"], 3600, "https://hook[/red]"
        )
        out = console.export_text()
        assert "x[/bold]y.com" in out
        assert "ok.com" in out


class TestWizardMarkupTarget:
    def test_start_survives_hostile_target(self):
        from ui import wizard as wiz

        prompt_answers = iter(
            ["x[/bold]y.com", "", "", "normal", "osint_eye_x"]
        )  # targets, scope, exclusions, depth, output base
        confirm_answers = iter(
            [True, True, True, False, False, False, False, False, False]
        )  # authorized, ai, cache, stealth, rich, agent, pdf, dashboard, cypher

        with patch.object(wiz.Prompt, "ask", staticmethod(lambda *a, **k: next(prompt_answers))), \
             patch.object(wiz.Confirm, "ask", staticmethod(lambda *a, **k: next(confirm_answers))):
            args = wiz.InteractiveWizard().start()

        assert args[0] == "x[/bold]y.com"


class TestExecutorErrorDraining:
    def test_crashed_worker_is_reported(self):
        import concurrent.futures
        from osint_eye import OSINTEye

        engine = OSINTEye(target="example.com", ai=False, cache=False)
        fut = concurrent.futures.Future()
        fut.set_exception(RuntimeError("worker exploded"))

        with patch("builtins.print") as mock_print:
            engine._drain_executor_errors([fut], "phase1")

        assert engine.results["errors"] == ["[phase1] worker crashed: worker exploded"]
        assert engine._module_errors == 1
        printed = " ".join(str(c.args[0]) for c in mock_print.call_args_list if c.args)
        assert "worker exploded" in printed

    def test_completed_futures_are_silent(self):
        import concurrent.futures
        from osint_eye import OSINTEye

        engine = OSINTEye(target="example.com", ai=False, cache=False)
        fut = concurrent.futures.Future()
        fut.set_result({"ok": True})
        engine._drain_executor_errors([fut], "phase1")
        assert engine.results["errors"] == []


class TestRunCveAndTakeoverGuards:
    def _engine(self):
        from osint_eye import OSINTEye

        return OSINTEye(target="example.com", ai=False, cache=False)

    def test_run_cve_tolerates_non_dict_services(self):
        engine = self._engine()
        engine.results["modules"]["network"] = {"services": ["http", 80, None]}
        engine.run_cve()  # must not raise; no valid service -> no CVE branch
        assert "cve" not in engine.results["modules"]

    def test_run_cve_tolerates_null_cves_payload(self):
        engine = self._engine()
        engine.results["modules"]["network"] = {
            "services": [{"service": "http", "state": "open"}]
        }
        with patch.object(engine.cve_scanner, "scan", return_value={"cves": None}):
            engine.run_cve()
        assert engine.results["modules"]["cve"] == {"cves": []}

    def test_run_takeover_tolerates_null_subdomains(self):
        engine = self._engine()
        engine.results["modules"]["permutation"] = {"subdomains": None}
        engine.results["modules"]["dns"] = {"subdomains": None}
        with patch.object(
            engine.takeover_detector, "scan_list", return_value=[]
        ) as mock_scan:
            engine.run_takeover_check()
        mock_scan.assert_called_once_with([])
        assert engine.results["modules"]["takeover"]["checked"] == 0


class TestExportAllCreatesParentDirs:
    def test_export_all_into_missing_directory(self, tmp_path, monkeypatch):
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        engine.results = {
            "target": "example.com",
            "scan_date": "2024-01-01T00:00:00",
            "depth": "normal",
            "modules": {},
            "errors": [],
        }
        exports = engine.export_all("reports/run1/report")
        for key in ("json", "markdown", "html", "mitre_json"):
            assert Path(exports[key]).exists(), f"missing {key}"


class TestHTMLSensitiveFromEndpointsModule:
    RESULTS = {
        "target": "example.com",
        "modules": {
            "endpoints": {
                "found": [{"path": "/login", "status": 200}],
                "sensitive": [{"path": "/.env", "status": 200, "size": 12}],
            },
            "web": {"technologies": {"technologies": ["nginx"]}},
        },
    }

    def test_sensitive_files_visible_from_osint_eye_shape(self):
        from reporting.export import HTMLReporter

        html = HTMLReporter()._build_html(self.RESULTS)
        assert "Sensitive Files" in html
        assert ".env" in html

    def test_web_endpoints_fallback_still_works(self):
        from reporting.export import HTMLReporter

        results = {
            "target": "example.com",
            "modules": {
                "web": {
                    "technologies": {"technologies": ["nginx"]},
                    "endpoints": {"sensitive": [{"path": "/backup.sql", "status": 200}]},
                }
            },
        }
        html = HTMLReporter()._build_html(results)
        assert ".sql" in html


class TestGraphIngestsPermutation:
    def test_permutation_subdomains_become_nodes_and_edges(self):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.ingest_all(
            {
                "modules": {
                    "permutation": {
                        "domain": "example.com",
                        "subdomains": ["api-dev.example.com"],
                    }
                }
            }
        )
        assert builder.graph.has_node("api-dev.example.com")
        assert builder.graph.has_edge("example.com", "api-dev.example.com")

    def test_empty_or_missing_domain_is_noop(self):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.ingest_all({"modules": {"permutation": {"domain": "", "subdomains": ["x.com"]}}})
        assert builder.graph.number_of_nodes() == 0


class TestCorrelatorRecordShapeGuards:
    def test_records_as_list_does_not_crash(self):
        from core.correlator import AssetCorrelator

        correlator = AssetCorrelator()
        correlator.ingest_dns({"domain": "x.com", "records": ["A", "MX"]})
        assert correlator.assets["subdomains"] == set()

    def test_non_iterable_record_value_skipped(self):
        from core.correlator import AssetCorrelator

        correlator = AssetCorrelator()
        correlator.ingest_dns({"domain": "x.com", "records": {"A": 5, "MX": None}})
        assert "ips" not in correlator.assets or not correlator.assets["ips"]

    def test_string_record_value_still_ingested(self):
        from core.correlator import AssetCorrelator

        correlator = AssetCorrelator()
        correlator.ingest_dns({"domain": "x.com", "records": {"A": "1.2.3.4"}})
        assert "1.2.3.4" in correlator.assets["ips"]


class TestMitreWebNoneModule:
    def test_map_findings_with_null_web_module(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        findings = mapper.map_findings({"modules": {"web": None}})
        assert isinstance(findings, list)


class TestPdfOutputName:
    def test_filename_is_sanitized_for_url_targets(self):
        from osint_eye import _pdf_output_name

        name = _pdf_output_name("https://acme.com:8443/x")
        assert name.endswith(".pdf")
        assert "/" not in name
        assert ":" not in name
        assert name.startswith("osint_eye_")


class TestTuiRecordCoercion:
    def test_string_value_becomes_single_element_list(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values("1.2.3.4") == ["1.2.3.4"]

    def test_list_values_are_stringified(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values(["a", 1]) == ["a", "1"]

    def test_junk_is_dropped(self):
        from ui.tui_app import ScanScreen

        assert ScanScreen._coerce_record_values(5) == []
        assert ScanScreen._coerce_record_values(None) == []


class TestPassiveDNSShapeGuards:
    def test_ingest_scan_survives_malformed_shapes(self, tmp_path):
        from core.monitor import PassiveDNSDatabase

        db = PassiveDNSDatabase(db_path=str(tmp_path / "pdns.db"))
        db.ingest_scan(
            {
                "target": "example.com",
                "modules": {
                    "dns": None,
                    "certs": {"subdomains": None},
                },
            }
        )
        db.ingest_scan(
            {
                "target": "example.com",
                "modules": {
                    "dns": {"subdomains": ["a.example.com"], "records": {"A": "1.2.3.4", "MX": 7}},
                    "certs": "garbage",
                },
            }
        )
        rows = db.lookup("a.example.com")
        assert len(rows) == 1
        assert db.get_stats()["total_records"] >= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
