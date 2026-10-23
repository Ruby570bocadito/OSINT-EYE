"""Offline tests for core engines: correlator, session cache, scan diff, plugins, async.

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
import os
import tempfile


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
