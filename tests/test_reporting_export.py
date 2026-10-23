"""Offline tests for the report exporters: markdown, CSV/HTML, Burp/MSF, PDF.

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
import json
import os
import tempfile
import xml.etree.ElementTree as ET

from tests.conftest import FULL_RESULTS


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
