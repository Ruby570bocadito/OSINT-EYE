"""Offline tests for cert/CDN/CVE collectors (modules/certs, modules/osint, modules/cve).

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
from unittest.mock import MagicMock, patch


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
