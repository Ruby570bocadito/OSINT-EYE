"""Offline tests for DNS wildcard detection (modules/dns/wildcard.py).

No DNS traffic: resolution is injected as a dict-backed ``resolve_fn``
and random labels come from a deterministic ``label_factory``.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.dns.wildcard import WildcardDetector
from modules.dns.dns_scanner import SubdomainEnumerator

DOMAIN = "example.com"
WILDCARD_IP = "10.0.0.7"
REAL_IP = "93.184.216.34"


def _detector_with_answers(answers, probes=3):
    """WildcardDetector whose DNS is a static map; unknown hosts fail."""
    def resolve_fn(host):
        if host in answers:
            return answers[host]
        raise OSError("NXDOMAIN")

    counter = {"n": 0}

    def label_factory():
        counter["n"] += 1
        return f"probe{counter['n']}"

    return WildcardDetector(probes=probes, resolve_fn=resolve_fn, label_factory=label_factory)


# ─────────────────────────────────────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────────────────────────────────────
class TestDetection:
    def test_all_probes_resolve_is_high_confidence_wildcard(self):
        answers = {f"probe{i}.{DOMAIN}": WILDCARD_IP for i in range(1, 4)}
        det = _detector_with_answers(answers)
        result = det.detect(DOMAIN)
        assert result["wildcard"] is True
        assert result["confidence"] == "high"
        assert result["wildcard_ips"] == [WILDCARD_IP]
        assert result["resolved"] == 3
        assert result["probes"] == 3

    def test_no_probe_resolves_means_no_wildcard(self):
        det = _detector_with_answers({})
        result = det.detect(DOMAIN)
        assert result["wildcard"] is False
        assert result["confidence"] == "none"
        assert result["wildcard_ips"] == []
        assert det.is_false_positive([WILDCARD_IP]) is False

    def test_partial_resolution_is_medium_confidence(self):
        answers = {"probe1." + DOMAIN: WILDCARD_IP}
        det = _detector_with_answers(answers)
        result = det.detect(DOMAIN)
        assert result["wildcard"] is True
        assert result["confidence"] == "medium"
        assert result["resolved"] == 1

    def test_multiple_wildcard_ips_are_collected_sorted(self):
        answers = {
            "probe1." + DOMAIN: "10.0.0.9",
            "probe2." + DOMAIN: "10.0.0.2",
            "probe3." + DOMAIN: "10.0.0.9",
        }
        det = _detector_with_answers(answers)
        result = det.detect(DOMAIN)
        assert result["wildcard_ips"] == ["10.0.0.2", "10.0.0.9"]

    def test_empty_domain_degrades_gracefully(self):
        det = _detector_with_answers({})
        result = det.detect("   ")
        assert result["wildcard"] is False
        assert result["probes"] == 0
        assert "error" in result

    def test_resolver_explosion_never_raises(self):
        def broken_resolve(host):
            raise RuntimeError("resolver exploded")

        det = WildcardDetector(probes=2, resolve_fn=broken_resolve,
                               label_factory=lambda: "p")
        result = det.detect(DOMAIN)
        # per-probe failures count as "not resolved": graceful, no crash
        assert result["wildcard"] is False
        assert result["resolved"] == 0
        assert result["probes"] == 2

    def test_last_detection_is_kept_for_filtering(self):
        answers = {f"probe{i}.{DOMAIN}": WILDCARD_IP for i in range(1, 4)}
        det = _detector_with_answers(answers)
        det.detect(DOMAIN)
        assert det.last_detection["wildcard"] is True


# ─────────────────────────────────────────────────────────────────────────────
# False-positive filter semantics
# ─────────────────────────────────────────────────────────────────────────────
class TestFalsePositive:
    def _active_detector(self):
        answers = {f"probe{i}.{DOMAIN}": WILDCARD_IP for i in range(1, 4)}
        det = _detector_with_answers(answers)
        det.detect(DOMAIN)
        return det

    def test_wildcard_only_answer_is_dropped(self):
        det = self._active_detector()
        assert det.is_false_positive([WILDCARD_IP]) is True

    def test_real_answer_is_kept(self):
        det = self._active_detector()
        assert det.is_false_positive([REAL_IP]) is False

    def test_mixed_answer_is_kept(self):
        det = self._active_detector()
        assert det.is_false_positive([WILDCARD_IP, REAL_IP]) is False

    def test_empty_answer_is_never_dropped(self):
        det = self._active_detector()
        assert det.is_false_positive([]) is False
        assert det.is_false_positive([None, ""]) is False

    def test_inactive_detector_never_drops(self):
        det = _detector_with_answers({})  # no wildcard
        det.detect(DOMAIN)
        assert det.is_false_positive([WILDCARD_IP]) is False


# ─────────────────────────────────────────────────────────────────────────────
# Enumeration integration (socket patched, fully offline)
# ─────────────────────────────────────────────────────────────────────────────
class TestEnumeratorIntegration:
    def test_bruteforce_drops_wildcard_candidates(self, monkeypatch):
        import modules.dns.dns_scanner as ds

        det = self or None
        # static DNS: every random probe + "www" → wildcard IP; "api" → real
        def fake_gethostbyname(host):
            if host.startswith("oe-wc-") or host.startswith("www."):
                return WILDCARD_IP
            if host.startswith("api."):
                return REAL_IP
            raise OSError("NXDOMAIN")

        monkeypatch.setattr(ds.socket, "gethostbyname", fake_gethostbyname)
        monkeypatch.setattr(
            SubdomainEnumerator, "load_wordlist", lambda self: ["www", "api"]
        )

        detector = WildcardDetector(
            probes=2,
            resolve_fn=fake_gethostbyname,
            label_factory=lambda: "oe-wc-x",
        )
        detector.detect(DOMAIN)

        enum = SubdomainEnumerator()
        result = enum.enumerate(DOMAIN, wildcard_detector=detector)

        assert result == ["api.example.com"]
        assert enum.wildcard_skipped == 1

    def test_bruteforce_without_detector_keeps_everything(self, monkeypatch):
        import modules.dns.dns_scanner as ds

        def fake_gethostbyname(host):
            return WILDCARD_IP  # wildcard active but nobody filtered it

        monkeypatch.setattr(ds.socket, "gethostbyname", fake_gethostbyname)
        monkeypatch.setattr(
            SubdomainEnumerator, "load_wordlist", lambda self: ["www"]
        )

        enum = SubdomainEnumerator()
        result = enum.enumerate(DOMAIN)
        assert result == ["www.example.com"]
        assert enum.wildcard_skipped == 0

    def test_permutator_drops_wildcard_candidates(self, monkeypatch):
        from modules.dns.subdomain_permutator import SubdomainPermutator
        import modules.dns.subdomain_permutator as sp

        def fake_gethostbyname(host):
            if host.startswith("oe-wc-") or host.startswith("www2."):
                return WILDCARD_IP
            if host.startswith("api."):
                return REAL_IP
            raise OSError("NXDOMAIN")

        monkeypatch.setattr(sp.socket, "gethostbyname", fake_gethostbyname)
        monkeypatch.setattr(
            SubdomainPermutator,
            "generate_permutations",
            lambda self, domain, base_names=None: ["www2", "api"],
        )

        detector = WildcardDetector(
            probes=2,
            resolve_fn=fake_gethostbyname,
            label_factory=lambda: "oe-wc-y",
        )
        detector.detect(DOMAIN)

        perm = SubdomainPermutator(threads=2)
        result = perm.enumerate(DOMAIN, wildcard_detector=detector)

        assert result == ["api.example.com"]
        assert perm.wildcard_skipped == 1

    def test_permutator_without_detection_is_unchanged(self, monkeypatch):
        from modules.dns.subdomain_permutator import SubdomainPermutator
        import modules.dns.subdomain_permutator as sp

        monkeypatch.setattr(
            sp.socket, "gethostbyname", lambda host: WILDCARD_IP
        )
        monkeypatch.setattr(
            SubdomainPermutator,
            "generate_permutations",
            lambda self, domain, base_names=None: ["www2"],
        )

        perm = SubdomainPermutator(threads=2)
        result = perm.enumerate(DOMAIN)
        assert result == ["www2.example.com"]

    def test_detector_inactive_does_not_filter_even_if_passed(self, monkeypatch):
        import modules.dns.dns_scanner as ds

        def fake_gethostbyname(host):
            return REAL_IP  # zone without wildcard

        monkeypatch.setattr(ds.socket, "gethostbyname", fake_gethostbyname)
        monkeypatch.setattr(
            SubdomainEnumerator, "load_wordlist", lambda self: ["api"]
        )

        detector = WildcardDetector(
            probes=1, resolve_fn=fake_gethostbyname, label_factory=lambda: "oe-wc-z"
        )
        detector.detect(DOMAIN)  # resolves → but that IS a wildcard... 

        # force an inactive detection (no probes resolved)
        detector.last_detection = {
            "domain": DOMAIN, "wildcard": False, "confidence": "none",
            "wildcard_ips": [], "probes": 1, "resolved": 0,
        }

        enum = SubdomainEnumerator()
        result = enum.enumerate(DOMAIN, wildcard_detector=detector)
        assert result == ["api.example.com"]
        assert enum.wildcard_skipped == 0


# ─────────────────────────────────────────────────────────────────────────────
# DNSScanner orchestration
# ─────────────────────────────────────────────────────────────────────────────
class TestDNSScannerWildcard:
    def _scanner(self, wildcard=True):
        from modules.dns import DNSScanner

        scanner = DNSScanner(passive=False, wildcard=wildcard)
        scanner.resolver = MagicMock()
        scanner.resolver.get_all_records.return_value = {"A": ["93.184.216.34"]}
        scanner.resolver.check_spf.return_value = {"exists": False}
        scanner.resolver.check_dmarc.return_value = {"exists": False}
        scanner.subenum = MagicMock()
        scanner.subenum.enumerate.return_value = ["api.example.com"]
        scanner.subenum.wildcard_skipped = 4
        scanner.zonetransfer = MagicMock()
        scanner.zonetransfer.check_axfr_enabled.return_value = {"vulnerable": False}
        return scanner

    def test_full_scan_reports_wildcard_and_passes_detector(self):
        scanner = self._scanner()
        detection = {
            "domain": DOMAIN, "wildcard": True, "confidence": "high",
            "wildcard_ips": [WILDCARD_IP], "probes": 3, "resolved": 3,
        }
        scanner.wildcard_detector = MagicMock()
        scanner.wildcard_detector.detect.return_value = detection

        result = scanner.scan(DOMAIN, "full")

        assert result["wildcard"] == detection
        _, kwargs = scanner.subenum.enumerate.call_args
        assert kwargs.get("wildcard_detector") is scanner.wildcard_detector
        assert result["wildcard"]["skipped"] == 4

    def test_no_wildcard_passes_none_detector(self):
        scanner = self._scanner()
        detection = {
            "domain": DOMAIN, "wildcard": False, "confidence": "none",
            "wildcard_ips": [], "probes": 3, "resolved": 0,
        }
        scanner.wildcard_detector = MagicMock()
        scanner.wildcard_detector.detect.return_value = detection

        result = scanner.scan(DOMAIN, "subdomains")

        _, kwargs = scanner.subenum.enumerate.call_args
        assert kwargs.get("wildcard_detector") is None
        assert "skipped" not in result["wildcard"]

    def test_detection_failure_degrades_and_continues(self):
        scanner = self._scanner()
        scanner.wildcard_detector = MagicMock()
        scanner.wildcard_detector.detect.side_effect = RuntimeError("boom")

        result = scanner.scan(DOMAIN, "subdomains")

        assert result["wildcard"]["wildcard"] is False
        assert "error" in result["wildcard"]
        # enumeration still ran (with no filtering)
        _, kwargs = scanner.subenum.enumerate.call_args
        assert kwargs.get("wildcard_detector") is None
        assert result["subdomains"] == ["api.example.com"]

    def test_wildcard_disabled_keeps_default_shape(self):
        scanner = self._scanner(wildcard=False)

        result = scanner.scan(DOMAIN, "subdomains")

        assert scanner.wildcard_detector is None
        assert result["wildcard"]["wildcard"] is False
        assert result["wildcard"]["probes"] == 0
        _, kwargs = scanner.subenum.enumerate.call_args
        assert kwargs.get("wildcard_detector") is None

    def test_basic_scan_has_no_wildcard_section(self):
        scanner = self._scanner()
        result = scanner.scan(DOMAIN, "basic")
        assert "wildcard" not in result
        assert "subdomains" in result
