"""Offline tests for the email security audit (modules/dns/email_security.py).

DNS is a fake resolver backed by a static record map; no network.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from modules.dns.email_security import (
    DKIM_SELECTORS,
    EmailSecurityAuditor,
    _tag_value,
    _txt_text,
)

DOMAIN = "example.com"


def _fake_resolver(records):
    """DNSResolver stand-in: records maps (name, type) -> list of strings."""
    resolver = MagicMock()

    def fake_resolve(name, rtype, *args, **kwargs):
        key = (str(name).lower(), str(rtype))
        if key in records:
            return list(records[key])
        raise OSError("NXDOMAIN")

    def fake_check_spf(domain):
        return {"exists": False, "record": "", "policy": None}

    def fake_check_dmarc(domain):
        return {"exists": False, "record": "", "policy": None}

    resolver.resolve.side_effect = fake_resolve
    resolver.check_spf.side_effect = fake_check_spf
    resolver.check_dmarc.side_effect = fake_check_dmarc
    return resolver


SPF_HARD = {"exists": True, "record": "v=spf1 ip4:1.2.3.4 -all", "policy": "hardfail"}
SPF_SOFT = {"exists": True, "record": "v=spf1 ~all", "policy": "softfail"}
SPF_OPEN = {"exists": True, "record": "v=spf1 +all", "policy": "pass-all"}
SPF_ABSENT = {"exists": False, "record": "", "policy": None}
DMARC_REJECT = {"exists": True, "record": "v=DMARC1; p=reject; rua=mailto:d@x", "policy": "reject"}
DMARC_NONE = {"exists": True, "record": "v=DMARC1; p=none", "policy": "none"}
DMARC_ABSENT = {"exists": False, "record": "", "policy": None}


# ─────────────────────────────────────────────────────────────────────────────
# Text/tag helpers
# ─────────────────────────────────────────────────────────────────────────────
class TestHelpers:
    def test_txt_text_joins_fragments(self):
        assert _txt_text(['"v=spf1', ' ip4:1.2.3.4"']) == "v=spf1 ip4:1.2.3.4"

    def test_tag_value_case_insensitive(self):
        assert _tag_value("v=STSv1; id=2023a", "ID") == "2023a"
        assert _tag_value("v=TLSRPTv1; rua=mailto:r@x", "rua") == "mailto:r@x"

    def test_tag_value_none_when_absent(self):
        assert _tag_value("v=STSv1", "id") is None


# ─────────────────────────────────────────────────────────────────────────────
# Individual checks
# ─────────────────────────────────────────────────────────────────────────────
class TestChecks:
    def test_dkim_found_on_common_selector(self):
        records = {("google._domainkey." + DOMAIN, "TXT"): ['"v=DKIM1; p=MIIB"']}
        auditor = EmailSecurityAuditor(resolver=_fake_resolver(records))
        result = auditor.check_dkim(DOMAIN)
        assert result["present"] is True
        assert result["found"][0]["selector"] == "google"
        assert result["selectors_probed"] == len(DKIM_SELECTORS)

    def test_dkim_garbage_txt_is_not_evidence(self):
        records = {("default._domainkey." + DOMAIN, "TXT"): ['"not a key"']}
        auditor = EmailSecurityAuditor(resolver=_fake_resolver(records))
        assert auditor.check_dkim(DOMAIN)["present"] is False

    def test_dkim_absent(self):
        auditor = EmailSecurityAuditor(resolver=_fake_resolver({}))
        result = auditor.check_dkim(DOMAIN)
        assert result["present"] is False
        assert result["found"] == []

    def test_mta_sts_present_with_id(self):
        records = {("_mta-sts." + DOMAIN, "TXT"): ['"v=STSv1; id=2024a"']}
        auditor = EmailSecurityAuditor(resolver=_fake_resolver(records))
        result = auditor.check_mta_sts(DOMAIN)
        assert result["present"] is True
        assert result["id"] == "2024a"

    def test_mta_sts_absent(self):
        auditor = EmailSecurityAuditor(resolver=_fake_resolver({}))
        assert auditor.check_mta_sts(DOMAIN)["present"] is False

    def test_tls_rpt_parses_rua(self):
        records = {
            ("_smtp._tls." + DOMAIN, "TXT"): ['"v=TLSRPTv1; rua=mailto:tls@x,https://r/x"']
        }
        auditor = EmailSecurityAuditor(resolver=_fake_resolver(records))
        result = auditor.check_tls_rpt(DOMAIN)
        assert result["present"] is True
        assert result["rua"] == ["mailto:tls@x", "https://r/x"]

    def test_bimi_found(self):
        records = {("default._bimi." + DOMAIN, "TXT"): ['"v=BIMI1; l=https://l/x.svg"']}
        auditor = EmailSecurityAuditor(resolver=_fake_resolver(records))
        result = auditor.check_bimi(DOMAIN)
        assert result["present"] is True
        assert result["selector"] == "default"

    def test_mx_presence(self):
        records = {(DOMAIN, "MX"): ['"10 mail." + DOMAIN + "."']}
        auditor = EmailSecurityAuditor(resolver=_fake_resolver(records))
        assert auditor.check_mx(DOMAIN)["present"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Explicable spoofing score
# ─────────────────────────────────────────────────────────────────────────────
class TestScore:
    def _audit(self, records, spf=None, dmarc=None):
        auditor = EmailSecurityAuditor(resolver=_fake_resolver(records))
        return auditor.audit(DOMAIN, spf=spf, dmarc=dmarc)

    def test_hardened_domain_scores_high(self):
        records = {
            ("google._domainkey." + DOMAIN, "TXT"): ['"v=DKIM1; p=MIIB"'],
            ("_mta-sts." + DOMAIN, "TXT"): ['"v=STSv1; id=1"'],
            ("_smtp._tls." + DOMAIN, "TXT"): ['"v=TLSRPTv1; rua=mailto:r@x"'],
            (DOMAIN, "MX"): ['"10 mail"'],
        }
        result = self._audit(records, spf=SPF_HARD, dmarc=DMARC_REJECT)
        assert result["spoofing_score"] == 100
        assert result["risk"] == "low"
        assert result["score_breakdown"] == {
            "spf": 0, "dmarc": 0, "dkim": 0, "mta_sts": 0, "tls_rpt": 0,
        }

    def test_unprotected_domain_scores_critical(self):
        result = self._audit({}, spf=SPF_ABSENT, dmarc=DMARC_ABSENT)
        # 100 -40 (spf) -40 (dmarc) -15 (dkim) = 5; no MX → sts/rpt not counted
        assert result["spoofing_score"] == 5
        assert result["risk"] == "critical"

    def test_open_spf_is_heavily_penalised(self):
        result = self._audit({}, spf=SPF_OPEN, dmarc=DMARC_REJECT)
        assert result["score_breakdown"]["spf"] == -30

    def test_dmarc_none_is_penalised_more_than_reject(self):
        strict = self._audit({}, spf=SPF_HARD, dmarc=DMARC_REJECT)
        lax = self._audit({}, spf=SPF_HARD, dmarc=DMARC_NONE)
        assert lax["spoofing_score"] < strict["spoofing_score"]

    def test_mta_sts_not_counted_without_mx(self):
        with_mx = self._audit({(DOMAIN, "MX"): ['"10 mail"']}, spf=SPF_HARD, dmarc=DMARC_REJECT)
        without_mx = self._audit({}, spf=SPF_HARD, dmarc=DMARC_REJECT)
        # same spf/dmarc/dkim: the difference is exactly sts+rpt (-10)
        assert with_mx["spoofing_score"] == without_mx["spoofing_score"] - 10

    def test_recommendations_are_actionable(self):
        result = self._audit({}, spf=SPF_ABSENT, dmarc=DMARC_ABSENT)
        text = " ".join(result["recommendations"]).lower()
        assert "spf" in text
        assert "dmarc" in text
        assert "dkim" in text

    def test_no_recommendation_when_hardened(self):
        records = {
            ("google._domainkey." + DOMAIN, "TXT"): ['"v=DKIM1; p=MIIB"'],
            ("_mta-sts." + DOMAIN, "TXT"): ['"v=STSv1; id=1"'],
            ("_smtp._tls." + DOMAIN, "TXT"): ['"v=TLSRPTv1; rua=mailto:r@x"'],
            (DOMAIN, "MX"): ['"10 mail"'],
        }
        result = self._audit(records, spf=SPF_HARD, dmarc=DMARC_REJECT)
        assert result["recommendations"] == []

    def test_score_always_within_bounds(self):
        result = self._audit({}, spf=SPF_OPEN, dmarc=DMARC_ABSENT)
        assert 0 <= result["spoofing_score"] <= 100

    def test_spf_dmarc_defaults_when_not_given(self):
        auditor = EmailSecurityAuditor(resolver=_fake_resolver({}))
        result = auditor.audit(DOMAIN)
        assert result["spf"]["exists"] is False
        assert result["dmarc"]["exists"] is False


# ─────────────────────────────────────────────────────────────────────────────
# DNSScanner integration
# ─────────────────────────────────────────────────────────────────────────────
class TestDNSScannerIntegration:
    def test_full_scan_includes_email_security(self):
        from modules.dns import DNSScanner

        scanner = DNSScanner(passive=False, wildcard=False)
        scanner.resolver = MagicMock()
        scanner.resolver.get_all_records.return_value = {"A": ["1.2.3.4"]}
        scanner.resolver.check_spf.return_value = SPF_HARD
        scanner.resolver.check_dmarc.return_value = DMARC_REJECT
        scanner.subenum = MagicMock()
        scanner.subenum.enumerate.return_value = []
        scanner.zonetransfer = MagicMock()
        scanner.zonetransfer.check_axfr_enabled.return_value = {}
        scanner.email_auditor = MagicMock()
        scanner.email_auditor.audit.return_value = {
            "domain": DOMAIN, "spoofing_score": 100, "risk": "low",
        }

        result = scanner.scan(DOMAIN, "full")

        assert result["email_security"]["risk"] == "low"
        args, kwargs = scanner.email_auditor.audit.call_args
        assert kwargs.get("spf") == SPF_HARD
        assert kwargs.get("dmarc") == DMARC_REJECT

    def test_email_audit_failure_degrades(self):
        from modules.dns import DNSScanner

        scanner = DNSScanner(passive=False, wildcard=False)
        scanner.resolver = MagicMock()
        scanner.resolver.get_all_records.return_value = {}
        scanner.resolver.check_spf.return_value = SPF_HARD
        scanner.resolver.check_dmarc.return_value = DMARC_REJECT
        scanner.subenum = MagicMock()
        scanner.subenum.enumerate.return_value = []
        scanner.zonetransfer = MagicMock()
        scanner.zonetransfer.check_axfr_enabled.return_value = {}
        scanner.email_auditor = MagicMock()
        scanner.email_auditor.audit.side_effect = RuntimeError("boom")

        result = scanner.scan(DOMAIN, "full")

        assert result["email_security"]["risk"] == "unknown"
        assert "error" in result["email_security"]

    def test_basic_scan_has_no_email_section(self):
        from modules.dns import DNSScanner

        scanner = DNSScanner(passive=False, wildcard=False)
        scanner.resolver = MagicMock()
        scanner.resolver.get_all_records.return_value = {}
        scanner.resolver.check_spf.return_value = SPF_HARD
        scanner.resolver.check_dmarc.return_value = DMARC_REJECT

        result = scanner.scan(DOMAIN, "basic")
        assert "email_security" not in result
