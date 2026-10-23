"""Tests for the canonical findings extractor (core/findings.py) — offline.

Covers: per-category extraction (dict and string shapes), CVE severity
normalisation, tolerance to corrupt shapes, deterministic ordering,
summaries, worst severity, and fingerprint stability.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.findings import (  # noqa: E402
    RULE_CATALOG,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    Finding,
    extract_findings,
    findings_summary,
    normalize_cve_severity,
    sort_findings,
    worst_severity,
)
from reporting.sarif import extract_findings as sarif_extract_findings  # noqa: E402


def _mixed_results() -> dict:
    return {
        "target": "example.com",
        "modules": {
            "takeover": {
                "vulnerable": [
                    {"subdomain": "dangling.example.com", "service": "s3"},
                    "plain.example.org",
                ]
            },
            "cloud_buckets": {
                "public": [
                    {"url": "https://acme-backup.s3.amazonaws.com/", "provider": "aws"},
                    "https://data.blob.core.windows.net/",
                ]
            },
            "github": {
                "findings": [
                    {"file": "config/settings.py", "snippet": "AWS_KEY=..."},
                    "https://github.com/leak/repo",
                ]
            },
            "cve": {
                "cves": [
                    {
                        "id": "CVE-2026-1111",
                        "severity": [{"severity": "CRITICAL", "score": 9.8}],
                        "description": "Remote code execution",
                    },
                    {"id": "CVE-2026-2222", "severity": {"score": 5.3}},
                    {"id": "CVE-2026-3333"},
                ]
            },
            "endpoints": {
                "sensitive": [
                    {"url": "https://example.com/.env", "status": 200},
                    "https://example.com/backup.sql",
                ]
            },
            "google": {
                "admin_panels": [{"url": "https://example.com/admin"}],
                "login_pages": ["https://example.com/login"],
            },
        },
    }


class TestExtraction:
    def test_every_rule_category_is_covered(self):
        findings = extract_findings(_mixed_results())
        rules = {f.rule for f in findings}
        assert rules == set(RULE_CATALOG)

    def test_takeover_dict_and_string_shapes(self):
        findings = extract_findings(_mixed_results())
        takeovers = [f for f in findings if f.rule == "subdomain_takeover"]
        assert {f.uri for f in takeovers} == {
            "https://dangling.example.com",
            "https://plain.example.org",
        }
        assert all(f.severity == "critical" for f in takeovers)
        assert "(dangling fingerprint: s3)" in takeovers[0].title

    def test_public_buckets_carry_provider_evidence(self):
        findings = extract_findings(_mixed_results())
        buckets = [f for f in findings if f.rule == "public_cloud_bucket"]
        assert len(buckets) == 2
        assert any("provider=aws" in f.evidence for f in buckets)
        assert any("provider=unknown" in f.evidence for f in buckets)

    def test_github_leaks_build_search_uri(self):
        findings = extract_findings(_mixed_results())
        leaks = [f for f in findings if f.rule == "github_secret_leak"]
        assert "https://github.com/search?q=config/settings.py" in [f.uri for f in leaks]
        assert "https://github.com/leak/repo" in [f.uri for f in leaks]
        assert any("AWS_KEY=..." in f.evidence for f in leaks)

    def test_sensitive_files_from_both_shapes(self):
        findings = extract_findings(_mixed_results())
        files = [f for f in findings if f.rule == "sensitive_file"]
        assert {f.uri for f in files} == {
            "https://example.com/.env",
            "https://example.com/backup.sql",
        }
        assert any("http_status=200" in f.evidence for f in files)

    def test_google_dorks_map_to_two_rules(self):
        findings = extract_findings(_mixed_results())
        assert {f.uri for f in findings if f.rule == "exposed_admin_panel"} == {
            "https://example.com/admin"
        }
        assert {f.uri for f in findings if f.rule == "exposed_login_page"} == {
            "https://example.com/login"
        }

    def test_empty_and_corrupt_shapes_yield_no_findings(self):
        for payload in [
            {},
            {"target": "example.com"},
            {"target": "example.com", "modules": None},
            {"target": "x.com", "modules": {"takeover": {"vulnerable": [None, "", 42]}}},
            {"target": "x.com", "modules": {"cve": {"cves": ["CVE-X", None, {"id": ""}]}}},
            {
                "target": "x.com",
                "modules": {"endpoints": {"sensitive": [None, {"url": ""}, ""]}},
            },
        ]:
            assert extract_findings(payload) == []

    def test_findings_are_json_round_trip_safe(self):
        findings = extract_findings(_mixed_results())
        restored = [Finding(**f.to_dict()) for f in findings]
        restored = [
            Finding(
                rule=f.rule,
                severity=f.severity,
                title=f.title,
                uri=f.uri,
                evidence=f.evidence,
                source_module=f.source_module,
            )
            for f in restored
        ]
        assert restored == findings
        json.dumps([f.to_dict() for f in findings])


class TestCVESeverity:
    @pytest.mark.parametrize(
        "sev,expected",
        [
            ({"severity": "CRITICAL"}, "critical"),
            ({"severity": "HIGH"}, "high"),
            ({"severity": "MEDIUM"}, "medium"),
            ({"severity": "LOW"}, "low"),
            ([{"severity": "CRITICAL", "score": 9.8}], "critical"),
            ({"score": 9.5}, "critical"),
            ({"score": 7.2}, "high"),
            ({"score": 4.5}, "medium"),
            ({"score": 1.0}, "low"),
            ({"score": "junk"}, "low"),
            ({}, "low"),
            (None, "low"),
            ("weird", "low"),
        ],
    )
    def test_normalisation_table(self, sev, expected):
        assert normalize_cve_severity({"severity": sev}) == expected

    def test_named_severity_wins_over_score(self):
        assert (
            normalize_cve_severity({"severity": {"severity": "LOW", "score": 9.9}})
            == "low"
        )


class TestOrderingAndSummary:
    def test_sort_puts_critical_first_and_is_deterministic(self):
        findings = extract_findings(_mixed_results())
        ordered = sort_findings(findings)
        ranks = [SEVERITY_RANK[f.severity] for f in ordered]
        assert ranks == sorted(ranks, reverse=True)
        assert ordered == sort_findings(ordered)

    def test_summary_counts(self):
        findings = extract_findings(_mixed_results())
        summary = findings_summary(findings)
        assert summary["total"] == len(findings)
        assert sum(summary["by_severity"].values()) == len(findings)
        assert sum(summary["by_rule"].values()) == len(findings)
        assert set(summary["by_severity"]) == set(SEVERITY_ORDER)

    def test_worst_severity(self):
        assert worst_severity([]) is None
        findings = extract_findings(_mixed_results())
        assert worst_severity(findings) == "critical"

    def test_severity_ladder_is_consistent_with_rank(self):
        ranks = [SEVERITY_RANK[name] for name in SEVERITY_ORDER]
        assert ranks == sorted(ranks)


class TestFingerprints:
    def test_stable_across_extractions(self):
        first = extract_findings(_mixed_results())
        second = extract_findings(json.loads(json.dumps(_mixed_results())))
        assert first == second
        assert [f.fingerprint for f in first] == [f.fingerprint for f in second]

    def test_fingerprint_is_derived_from_rule_uri_title(self):
        finding = Finding(
            rule="sensitive_file", severity="medium", title="t", uri="https://x"
        )
        import hashlib

        expected = hashlib.sha256(b"sensitive_file|https://x|t").hexdigest()[:16]
        assert finding.fingerprint == expected


class TestSarifDelegation:
    def test_sarif_projects_all_canonical_findings(self):
        canonical = extract_findings(_mixed_results())
        projected = sarif_extract_findings(_mixed_results())
        assert len(projected) == len(canonical)
        assert {p["rule_id"] for p in projected} == {
            "OE001",
            "OE002",
            "OE003",
            "OE004",
            "OE005",
            "OE006",
            "OE007",
        }

    def test_sarif_entries_carry_evidence_and_module(self):
        projected = sarif_extract_findings(_mixed_results())
        for entry in projected:
            assert "evidence" in entry and "source_module" in entry
            assert entry["level"] in ("error", "warning", "note")
