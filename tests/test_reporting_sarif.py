"""Tests for SARIF export (reporting/sarif.py) — 100% offline.

Covers: SARIF 2.1.0 skeleton validity, rule catalogue, per-finding level
mapping (including the many CVE severity shapes), tolerance to corrupt
module shapes, fingerprint stability, and the export_all wiring.
"""

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from reporting.sarif import (  # noqa: E402
    INFORMATION_URI,
    RULES,
    SARIF_VERSION,
    TOOL_NAME,
    SarifExporter,
    extract_findings,
)


def _results_with_everything() -> dict:
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
                    {
                        "id": "CVE-2026-2222",
                        "severity": {"severity": "MEDIUM", "score": 5.3},
                    },
                    {"id": "CVE-2026-3333", "severity": {"score": 2.1}},
                    {"id": "CVE-2026-4444", "severity": "weird-shape"},
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


def _load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


class TestSkeleton:
    def test_valid_sarif_skeleton(self, tmp_path):
        path = SarifExporter().export(_results_with_everything(), str(tmp_path / "o.sarif"))
        log = _load(path)
        assert log["version"] == SARIF_VERSION == "2.1.0"
        assert log["$schema"].endswith("sarif-2.1.0.json")
        run = log["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == TOOL_NAME
        assert driver["informationUri"] == INFORMATION_URI
        assert {r["id"] for r in driver["rules"]} == set(RULES)
        assert run["invocations"][0]["executionSuccessful"] is True

    def test_every_finding_class_produces_results(self, tmp_path):
        path = SarifExporter().export(_results_with_everything(), str(tmp_path / "o.sarif"))
        results = _load(path)["runs"][0]["results"]
        by_rule = {r["ruleId"] for r in results}
        assert by_rule == set(RULES)
        for r in results:
            assert r["level"] in ("error", "warning", "note")
            assert r["message"]["text"].strip()
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert uri.strip()
            assert (
                r["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
            )
            assert r["partialFingerprints"]["osintEye/finding/v1"]

    def test_empty_results_still_valid(self, tmp_path):
        path = SarifExporter().export({"target": "example.com", "modules": {}}, str(tmp_path / "e.sarif"))
        log = _load(path)
        assert log["runs"][0]["results"] == []

    def test_default_filename_from_target(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = SarifExporter().export({"target": "example.com", "modules": {}})
        assert path.startswith("osint_eye_example.com_")
        assert path.endswith(".sarif")
        assert _load(path)["version"] == "2.1.0"


class TestLevels:
    def test_cve_severity_shapes(self, tmp_path):
        path = SarifExporter().export(_results_with_everything(), str(tmp_path / "o.sarif"))
        levels = {
            r["message"]["text"].split(" ")[0]: r["level"]
            for r in _load(path)["runs"][0]["results"]
            if r["ruleId"] == "OE004"
        }
        assert levels["CVE-2026-1111"] == "error"  # CRITICAL via list shape
        assert levels["CVE-2026-2222"] == "warning"  # MEDIUM via dict shape
        assert levels["CVE-2026-3333"] == "note"  # low score fallback
        assert levels["CVE-2026-4444"] == "note"  # malformed severity

    @pytest.mark.parametrize(
        "sev,expected",
        [
            ({"severity": "HIGH", "score": 7.5}, "error"),
            ({"severity": "LOW"}, "note"),
            ({"score": 9.0}, "error"),
            ({"score": 4.0}, "warning"),
            ({"score": "junk"}, "note"),
            (None, "note"),
        ],
    )
    def test_cve_level_mapping_table(self, sev, expected):
        findings = extract_findings(
            {"target": "t.com", "modules": {"cve": {"cves": [{"id": "CVE-X", "severity": sev}]}}}
        )
        assert findings[0]["level"] == expected

    def test_static_rule_levels(self):
        findings = extract_findings(_results_with_everything())
        levels = {(f["rule_id"], f["level"]) for f in findings}
        assert ("OE001", "error") in levels
        assert ("OE002", "error") in levels
        assert ("OE003", "warning") in levels  # potential leak = medium
        assert ("OE005", "warning") in levels
        assert ("OE006", "note") in levels  # login page = low
        assert ("OE007", "warning") in levels  # admin panel = medium


class TestTolerance:
    @pytest.mark.parametrize(
        "payload",
        [
            {"target": "example.com"},
            {"target": "example.com", "modules": None},
            {"target": "example.com", "modules": {"takeover": None}},
            {"target": "example.com", "modules": {"takeover": {"vulnerable": None}}},
            {"target": "example.com", "modules": {"cve": {"cves": ["CVE-X", None, 42]}}},
            {
                "target": "example.com",
                "modules": {"endpoints": {"sensitive": [None, "", {"url": ""}]}},
            },
        ],
    )
    def test_corrupt_shapes_never_crash(self, tmp_path, payload):
        path = SarifExporter().export(payload, str(tmp_path / "c.sarif"))
        log = _load(path)
        assert log["version"] == "2.1.0"

    def test_control_chars_stripped(self, tmp_path):
        payload = {
            "target": "example.com",
            "modules": {
                "takeover": {"vulnerable": [{"subdomain": "bad\x01.example.com"}]}
            },
        }
        path = SarifExporter().export(payload, str(tmp_path / "x.sarif"))
        log = _load(path)
        assert "\x01" not in json.dumps(log)


class TestFingerprints:
    def test_stable_across_calls(self):
        first = extract_findings(_results_with_everything())
        second = extract_findings(json.loads(json.dumps(_results_with_everything())))
        assert first == second

    def test_fingerprint_algorithm(self):
        from reporting.sarif import _fingerprint

        expected = hashlib.sha256(
            b"OE001|https://sub|message"
        ).hexdigest()[:16]
        assert _fingerprint("OE001", "https://sub", "message") == expected


class TestExportWiring:
    def test_export_all_includes_sarif(self, tmp_path, monkeypatch):
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        engine.results["modules"] = {
            "cloud_buckets": {
                "public": [{"url": "https://b.s3.amazonaws.com/", "provider": "aws"}]
            }
        }
        exports = engine.export_all(str(tmp_path / "scan.json"))
        assert "sarif" in exports
        log = _load(exports["sarif"])
        rule_ids = {r["ruleId"] for r in log["runs"][0]["results"]}
        assert "OE002" in rule_ids

    def test_export_logs_through_logger(self, tmp_path, caplog):
        import logging

        with caplog.at_level(logging.INFO, logger="osint_eye.reporting.sarif"):
            path = SarifExporter().export(
                {"target": "example.com", "modules": {}}, str(tmp_path / "l.sarif")
            )
        records = [
            r
            for r in caplog.records
            if "SARIF report saved" in r.message
        ]
        assert records and records[0].name == "osint_eye.reporting.sarif"
        assert os.path.exists(path)
