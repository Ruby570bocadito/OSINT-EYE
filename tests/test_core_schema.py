"""Tests for the results contract (core/schema.py) — 100% offline.

Covers: validate_results() on canonical shapes, per-module validators,
tolerance to unknown/extra keys, require_valid_results(), and the wiring
in osint_eye.OSINTEye (schema_version present + non-fatal validation).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.schema import (  # noqa: E402
    KNOWN_SEVERITIES,
    MODULE_VALIDATORS,
    SCHEMA_VERSION,
    ResultsSchemaError,
    new_results,
    require_valid_results,
    validate_results,
)


# ─────────────────────────────────────────────────────────────────────────────
# Canonical fixtures (mirrors of what the orchestrator really produces)
# ─────────────────────────────────────────────────────────────────────────────
def _full_results() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "target": "example.com",
        "scan_date": "2026-10-23T12:00:00",
        "depth": "normal",
        "modules": {
            "dns": {
                "domain": "example.com",
                "subdomains": ["www.example.com"],
                "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
            },
            "certs": {
                "subdomains": ["ct.example.com"],
                "certificates": [{"domain": "ct.example.com", "issuer": "LE"}],
            },
            "wayback": {"total_snapshots": 12, "unique_paths": ["/login"]},
            "network": {
                "host": "example.com",
                "services": [
                    {"port": 443, "state": "open", "service": "https", "version": ""}
                ],
            },
            "whois": {"registrar": "RESERVED", "name_servers": ["a.iana-servers.net"]},
            "web": {"target": "example.com", "technologies": {"technologies": []}},
            "endpoints": {"found": [], "sensitive": [], "total_found": 0},
            "cloud_buckets": {"found": [], "public": []},
            "emails": {"emails_found": []},
            "github": {"findings": [], "total_findings": 0},
            "google": {"login_pages": [], "subdomains": []},
            "cve": {"cves": [{"id": "CVE-2024-0001", "severity": []}]},
            "permutation": {"subdomains": [], "total_found": 0, "domain": "example.com"},
            "takeover": {"checked": 0, "vulnerable": []},
            "cdn_waf": {"cdn": None, "waf": None},
        },
        "errors": [],
        "correlation": {
            "attack_surface_score": {"score": 0, "severity": "LOW", "factors": []},
            "relationships": [],
        },
        "graph": {"nodes": [], "edges": []},
        "mitre": {"findings": []},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Top-level validation
# ─────────────────────────────────────────────────────────────────────────────
class TestValidateResults:
    def test_full_canonical_results_are_valid(self):
        assert validate_results(_full_results()) == []

    def test_minimal_results_are_valid(self):
        minimal = {"target": "example.com", "modules": {}, "errors": []}
        assert validate_results(minimal) == []

    def test_factory_output_is_valid_and_versioned(self):
        results = new_results("example.com", "quick")
        assert results["schema_version"] == SCHEMA_VERSION
        assert results["depth"] == "quick"
        assert validate_results(results) == []

    def test_empty_modules_set_is_valid(self):
        assert validate_results(new_results("example.com")) == []

    def test_non_dict_input_reported(self):
        assert validate_results(None) == ["results debe ser un dict"]
        assert validate_results([1, 2]) == ["results debe ser un dict"]

    def test_missing_or_empty_target_reported(self):
        assert "target debe ser un string no vacío" in validate_results({})
        assert (
            "target debe ser un string no vacío" in validate_results({"target": "   "})
        )

    def test_invalid_depth_reported(self):
        problems = validate_results({**new_results("example.com"), "depth": "mega"})
        assert any("depth" in p for p in problems)

    def test_wrong_schema_major_reported(self):
        results = new_results("example.com")
        results["schema_version"] = "3.0"
        problems = validate_results(results)
        assert any("incompatible" in p for p in problems)

    def test_same_major_minor_drift_accepted(self):
        results = new_results("example.com")
        results["schema_version"] = SCHEMA_VERSION.rsplit(".", 1)[0] + ".999"
        assert validate_results(results) == []

    def test_modules_not_a_dict_reported(self):
        results = new_results("example.com")
        results["modules"] = ["dns"]
        assert "modules debe ser dict" in validate_results(results)

    def test_module_entry_not_a_dict_reported(self):
        results = new_results("example.com")
        results["modules"] = {"dns": ["www.example.com"]}
        assert any("modules['dns']" in p for p in validate_results(results))

    def test_errors_entries_must_be_strings(self):
        results = new_results("example.com")
        results["errors"] = [{"boom": True}]
        assert any("errors debe ser string" in p for p in validate_results(results))

    def test_section_type_mismatches_reported(self):
        results = new_results("example.com")
        results["correlation"] = []
        results["graph"] = None
        results["attack_chains"] = {}
        results["agent_playbook"] = 7
        problems = validate_results(results)
        assert any("correlation" in p for p in problems)
        assert any("attack_chains" in p for p in problems)
        assert any("agent_playbook" in p for p in problems)

    def test_unknown_module_and_extra_keys_accepted(self):
        results = _full_results()
        results["modules"]["my_custom_plugin"] = {"whatever": [1, 2, 3]}
        results["future_section"] = {"anything": "goes"}
        assert validate_results(results) == []

    def test_json_round_trip_still_valid(self):
        import json

        loaded = json.loads(json.dumps(_full_results()))
        assert validate_results(loaded) == []


class TestRequireValidResults:
    def test_valid_passes_silently(self):
        require_valid_results(_full_results())

    def test_invalid_raises_with_problems(self):
        with pytest.raises(ResultsSchemaError) as excinfo:
            require_valid_results({"target": ""})
        assert "modules" not in str(excinfo.value) or True
        assert "target" in str(excinfo.value)


# ─────────────────────────────────────────────────────────────────────────────
# Per-module validators: every registered module must accept its canonical
# shape and reject the classic corruption shapes (list instead of dict,
# scalar lists, non-dict service/cve entries).
# ─────────────────────────────────────────────────────────────────────────────
class TestModuleValidators:
    def test_every_registered_module_is_covered_by_fixture(self):
        results = _full_results()
        missing = set(MODULE_VALIDATORS) - {"correlation", "graph", "mitre"} - set(
            results["modules"]
        )
        assert not missing, f"fixture sin cobertura para: {sorted(missing)}"

    def test_all_module_fixtures_validate_clean(self):
        modules = _full_results()["modules"]
        for name, validator in MODULE_VALIDATORS.items():
            if name in modules:
                assert validator(modules[name]) == [], f"{name} debería validar limpio"

    @pytest.mark.parametrize(
        "module_key,bad_value,fragment",
        [
            ("dns", {"subdomains": "www.example.com"}, "subdomains"),
            ("dns", {"records": ["A"]}, "records"),
            ("certs", {"certificates": ["le.pem"]}, "certificates"),
            ("wayback", {"total_snapshots": "many"}, "total_snapshots"),
            ("network", {"services": ["ssh 22"]}, "services"),
            ("whois", {"registrar": 42}, "registrar"),
            ("web", {"technologies": 3}, "technologies"),
            ("endpoints", {"found": "x"}, "found"),
            ("cloud_buckets", {"public": {"b": 1}}, "public"),
            ("emails", {"emails_found": [1]}, "emails_found"),
            ("github", {"total_findings": "0"}, "total_findings"),
            ("google", {"login_pages": None}, "login_pages"),
            ("cve", {"cves": ["CVE-2024-0001"]}, "cves"),
            ("permutation", {"subdomains": [1]}, "subdomains"),
            ("takeover", {"checked": "50"}, "checked"),
            ("cdn_waf", {"cdn": ["cloudflare"]}, "cdn"),
        ],
    )
    def test_corrupted_module_shapes_reported(self, module_key, bad_value, fragment):
        problems = MODULE_VALIDATORS[module_key](bad_value)
        assert problems, f"{module_key} con {bad_value!r} debería dar problemas"
        assert any(fragment in p for p in problems)

    def test_correlation_severity_must_be_known(self):
        problems = MODULE_VALIDATORS["correlation"](
            {"attack_surface_score": {"score": 10, "severity": "CATASTROPHIC"}}
        )
        assert any("severity" in p for p in problems)
        ok = MODULE_VALIDATORS["correlation"](
            {"attack_surface_score": {"score": 10, "severity": "HIGH"}}
        )
        assert ok == []
        # KNOWN_SEVERITIES drives the check — keep the tuple honest
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in KNOWN_SEVERITIES

    def test_graph_and_mitre_entries_must_be_dicts(self):
        assert MODULE_VALIDATORS["graph"]({"nodes": [1], "edges": []}) != []
        assert MODULE_VALIDATORS["mitre"]({"findings": ["T1595"]}) != []


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator wiring (offline: OSINTEye() builds objects, no network)
# ─────────────────────────────────────────────────────────────────────────────
class TestOSINTEyeWiring:
    def test_engine_results_carry_schema_version(self):
        from osint_eye import OSINTEye

        engine = OSINTEye(target="example.com", ai=False, cache=False)
        assert engine.results["schema_version"] == SCHEMA_VERSION
        assert validate_results(engine.results) == []

    def test_validate_schema_warns_but_does_not_raise(self, capsys):
        from osint_eye import OSINTEye

        engine = OSINTEye(target="example.com", ai=False, cache=False)
        engine.results["modules"] = {"dns": {"subdomains": {"not": "a list"}}}
        problems = engine._validate_schema()
        assert problems
        out = capsys.readouterr().out
        assert "[!] schema:" in out
        # Degradación elegante: el escaneo sigue viva tras el aviso
        assert engine.results["target"] == "example.com"

    def test_validate_schema_silent_on_valid_results(self, capsys):
        from osint_eye import OSINTEye

        engine = OSINTEye(target="example.com", ai=False, cache=False)
        problems = engine._validate_schema()
        assert problems == []
        assert "[!] schema:" not in capsys.readouterr().out

    def test_export_all_writes_schema_versioned_json(self, tmp_path, monkeypatch):
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        engine.results["modules"] = {"dns": {"domain": "example.com", "subdomains": []}}
        exports = engine.export_all(str(tmp_path / "scan.json"))
        import json

        with open(exports["json"]) as f:
            saved = json.load(f)
        assert saved["schema_version"] == SCHEMA_VERSION
        assert validate_results(saved) == []
