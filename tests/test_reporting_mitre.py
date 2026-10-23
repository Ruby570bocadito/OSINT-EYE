"""Offline tests for the MITRE ATT&CK mapper (reporting/mitre_mapper.py).

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
import json

from tests.conftest import FULL_RESULTS


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


class TestMitreMapperGuards:
    def test_map_findings_none_does_not_crash(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        assert mapper.map_findings(None) == []
        assert mapper.map_findings("garbage") == []
        assert mapper.map_findings({"modules": None}) == []


class TestMitreWebNoneModule:
    def test_map_findings_with_null_web_module(self):
        from reporting.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        findings = mapper.map_findings({"modules": {"web": None}})
        assert isinstance(findings, list)
