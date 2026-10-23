"""Offline tests for the CLI engine (osint_eye.py): filename hygiene, export
contract, executor/phase guards.

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
import json
from pathlib import Path
from unittest.mock import patch


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


class TestPdfOutputName:
    def test_filename_is_sanitized_for_url_targets(self):
        from osint_eye import _pdf_output_name

        name = _pdf_output_name("https://acme.com:8443/x")
        assert name.endswith(".pdf")
        assert "/" not in name
        assert ":" not in name
        assert name.startswith("osint_eye_")
