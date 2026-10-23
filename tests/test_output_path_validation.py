"""Offline regression tests for H-003 (TEST): output path traversal.

``-o ../../foo`` used to write two levels above the repo. Every
user-supplied output path (--output, --export-cypher, --log-file) must
resolve inside the current working directory or fail as a clean usage
error (exit 2) before any side effect happens.
"""
import sys
from pathlib import Path

import pytest

from osint_eye import OutputPathError, _validate_output_path


class TestValidateOutputPath:
    """Unit coverage of the CWD jail."""

    def test_relative_inside_cwd_passes_unchanged(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _validate_output_path("out/report") == "out/report"

    def test_plain_filename_passes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert _validate_output_path("report_2026") == "report_2026"

    def test_absolute_inside_cwd_passes(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        inside = str(tmp_path / "out.json")
        assert _validate_output_path(inside) == inside

    def test_cwd_itself_passes(self, tmp_path, monkeypatch):
        # "-o ." resolves to the CWD; harmless, files land inside it.
        monkeypatch.chdir(tmp_path)
        assert _validate_output_path(".") == "."

    def test_parent_traversal_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(OutputPathError):
            _validate_output_path("../../oe_escape_test")

    def test_single_parent_traversal_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(OutputPathError):
            _validate_output_path("../escape")

    def test_absolute_outside_cwd_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(OutputPathError):
            _validate_output_path(str(tmp_path.parent / "elsewhere"))

    def test_home_expansion_rejected_when_outside(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(OutputPathError):
            _validate_output_path("~/osint_eye_report")

    def test_error_message_names_flag_and_paths(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(OutputPathError) as excinfo:
            _validate_output_path("../../escape", flag="--output")
        message = str(excinfo.value)
        assert "--output" in message
        assert "escape" in message
        assert str(Path.cwd()) in message


class TestCliRefusesEscapingPaths:
    """main() must exit 2 BEFORE any scan/export/log side effect."""

    def _run_main(self, monkeypatch, argv, tmp_path):
        import osint_eye

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["osint_eye.py", *argv])
        scanned = []
        monkeypatch.setattr(
            osint_eye, "scan_targets", lambda *a, **k: scanned.append(a) or {}
        )
        # main() returns the exit code on the happy path and only raises
        # SystemExit via parser.error()/sys.exit() on error paths.
        try:
            code = osint_eye.main()
        except SystemExit as exc:
            code = exc.code
        return code, scanned

    def test_output_traversal_exits_2_before_scan(self, tmp_path, monkeypatch):
        code, scanned = self._run_main(
            monkeypatch,
            [
                "example.com",
                "--depth",
                "quick",
                "--no-ai",
                "--no-cache",
                "--modules",
                "dns",
                "-o",
                "../../oe_escape_test",
            ],
            tmp_path,
        )
        assert code == 2
        assert scanned == []  # the scan never started
        # nothing was written outside the CWD (the H-003 symptom)
        assert not (tmp_path.parent / "oe_escape_test.json").exists()

    def test_export_cypher_traversal_exits_2(self, tmp_path, monkeypatch):
        code, scanned = self._run_main(
            monkeypatch,
            ["example.com", "--modules", "dns", "--export-cypher", "../../evil"],
            tmp_path,
        )
        assert code == 2
        assert scanned == []
        assert not (tmp_path.parent / "evil.cypher").exists()

    def test_log_file_traversal_exits_2(self, tmp_path, monkeypatch):
        code, scanned = self._run_main(
            monkeypatch,
            ["example.com", "--modules", "dns", "--log-file", "../../evil.log"],
            tmp_path,
        )
        assert code == 2
        assert scanned == []
        # validation runs before setup_logging: no stray log file anywhere
        assert not (tmp_path.parent / "evil.log").exists()

    def test_valid_relative_output_reaches_scan(self, tmp_path, monkeypatch):
        code, scanned = self._run_main(
            monkeypatch,
            [
                "example.com",
                "--no-ai",
                "--no-cache",
                "--modules",
                "dns",
                "-o",
                "out/ok_base",
            ],
            tmp_path,
        )
        assert len(scanned) == 1  # validation must not block legit paths
        assert code == 3  # EXIT_NOTHING_SCANNED: stubbed scan returns {}


class TestExportAllGuard:
    """export_all() enforces the same jail for non-CLI callers."""

    def test_export_all_refuses_escaping_base(self, tmp_path, monkeypatch):
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        with pytest.raises(OutputPathError):
            engine.export_all(str(tmp_path.parent / "outside_base"))
        assert not (tmp_path.parent / "outside_base.json").exists()

    def test_export_all_accepts_base_inside_cwd(self, tmp_path, monkeypatch):
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        engine.results = {
            "target": engine.target,
            "scan_date": "2024-01-01T00:00:00",
            "depth": "quick",
            "modules": {},
            "errors": [],
        }
        exports = engine.export_all("inside/report", formats=["json"])
        assert Path(exports["json"]).exists()
