"""Tests for library logging (core/logging_config.py + conversions) — offline.

Verifies: setup_logging (levels, file handler, idempotency), parse_level,
and that core/graph/reporting modules emit through the ``osint_eye`` logger
tree instead of print().
"""

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.logging_config import (  # noqa: E402
    ROOT_LOGGER,
    LEVEL_NAMES,
    get_logger,
    parse_level,
    setup_logging,
)


MINIMAL_RESULTS = {
    "target": "example.com",
    "scan_date": "2026-10-23T12:00:00",
    "depth": "normal",
    "modules": {},
    "errors": [],
}


@pytest.fixture(autouse=True)
def _clean_logging():
    """Leave the global logger untouched after each test."""
    yield
    root = logging.getLogger(ROOT_LOGGER)
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    root.setLevel(logging.NOTSET)


class TestParseLevel:
    @pytest.mark.parametrize("name", LEVEL_NAMES)
    def test_every_level_name_round_trips(self, name):
        assert parse_level(name) == getattr(logging, name)

    def test_case_and_whitespace_tolerated(self):
        assert parse_level("  info ") == logging.INFO
        assert parse_level("Debug") == logging.DEBUG

    def test_unknown_level_rejected(self):
        with pytest.raises(ValueError):
            parse_level("LOUD")
        with pytest.raises(ValueError):
            parse_level("")



class TestSetupLogging:
    def test_console_handler_installed_at_level(self):
        root = setup_logging("WARNING")
        assert root is logging.getLogger(ROOT_LOGGER)
        assert root.level == logging.WARNING
        handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
        assert handlers, "falta console handler"

    def test_file_handler_appends_utf8(self, tmp_path):
        log_file = tmp_path / "logs" / "osint.log"
        setup_logging("DEBUG", log_file=str(log_file))
        get_logger("core.monitor").info("mensaje-de-prueba")
        for handler in logging.getLogger(ROOT_LOGGER).handlers:
            handler.flush()
        content = log_file.read_text(encoding="utf-8")
        assert "mensaje-de-prueba" in content
        assert "core.monitor" in content
        assert log_file.parent.name == "logs"  # parent dirs created

    def test_level_filters_records(self, tmp_path):
        log_file = tmp_path / "osint.log"
        setup_logging("WARNING", log_file=str(log_file))
        get_logger("reporting.export").info("esto-no-debe-salir")
        get_logger("reporting.export").warning("esto-si")
        for handler in logging.getLogger(ROOT_LOGGER).handlers:
            handler.flush()
        content = log_file.read_text(encoding="utf-8")
        assert "esto-no-debe-salir" not in content
        assert "esto-si" in content

    def test_idempotent_no_duplicate_handlers(self, tmp_path):
        log_file = tmp_path / "osint.log"
        setup_logging("INFO", log_file=str(log_file))
        setup_logging("DEBUG", log_file=str(log_file))
        root = logging.getLogger(ROOT_LOGGER)
        assert len(root.handlers) == 2  # console + file, not 4

    def test_invalid_level_raises_value_error(self, tmp_path):
        with pytest.raises(ValueError):
            setup_logging("CHATTY", log_file=str(tmp_path / "x.log"))


class TestLibraryModulesLog:
    def test_html_reporter_logs_not_prints(self, tmp_path, caplog):
        from reporting.export import HTMLReporter

        target = tmp_path / "report.html"
        with caplog.at_level(logging.INFO, logger="osint_eye.reporting.export"):
            HTMLReporter().generate(MINIMAL_RESULTS, str(target))
        html_records = [r for r in caplog.records if "HTML report saved" in r.message]
        assert html_records
        assert all(r.name == "osint_eye.reporting.export" for r in html_records)

    def test_markdown_reporter_logs(self, tmp_path, caplog):
        from reporting.markdown_reporter import MarkdownReporter

        target = tmp_path / "report.md"
        reporter = MarkdownReporter()
        reporter.load_results(MINIMAL_RESULTS)
        with caplog.at_level(logging.INFO, logger="osint_eye.reporting.markdown_reporter"):
            reporter.generate(str(target))
        assert any("Report saved" in r.message for r in caplog.records)

    def test_burp_exporter_logs(self, tmp_path, caplog):
        from reporting.export_tools import BurpExporter

        target = tmp_path / "burp.xml"
        with caplog.at_level(logging.INFO, logger="osint_eye.reporting.export_tools"):
            BurpExporter().export(MINIMAL_RESULTS, str(target))
        assert any("Burp XML saved" in r.message for r in caplog.records)

    def test_graph_builder_logs(self, tmp_path, caplog):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.ingest_all(MINIMAL_RESULTS)
        target = tmp_path / "graph.html"
        with caplog.at_level(logging.INFO, logger="osint_eye.graph.builder"):
            builder.export_html(str(target))
        assert any("Graph exported" in r.message for r in caplog.records)

    def test_alert_manager_failure_logged_not_printed(self, caplog):
        from core.monitor import AlertManager

        def broken_handler(alert_type, message, severity, data):
            raise RuntimeError("canal roto")

        manager = AlertManager()
        manager.add_handler(broken_handler)
        with caplog.at_level(logging.ERROR, logger="osint_eye.core.monitor"):
            manager.send("new_subdomain", "algo", severity="high")
        assert any(
            "Alert handler" in r.message and "canal roto" in r.message
            for r in caplog.records
        )

    def test_log_handler_emits_through_logger(self, caplog):
        from core.monitor import AlertManager

        with caplog.at_level(logging.INFO, logger="osint_eye.core.monitor"):
            AlertManager.log_handler("new_subdomain", "sub.example.com", "high", {})
        record = next(r for r in caplog.records if "ALERT" in r.message)
        assert record.levelno == logging.INFO
        assert record.name == "osint_eye.core.monitor"


class TestCLIWiring:
    """Real CLI contract, exercised via subprocess (fails before any network)."""

    def _run_cli(self, *cli_args, cwd=None):
        import subprocess

        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        env = dict(os.environ)
        env["PYTHONPATH"] = root
        return subprocess.run(
            [sys.executable, os.path.join(root, "osint_eye.py"), *cli_args],
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd or root,
            timeout=60,
        )

    def test_invalid_log_level_is_usage_error(self):
        result = self._run_cli("example.com", "--log-level", "BOGUS")
        assert result.returncode == 2
        assert "log level" in (result.stderr + result.stdout).lower()

    @pytest.mark.parametrize("level", LEVEL_NAMES)
    def test_valid_log_levels_accepted(self, level):
        # --modules sin valores imprime el catálogo y sale 0: pasa por
        # setup_logging antes de cualquier salida, sin tocar la red.
        result = self._run_cli("--log-level", level, "--modules")
        assert result.returncode == 0, result.stderr

    def test_log_file_created_by_cli_run(self, tmp_path):
        # cwd=tmp_path: the H-003 output-path guard requires --log-file to
        # resolve inside the CWD of the CLI invocation.
        log_file = tmp_path / "cli-run.log"
        result = self._run_cli("--log-file", str(log_file), "--modules", cwd=tmp_path)
        assert result.returncode == 0, result.stderr
        assert log_file.exists()
