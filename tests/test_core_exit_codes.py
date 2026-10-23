"""Tests for CI exit codes (--fail-on) — 100% offline.

Covers: severity ranking across targets, decide_exit_code semantics
(0/1/3, monitor passthrough), argparse choices, and the real CLI contract
via subprocess (out-of-scope run exits 3 without touching the network).
"""

import argparse
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from osint_eye import (  # noqa: E402
    EXIT_FAIL_ON,
    EXIT_NOTHING_SCANNED,
    EXIT_OK,
    FAIL_ON_CHOICES,
    SEVERITY_RANK,
    decide_exit_code,
    max_severity,
)


def _results(severity=None) -> dict:
    if severity is None:
        return {"example.com": {"target": "example.com", "modules": {}}}
    return {
        "example.com": {
            "target": "example.com",
            "modules": {},
            "correlation": {
                "attack_surface_score": {"score": 50, "severity": severity}
            },
        }
    }


def _args(fail_on=None, monitor=False) -> argparse.Namespace:
    return argparse.Namespace(fail_on=fail_on, monitor=monitor)


class TestMaxSeverity:
    def test_picks_worst_across_targets(self):
        def _with_target(target, severity):
            result = _results(severity)["example.com"]
            result["target"] = target
            return result

        results = {
            "a.com": _with_target("a.com", "MEDIUM"),
            "b.com": _with_target("b.com", "HIGH"),
            "c.com": _with_target("c.com", "LOW"),
        }
        assert max_severity(results) == "HIGH"

    def test_no_correlation_counts_as_low(self):
        assert max_severity({"a.com": {"target": "a.com", "modules": {}}}) == "LOW"

    @pytest.mark.parametrize(
        "payload",
        [None, [], {"a.com": None}, {"a.com": 42}, {"a.com": {"correlation": []}}],
    )
    def test_malformed_shapes_tolerated(self, payload):
        assert max_severity(payload) == "LOW"

    def test_unknown_severity_strings_ignored(self):
        results = _results("CATASTROPHIC")
        assert max_severity(results) == "LOW"

    def test_rank_table_is_ordered(self):
        assert SEVERITY_RANK["LOW"] < SEVERITY_RANK["MEDIUM"]
        assert SEVERITY_RANK["MEDIUM"] < SEVERITY_RANK["HIGH"]
        assert SEVERITY_RANK["HIGH"] < SEVERITY_RANK["CRITICAL"]


class TestDecideExitCode:
    @pytest.mark.parametrize(
        "severity,fail_on,expected",
        [
            ("HIGH", "high", EXIT_FAIL_ON),
            ("CRITICAL", "high", EXIT_FAIL_ON),
            ("MEDIUM", "high", EXIT_OK),
            ("MEDIUM", "medium", EXIT_FAIL_ON),
            ("LOW", "medium", EXIT_OK),
            ("LOW", "low", EXIT_FAIL_ON),
            ("CRITICAL", "medium", EXIT_FAIL_ON),
        ],
    )
    def test_threshold_semantics(self, severity, fail_on, expected):
        assert decide_exit_code(_results(severity), _args(fail_on)) == expected

    def test_without_fail_on_always_ok(self):
        assert decide_exit_code(_results("CRITICAL"), _args(None)) == EXIT_OK

    def test_nothing_scanned_exits_3(self):
        assert decide_exit_code({}, _args("high")) == EXIT_NOTHING_SCANNED
        assert decide_exit_code({}, _args(None)) == EXIT_NOTHING_SCANNED

    def test_monitor_mode_passes_through(self):
        assert decide_exit_code({}, _args("high", monitor=True)) == EXIT_OK
        assert decide_exit_code(_results("CRITICAL"), _args("low", monitor=True)) == EXIT_OK

    def test_choices_are_lowercase(self):
        assert FAIL_ON_CHOICES == ("low", "medium", "high")


class TestCLIExitCodes:
    def _run_cli(self, *cli_args):
        import subprocess

        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "..")
        return subprocess.run(
            [sys.executable, "osint_eye.py", *cli_args],
            capture_output=True,
            text=True,
            env=env,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
            timeout=60,
        )

    def test_help_documents_exit_codes(self):
        result = self._run_cli("--help")
        assert result.returncode == 0
        assert "--fail-on" in result.stdout
        assert "Exit codes" in result.stdout

    def test_invalid_threshold_is_usage_error(self):
        result = self._run_cli("example.com", "--fail-on", "bogus")
        assert result.returncode == 2

    def test_all_targets_out_of_scope_exits_3(self, tmp_path):
        scope = tmp_path / "scope.txt"
        scope.write_text("example.com\n", encoding="utf-8")
        result = self._run_cli("evil.net", "--scope", str(scope), "--fail-on", "high")
        assert result.returncode == 3
        assert "no target scanned" in (result.stdout + result.stderr)
