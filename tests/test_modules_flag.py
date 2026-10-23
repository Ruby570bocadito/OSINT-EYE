"""Offline regression tests for H-010 (TEST): commas in --modules.

``--modules dns,web`` used to die with a ~40-line argparse usage dump
(the choices error listing every module). The flag now splits commas per
token (both ``dns web`` and ``dns,web`` work), dedupes, and unknown names
get a short actionable error instead of the wall of text.
"""
import sys
from types import SimpleNamespace

import pytest

import osint_eye
from osint_eye import _split_modules_token


def _run_main(monkeypatch, argv, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["osint_eye.py", *argv])
    captured = {}

    def _fake_scan(targets, args):
        captured["args"] = args
        return {}

    monkeypatch.setattr(osint_eye, "scan_targets", _fake_scan)
    try:
        code = osint_eye.main()
    except SystemExit as exc:
        code = exc.code
    return code, captured


class TestSplitModulesToken:
    def test_single_module(self):
        assert _split_modules_token("dns") == ["dns"]

    def test_comma_list(self):
        assert _split_modules_token("dns,web") == ["dns", "web"]

    def test_spaces_around_commas(self):
        assert _split_modules_token("dns, web ,") == ["dns", "web"]

    def test_only_commas_yields_empty(self):
        assert _split_modules_token(",") == []


class TestCliModulesFlag:
    def test_comma_form_reaches_scan(self, tmp_path, monkeypatch):
        code, captured = _run_main(
            monkeypatch,
            ["example.com", "--no-ai", "--no-cache", "--modules", "dns,web"],
            tmp_path,
        )
        assert code == 3  # EXIT_NOTHING_SCANNED (stubbed scan)
        assert captured["args"].modules == ["dns", "web"]

    def test_space_form_still_works(self, tmp_path, monkeypatch):
        code, captured = _run_main(
            monkeypatch,
            ["example.com", "--no-ai", "--no-cache", "--modules", "dns", "web"],
            tmp_path,
        )
        assert code == 3
        assert captured["args"].modules == ["dns", "web"]

    def test_mixed_and_duplicated_tokens(self, tmp_path, monkeypatch):
        code, captured = _run_main(
            monkeypatch,
            [
                "example.com",
                "--no-ai",
                "--no-cache",
                "--modules",
                "dns,web",
                "web",
                "dns ,mitre",
            ],
            tmp_path,
        )
        assert code == 3
        assert captured["args"].modules == ["dns", "web", "mitre"]

    def test_unknown_module_short_error(self, tmp_path, monkeypatch, capsys):
        code, _ = _run_main(
            monkeypatch,
            ["example.com", "--no-ai", "--no-cache", "--modules", "dns,bogus"],
            tmp_path,
        )
        assert code == 2
        err = capsys.readouterr().err
        assert "unknown module(s): bogus" in err
        assert "--modules dns,web" in err  # actionable hint
        # no wall of text: the usage dump must stay short
        assert err.count("usage:") == 1
        assert len(err) < 1500

    def test_no_values_still_prints_catalog(self, tmp_path, monkeypatch, capsys):
        code, _ = _run_main(
            monkeypatch, ["--no-ai", "--no-cache", "--modules"], tmp_path
        )
        assert code == 0
        out = capsys.readouterr().out
        assert "dns" in out  # catalog listing
