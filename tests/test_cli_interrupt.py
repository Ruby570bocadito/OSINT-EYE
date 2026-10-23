"""Offline regression tests for H-007 (TEST): Ctrl+C mid-scan.

A KeyboardInterrupt during the target loop used to escape as a raw
traceback (e.g. inside ``sock.connect``). ``scan_targets`` now folds the
collected results (completed targets plus the in-flight one) into
``ScanInterrupted`` and ``main()`` reports cleanly with exit code 130
(POSIX 128+SIGINT).
"""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import osint_eye
from osint_eye import EXIT_INTERRUPTED, ScanInterrupted, scan_targets


def _args(**overrides):
    base = dict(
        monitor=False,
        scope_obj=None,
        depth="quick",
        stealth=False,
        no_ai=True,
        no_cache=True,
        modules=[],
        rich=False,
        pdf=False,
        output=None,
        export_cypher=None,
        dashboard=False,
        diff=False,
        export_formats=None,
        agent=False,
        fail_on=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _engine(target, crash=False):
    eng = MagicMock()
    eng.results = {"target": target, "modules": {}, "errors": []}
    if crash:
        eng.run_all.side_effect = KeyboardInterrupt()
    return eng


class TestScanInterruptedContract:
    def test_exception_carries_partials(self):
        exc = ScanInterrupted({"example.com": {"target": "example.com"}})
        assert exc.partial_results == {"example.com": {"target": "example.com"}}

    def test_exception_defaults_to_empty(self):
        assert ScanInterrupted(None).partial_results == {}


class TestScanTargetsInterrupt:
    """The loop converts KeyboardInterrupt into ScanInterrupted + partials."""

    def _run(self, monkeypatch, engines):
        created = []

        def _fake(cls_target, *a, **k):
            created.append(cls_target)
            return engines[len(created) - 1]

        monkeypatch.setattr(
            osint_eye, "OSINTEye", MagicMock(side_effect=_fake)
        )
        with pytest.raises(ScanInterrupted) as excinfo:
            scan_targets(["t1.example.com", "t2.example.com"], _args())
        return excinfo.value, {"created": created}

    def test_completed_plus_inflight_are_kept(self, monkeypatch):
        eng1 = _engine("t1.example.com")
        eng2 = _engine("t2.example.com", crash=True)
        exc, captured = self._run(monkeypatch, [eng1, eng2])

        assert set(exc.partial_results) == {"t1.example.com", "t2.example.com"}
        assert exc.partial_results["t1.example.com"]["target"] == "t1.example.com"
        assert exc.partial_results["t2.example.com"]["target"] == "t2.example.com"

    def test_interrupt_before_engine_does_not_misattribute(self, monkeypatch):
        eng1 = _engine("t1.example.com")
        # t2 dies before OSINTEye() returns: engine must stay None so t1's
        # results are never stored under t2's name
        boom = MagicMock(
            side_effect=[eng1, KeyboardInterrupt()]
        )
        monkeypatch.setattr(osint_eye, "OSINTEye", boom)

        with pytest.raises(ScanInterrupted) as excinfo:
            scan_targets(["t1.example.com", "t2.example.com"], _args())

        assert set(excinfo.value.partial_results) == {"t1.example.com"}

    def test_first_target_interrupt_still_reports(self, monkeypatch):
        eng1 = _engine("t1.example.com", crash=True)
        monkeypatch.setattr(osint_eye, "OSINTEye", MagicMock(side_effect=[eng1]))

        with pytest.raises(ScanInterrupted) as excinfo:
            scan_targets(["t1.example.com"], _args())

        assert excinfo.value.partial_results == {
            "t1.example.com": {"target": "t1.example.com", "modules": {}, "errors": []}
        }

    def test_clean_run_is_unaffected(self, monkeypatch):
        eng1 = _engine("t1.example.com")
        eng2 = _engine("t2.example.com")
        monkeypatch.setattr(
            osint_eye, "OSINTEye", MagicMock(side_effect=[eng1, eng2])
        )
        result = scan_targets(["t1.example.com", "t2.example.com"], _args())
        assert set(result) == {"t1.example.com", "t2.example.com"}


class TestMainExitCode:
    def test_main_returns_130_on_interrupt(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            ["osint_eye.py", "example.com", "--no-ai", "--no-cache", "--modules", "dns"],
        )
        monkeypatch.setattr(
            osint_eye,
            "scan_targets",
            lambda targets, args: (_ for _ in ()).throw(
                ScanInterrupted({"example.com": {"target": "example.com"}})
            ),
        )
        code = osint_eye.main()
        assert code == EXIT_INTERRUPTED == 130
        out = capsys.readouterr().out
        assert "interrupted by user" in out
        assert "example.com" in out
        assert "130" in out

    def test_main_normal_path_still_uses_decide_exit_code(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            ["osint_eye.py", "example.com", "--no-ai", "--no-cache", "--modules", "dns"],
        )
        monkeypatch.setattr(
            osint_eye, "scan_targets", lambda targets, args: {"example.com": {}}
        )
        # non-empty partials without --fail-on -> EXIT_OK via decide_exit_code
        assert osint_eye.main() == 0
