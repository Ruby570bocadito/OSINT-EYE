"""Offline regression tests for H-001 (TEST): no persistence without -o.

The README quickstart (`python osint_eye.py example.com --depth quick`)
left the user with no reusable file: results only lived inside the SQLite
cache. scan_targets now auto-saves a default JSON (same CWD convention as
the default PDF) and tells the operator where things live; --dashboard
reuses that file instead of writing a duplicate.
"""
import json
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import osint_eye
from osint_eye import scan_targets


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


def _engine(target):
    eng = MagicMock()
    eng.results = {"target": target, "modules": {}, "errors": []}
    eng.export_all.return_value = {"json": "out/scan.json"}
    return eng


def _run_scan(monkeypatch, tmp_path, args, target="example.com"):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        osint_eye, "OSINTEye", MagicMock(side_effect=[_engine(target)])
    )
    return scan_targets([target], args)


class TestDefaultPersistence:
    def test_autosaves_default_json_without_output(self, tmp_path, monkeypatch, capsys):
        result = _run_scan(monkeypatch, tmp_path, _args())

        saved = list(tmp_path.glob("osint_eye_example.com_*.json"))
        assert len(saved) == 1, "the quickstart must leave a usable file"
        data = json.loads(saved[0].read_text())
        assert data["target"] == "example.com"
        assert data == result["example.com"]

        out = capsys.readouterr().out
        assert "Results saved to" in out
        assert "-o" in out  # pointer to richer exports

    def test_cache_hint_reflects_use_cache(self, tmp_path, monkeypatch, capsys):
        engine = _engine("example.com")
        engine.use_cache = False
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(osint_eye, "OSINTEye", MagicMock(side_effect=[engine]))
        scan_targets(["example.com"], _args())
        assert "cache disabled" in capsys.readouterr().out

    def test_no_autosave_when_output_given(self, tmp_path, monkeypatch, capsys):
        _run_scan(monkeypatch, tmp_path, _args(output="out/scan"))

        assert not list(tmp_path.glob("osint_eye_*.json"))
        assert "Results saved to" not in capsys.readouterr().out

    def test_multitarget_gets_one_file_per_target(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            osint_eye,
            "OSINTEye",
            MagicMock(side_effect=[_engine("a.example.com"), _engine("b.example.com")]),
        )
        scan_targets(["a.example.com", "b.example.com"], _args())

        names = sorted(p.name for p in tmp_path.glob("osint_eye_*.json"))
        assert len(names) == 2
        assert any("_a.example.com_" in n for n in names)
        assert any("_b.example.com_" in n for n in names)

    def test_oserror_degrades_to_warning(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            osint_eye, "OSINTEye", MagicMock(side_effect=[_engine("example.com")])
        )

        def _boom(*a, **k):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(osint_eye.json, "dump", _boom)
        result = scan_targets(["example.com"], _args())

        out = capsys.readouterr().out
        assert "Could not auto-save" in out
        assert result["example.com"]["target"] == "example.com"  # scan survives
