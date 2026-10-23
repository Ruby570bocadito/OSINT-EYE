"""Offline regression tests for H-008 (TEST): duplicate PDF with -o.

``-o base --pdf`` used to render two PDFs: ``base.pdf`` (via export_all)
plus a default-named ``osint_eye_<target>_<ts>.pdf`` dropped in the CWD
by the --pdf branch. The branch now stays out of the way when export_all
will render the PDF, and derives the path from the -o base otherwise.
"""
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
        pdf=True,
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


def generate_calls(eng):
    return [
        c.args[1]
        for c in eng.pdf_reporter.generate.call_args_list
    ]


class TestPdfDedupe:
    def test_output_with_default_formats_skips_branch_render(self, monkeypatch, tmp_path):
        """-o + --pdf with all formats: export_all renders base.pdf; the
        --pdf branch must not generate anything (no CWD duplicate)."""
        monkeypatch.chdir(tmp_path)
        eng = _engine("example.com")
        monkeypatch.setattr(osint_eye, "OSINTEye", MagicMock(side_effect=[eng]))

        scan_targets(["example.com"], _args(output="out/scan"))

        assert generate_calls(eng) == []
        assert not list(tmp_path.glob("osint_eye_*.pdf"))

    def test_output_with_pdf_excluded_renders_base_pdf(self, monkeypatch, tmp_path):
        """-o + --pdf but 'pdf' excluded from --export-formats: the branch
        renders the -o derived path, never the default name."""
        monkeypatch.chdir(tmp_path)
        eng = _engine("example.com")
        monkeypatch.setattr(osint_eye, "OSINTEye", MagicMock(side_effect=[eng]))

        scan_targets(
            ["example.com"], _args(output="out/scan", export_formats=["json"])
        )

        assert generate_calls(eng) == ["out/scan.pdf"]

    def test_output_ending_in_pdf_is_not_doubled(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        eng = _engine("example.com")
        monkeypatch.setattr(osint_eye, "OSINTEye", MagicMock(side_effect=[eng]))

        scan_targets(
            ["example.com"],
            _args(output="out/report.pdf", export_formats=["json"]),
        )

        assert generate_calls(eng) == ["out/report.pdf"]

    def test_multitarget_derives_suffixed_base(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        eng = _engine("a.example.com")
        eng_b = _engine("b.example.com")
        monkeypatch.setattr(
            osint_eye, "OSINTEye", MagicMock(side_effect=[eng, eng_b])
        )

        scan_targets(
            ["a.example.com", "b.example.com"],
            _args(output="out/scan", export_formats=["json"]),
        )

        assert generate_calls(eng) == ["out/scan_a.example.com.pdf"]
        assert generate_calls(eng_b) == ["out/scan_b.example.com.pdf"]

    def test_without_output_keeps_default_name(self, monkeypatch, tmp_path):
        """No -o: the default-named CWD PDF keeps working (unchanged)."""
        monkeypatch.chdir(tmp_path)
        eng = _engine("example.com")
        monkeypatch.setattr(osint_eye, "OSINTEye", MagicMock(side_effect=[eng]))

        scan_targets(["example.com"], _args())

        calls = generate_calls(eng)
        assert len(calls) == 1
        assert calls[0].startswith("osint_eye_example.com_")
        assert calls[0].endswith(".pdf")
