"""Tests for lazy heavy imports (PUL-1 packaging request) — offline.

`import osint_eye` / `import reporting` must not pull reportlab (the
[pdf] extra) until a PDF is actually generated. Verified via subprocess
so the check is independent of what other tests already imported.
"""

import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _run_snippet(code: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=60,
    )


class TestLazyReportlab:
    def test_import_osint_eye_does_not_load_reportlab(self):
        result = _run_snippet(
            "import osint_eye, sys; "
            "assert 'reportlab' not in sys.modules, 'reportlab cargado'; print('ok')"
        )
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout

    def test_import_reporting_does_not_load_reportlab(self):
        result = _run_snippet(
            "import reporting, sys; "
            "assert 'reportlab' not in sys.modules, 'reportlab cargado'; print('ok')"
        )
        assert result.returncode == 0, result.stderr

    def test_from_reporting_import_pdfreporter_still_works(self):
        result = _run_snippet(
            "from reporting import PDFReporter; print(PDFReporter.__name__)"
        )
        assert result.returncode == 0, result.stderr
        assert "PDFReporter" in result.stdout

    def test_engine_pdf_export_still_works(self, tmp_path, monkeypatch):
        # Functional: the deferred property produces a real PDF.
        from osint_eye import OSINTEye

        monkeypatch.chdir(tmp_path)
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        path = engine.pdf_reporter.generate(engine.results, str(tmp_path / "r.pdf"))
        with open(path, "rb") as handle:
            assert handle.read(5) == b"%PDF-"

    def test_unknown_reporting_attribute_still_raises(self):
        result = _run_snippet(
            "import reporting\n"
            "try:\n"
            "    reporting.Nonsense\n"
            "except AttributeError:\n"
            "    print('ok')\n"
        )
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout
