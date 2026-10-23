"""Offline regression tests for H-004 (TEST): escape/injection in targets.

``$'\\x1b\\x1b]0;pwned\\x07evil.com'`` used to reach stdout raw: 5 output
lines carried the literal ESC byte and the OSC sequence could rewrite the
terminal title. Targets and user-supplied paths are now neutralized at the
entry points (CLI -> scan_targets, OSINTEye.__init__) and at the engine
message choke point (_print). Stripping control bytes leaves inert payload
text (e.g. ``]0;pwned``) visible but harmless: no ESC byte, no terminal
effect.
"""
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

from osint_eye import OSINTEye, _neutralize_console_text


HOSTILE_TARGET = "\x1b\x1b]0;pwned\x07evil.com"


class TestNeutralizeConsoleText:
    """Unit coverage of the control-byte stripper."""

    def test_strips_esc_and_osc_sequences(self):
        assert _neutralize_console_text(HOSTILE_TARGET) == "]0;pwnedevil.com"

    def test_strips_c0_controls_and_del(self):
        text = "a\x00b\x07c\x08d\x1be\x1f\x7ff"
        assert _neutralize_console_text(text) == "abcdef"

    def test_strips_ansi_color_sequence(self):
        assert _neutralize_console_text("\x1b[31mred\x1b[0m") == "[31mred[0m"

    def test_keeps_printable_and_unicode(self):
        text = "acme.com ñ 中文 123 !@#"
        assert _neutralize_console_text(text) == text

    def test_keeps_spaces_and_tabs_free_text(self):
        # tabs are control bytes too: stripped, like every C0 escape
        assert _neutralize_console_text("a\tb") == "ab"

    def test_accepts_non_string_input(self):
        assert _neutralize_console_text(123) == "123"
        assert _neutralize_console_text(None) == "None"


class TestEngineEntryPoints:
    """OSINTEye and _print never emit control bytes."""

    def test_engine_target_is_neutralized(self):
        engine = OSINTEye(target=HOSTILE_TARGET, ai=False, cache=False)
        assert engine.target == "]0;pwnedevil.com"

    def test_results_target_is_neutralized(self):
        engine = OSINTEye(target=HOSTILE_TARGET, ai=False, cache=False)
        assert engine.results["target"] == "]0;pwnedevil.com"
        assert "\x1b" not in str(engine.results)

    def test_print_neutralizes_message(self, capsys):
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        engine._print(f"Scanning {HOSTILE_TARGET}")
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "\x07" not in out
        assert "[*] Scanning ]0;pwnedevil.com" in out

    def test_print_keeps_normal_messages(self, capsys):
        engine = OSINTEye(target="example.com", ai=False, cache=False)
        engine._print("Scanning example.com (phase 1/3)")
        assert "[*] Scanning example.com (phase 1/3)" in capsys.readouterr().out


class TestCliHandoff:
    """main()/scan_targets() neutralize before anything renders or runs."""

    def test_scan_targets_neutralizes_before_engine(self, monkeypatch, capsys):
        import osint_eye

        fake_engine = MagicMock()
        fake_cls = MagicMock(return_value=fake_engine)
        monkeypatch.setattr(osint_eye, "OSINTEye", fake_cls)
        args = SimpleNamespace(
            monitor=False,
            scope_obj=None,
            depth="quick",
            stealth=False,
            no_ai=True,
            no_cache=True,
            modules=["dns"],
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
        osint_eye.scan_targets([HOSTILE_TARGET], args)
        assert fake_cls.call_args.args[0] == "]0;pwnedevil.com"
        # the Rich scan header printed for the target is also clean
        assert "\x1b" not in capsys.readouterr().out

    def test_output_path_arg_is_neutralized_and_stored(self, tmp_path, monkeypatch):
        import osint_eye

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "osint_eye.py",
                "example.com",
                "--no-ai",
                "--no-cache",
                "--modules",
                "dns",
                "-o",
                "out/\x1breport",
            ],
        )
        captured = {}
        monkeypatch.setattr(
            osint_eye,
            "scan_targets",
            lambda targets, args: captured.setdefault("output", args.output) or {},
        )
        osint_eye.main()
        assert captured["output"] == "out/report"
        assert "\x1b" not in captured["output"]
