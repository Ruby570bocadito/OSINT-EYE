"""Offline regression tests for H-002 (TEST): CLI target validation.

Dirty targets used to reach the engines untouched: ``HTTPS://Example.COM``
was stored verbatim in the JSON, ``example.com/path?x=1`` made the DNS
module query garbage, and ``not_a_domain!!`` produced silent empty
results. The CLI now normalizes what is explainable and rejects the rest
with an actionable usage error, using the wizard's host rules.
"""
import sys

import pytest

import osint_eye
from osint_eye import _normalize_cli_target


class TestNormalizeCliTarget:
    def test_url_case_and_path_are_normalized(self):
        assert _normalize_cli_target("HTTPS://Example.COM") == ("https://example.com", None)
        assert _normalize_cli_target("https://example.com/ruta") == ("https://example.com", None)

    def test_whitespace_and_trailing_dot(self):
        assert _normalize_cli_target("example.com ") == ("example.com", None)
        assert _normalize_cli_target("example.com.") == ("example.com", None)
        assert _normalize_cli_target("  Example.COM/  ") == ("example.com", None)

    def test_schemeless_path_keeps_host(self):
        assert _normalize_cli_target("example.com/path?x=1") == ("example.com", None)

    def test_loopback_url_with_port_is_preserved(self):
        """The e2e/web-module contract: scheme and port must survive."""
        assert _normalize_cli_target("http://127.0.0.1:8999") == (
            "http://127.0.0.1:8999",
            None,
        )
        assert _normalize_cli_target("http://[::1]:8080/admin") == (
            "http://[::1]:8080",
            None,
        )

    def test_host_port_and_cidr_and_ipv6(self):
        assert _normalize_cli_target("example.com:8443") == ("example.com:8443", None)
        assert _normalize_cli_target("192.0.2.0/24") == ("192.0.2.0/24", None)
        assert _normalize_cli_target("2001:db8::1") == ("2001:db8::1", None)
        assert _normalize_cli_target("::1") == ("::1", None)

    def test_invalid_tokens_are_refused_with_reason(self):
        for token in (
            "not_a_domain!!",
            "*.example.com",
            "",
            "   ",
            "example.com:notaport",
        ):
            target, reason = _normalize_cli_target(token)
            assert target is None
            assert reason


class TestCliTargetHandoff:
    def _main(self, monkeypatch, tmp_path, argv):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["osint_eye.py", *argv])
        captured = {}

        def _fake_scan(targets, args):
            captured["targets"] = list(targets)
            return {}

        monkeypatch.setattr(osint_eye, "scan_targets", _fake_scan)
        try:
            code = osint_eye.main()
        except SystemExit as exc:
            code = exc.code
        return code, captured

    def test_dirty_targets_arrive_normalized(self, tmp_path, monkeypatch):
        code, captured = self._main(
            monkeypatch,
            tmp_path,
            [
                "HTTPS://Example.COM/ruta",
                "example.com/path?x=1",
                "--no-ai",
                "--no-cache",
                "--modules",
                "dns",
            ],
        )
        assert code == 3  # EXIT_NOTHING_SCANNED (stubbed scan)
        assert captured["targets"] == ["https://example.com", "example.com"]

    def test_invalid_target_is_usage_error(self, tmp_path, monkeypatch, capsys):
        code, _ = self._main(
            monkeypatch,
            tmp_path,
            ["not_a_domain!!", "--no-ai", "--no-cache", "--modules", "dns"],
        )
        assert code == 2
        err = capsys.readouterr().err
        assert "invalid target(s)" in err
        assert "not_a_domain!!" in err

    def test_wildcard_gets_scope_hint(self, tmp_path, monkeypatch, capsys):
        code, _ = self._main(
            monkeypatch,
            tmp_path,
            ["*.example.com", "--no-ai", "--no-cache", "--modules", "dns"],
        )
        assert code == 2
        assert "scope" in capsys.readouterr().err

    def test_loopback_fixture_scan_still_reaches_scan(
        self, tmp_path, monkeypatch
    ):
        code, captured = self._main(
            monkeypatch,
            tmp_path,
            [
                "http://127.0.0.1:8999",
                "--no-ai",
                "--no-cache",
                "--modules",
                "web",
            ],
        )
        assert code == 3
        assert captured["targets"] == ["http://127.0.0.1:8999"]
