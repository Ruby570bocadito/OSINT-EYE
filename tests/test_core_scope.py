"""Tests for scope control (core/scope.py + CLI wiring) — 100% offline.

Covers: entry parsing (domains, wildcards, IPs, CIDRs), include/exclude
semantics, URL/host:port normalisation, hostile inputs, discard auditing,
file loading, and the orchestrator gating (targets, permutation, takeover).
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scope import (  # noqa: E402
    Scope,
    ScopeError,
    _normalise_target,
)


# ─────────────────────────────────────────────────────────────────────────────
# Target normalisation
# ─────────────────────────────────────────────────────────────────────────────
class TestNormaliseTarget:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("https://Example.com:8443/path?x=1", "example.com"),
            ("HTTP://EXAMPLE.COM/", "example.com"),
            ("example.com.", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("example.com:8443", "example.com"),
            ("https://user:pass@example.com", "example.com"),
            ("example.com/../../etc/passwd", "example.com"),
            ("93.184.216.34", "93.184.216.34"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("2001:DB8::1", "2001:db8::1"),
        ],
    )
    def test_reduces_to_bare_host(self, raw, expected):
        assert _normalise_target(raw) == expected

    @pytest.mark.parametrize(
        "raw", ["", "   ", None, 42, "exa mple.com", "ex\tample.com", "https://"]
    )
    def test_hostile_or_broken_input_rejected(self, raw):
        with pytest.raises(ScopeError):
            _normalise_target(raw)


# ─────────────────────────────────────────────────────────────────────────────
# Include / exclude semantics
# ─────────────────────────────────────────────────────────────────────────────
class TestDomainScope:
    def test_apex_entry_covers_subdomains(self):
        scope = Scope(includes=["example.com"])
        assert scope.allows("example.com")
        assert scope.allows("www.example.com")
        assert scope.allows("deep.api.example.com")
        assert not scope.allows("notexample.com")  # no suffix false-positive
        assert not scope.allows("evilexample.com")

    def test_wildcard_entry_excludes_apex(self):
        scope = Scope(includes=["*.example.com"])
        assert scope.allows("www.example.com")
        assert not scope.allows("example.com")

    def test_exclude_always_wins(self):
        scope = Scope(includes=["example.com"], excludes=["secret.example.com"])
        assert scope.allows("example.com")
        assert scope.allows("api.example.com")
        assert not scope.allows("secret.example.com")
        assert not scope.allows("deep.secret.example.com")

    def test_unrestricted_scope_only_applies_excludes(self):
        scope = Scope(excludes=["bad.net"])
        assert scope.unrestricted
        assert scope.allows("anything.org")
        assert not scope.allows("bad.net")
        assert not scope.allows("sub.bad.net")

    def test_case_and_trailing_dot_insensitive(self):
        scope = Scope(includes=["EXAMPLE.COM."])
        assert scope.allows("WWW.Example.COM.")

    def test_hostile_targets_never_in_scope(self):
        scope = Scope(includes=["example.com"])
        for hostile in ["ex\tample.com", "", "\x01example.com", None]:
            assert not scope.allows(hostile)
        assert scope.reason("\x01example.com") == "target no parseable"


class TestNetworkScope:
    def test_exact_ip(self):
        scope = Scope(includes=["93.184.216.34"])
        assert scope.allows("93.184.216.34")
        assert scope.allows("http://93.184.216.34/")
        assert not scope.allows("93.184.216.35")

    def test_cidr_v4(self):
        scope = Scope(includes=["192.0.2.0/24"])
        assert scope.allows("192.0.2.1")
        assert scope.allows("192.0.2.254")
        assert not scope.allows("192.0.3.1")
        assert not scope.allows("example.com")

    def test_cidr_v6(self):
        scope = Scope(includes=["2001:db8::/32"])
        assert scope.allows("2001:db8::1")
        assert not scope.allows("2001:db9::1")

    def test_ip_exclude_wins_over_cidr(self):
        scope = Scope(includes=["10.0.0.0/8"], excludes=["10.1.2.3"])
        assert scope.allows("10.1.2.4")
        assert not scope.allows("10.1.2.3")

    def test_invalid_cidr_raises(self):
        with pytest.raises(ScopeError):
            Scope(includes=["192.0.2.0/99"])


# ─────────────────────────────────────────────────────────────────────────────
# File loading + audit log
# ─────────────────────────────────────────────────────────────────────────────
class TestScopeFile:
    def _write(self, tmp_path, content):
        path = tmp_path / "scope.txt"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        path = self._write(
            tmp_path,
            "# authorized by ACME\n\nexample.com\n  \n192.0.2.0/24\n# tail\n",
        )
        scope = Scope.from_file(path)
        assert scope.allows("www.example.com")
        assert scope.allows("192.0.2.7")
        assert not scope.allows("off.net")

    def test_invalid_line_lists_entry(self, tmp_path):
        path = self._write(tmp_path, "example.com\nbad/path/entry\n")
        with pytest.raises(ScopeError):
            Scope.from_file(path)

    def test_missing_file_raises_oserror(self, tmp_path):
        with pytest.raises(OSError):
            Scope.from_file(tmp_path / "nope.txt")

    def test_from_file_with_cli_excludes(self, tmp_path):
        path = self._write(tmp_path, "example.com\n")
        scope = Scope.from_file(path, excludes=["api.example.com"])
        assert scope.allows("www.example.com")
        assert not scope.allows("api.example.com")


class TestDiscardAudit:
    def test_filter_targets_preserves_order_and_logs(self):
        scope = Scope(includes=["example.com"])
        allowed = scope.filter_targets(
            ["www.example.com", "evil.net", "api.example.com"], module="permutation"
        )
        assert allowed == ["www.example.com", "api.example.com"]
        assert len(scope.discarded) == 1
        entry = scope.discarded[0]
        assert entry["target"] == "evil.net"
        assert entry["module"] == "permutation"
        assert entry["reason"] == "fuera de scope"
        assert entry["timestamp"]

    def test_to_dict_shape(self):
        scope = Scope(includes=["example.com"], excludes=["10.0.0.0/8"])
        scope.discard("off.net", "cli")
        summary = scope.to_dict()
        assert summary["unrestricted"] is False
        assert summary["includes"] == 1
        assert summary["excludes"] == 1
        assert len(summary["discarded"]) == 1
        import json

        json.dumps(summary)  # must stay JSON-safe


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator gating (offline, modules patched like the rest of the suite)
# ─────────────────────────────────────────────────────────────────────────────
class TestOSINTEyeScopeGating:
    def _engine(self, scope):
        from osint_eye import OSINTEye

        return OSINTEye(target="example.com", ai=False, cache=False, scope=scope)

    def test_permutation_drops_out_of_scope_candidates(self):
        scope = Scope(includes=["example.com"])
        engine = self._engine(scope)
        with patch.object(
            engine.permutator,
            "enumerate",
            return_value=["api.example.com", "evil.net"],
        ):
            engine.run_permutation()
        assert engine.results["modules"]["permutation"]["subdomains"] == [
            "api.example.com"
        ]
        assert engine.results["modules"]["permutation"]["total_found"] == 1
        assert [d["target"] for d in scope.discarded] == ["evil.net"]
        assert scope.discarded[0]["module"] == "permutation"

    def test_takeover_probes_only_in_scope_subs(self):
        scope = Scope(includes=["example.com"], excludes=["secret.example.com"])
        engine = self._engine(scope)
        engine.results["modules"]["dns"] = {
            "subdomains": [
                "www.example.com",
                "secret.example.com",
                "off.net",
            ]
        }
        probed = {}
        with patch.object(
            engine.takeover_detector, "scan_list", return_value=[]
        ) as mocked:
            engine.run_takeover_check()
            probed["args"] = mocked.call_args[0][0]
        assert probed["args"] == ["www.example.com"]
        targets_discarded = [d["target"] for d in scope.discarded]
        assert "secret.example.com" in targets_discarded
        assert "off.net" in targets_discarded

    def test_scope_summary_lands_in_results(self):
        scope = Scope(includes=["example.com"])
        engine = self._engine(scope)
        engine._refresh_scope_summary()
        assert engine.results["scope"]["unrestricted"] is False
        assert engine.results["scope"]["includes"] == 1
        from core.schema import validate_results

        assert validate_results(engine.results) == []

    def test_no_scope_keeps_results_clean(self):
        engine = self._engine(None)
        engine._refresh_scope_summary()
        assert "scope" not in engine.results


class TestCLIScopeWiring:
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

    def test_missing_scope_file_is_usage_error(self, tmp_path):
        result = self._run_cli("example.com", "--scope", str(tmp_path / "no.txt"))
        assert result.returncode == 2
        assert "scope" in (result.stderr + result.stdout).lower()

    def test_invalid_scope_entry_is_usage_error(self, tmp_path):
        bad = tmp_path / "scope.txt"
        bad.write_text("example.com\nbad//entry\n", encoding="utf-8")
        result = self._run_cli("example.com", "--scope", str(bad))
        assert result.returncode == 2

    def test_valid_scope_file_accepted_by_cli(self, tmp_path):
        good = tmp_path / "scope.txt"
        good.write_text("# ok\nexample.com\n", encoding="utf-8")
        # --modules sin valores imprime el catálogo y sale 0: cruza la
        # construcción de scope sin tocar la red.
        result = self._run_cli("example.com", "--scope", str(good), "--modules")
        assert result.returncode == 0, result.stderr
