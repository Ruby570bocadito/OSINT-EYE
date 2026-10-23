"""Tests for the wizard's scope/exclusions questions and authorization gate.

All offline: rich Prompt/Confirm are monkeypatched with scripted answers.
"""

import pytest

from ui import wizard as wizard_mod
from ui.wizard import InteractiveWizard


@pytest.fixture()
def w():
    return InteractiveWizard()


class TestMatchesScope:
    def test_plain_domain_matches_self_and_subdomains(self):
        assert InteractiveWizard._matches_scope("example.com", "example.com")
        assert InteractiveWizard._matches_scope("api.example.com", "example.com")
        assert InteractiveWizard._matches_scope("API.Example.COM.", "example.com")

    def test_plain_domain_does_not_overmatch(self):
        assert not InteractiveWizard._matches_scope("notexample.com", "example.com")
        assert not InteractiveWizard._matches_scope("example.com.evil.io", "example.com")

    def test_wildcard_matches_only_subdomains(self):
        assert InteractiveWizard._matches_scope("api.example.com", "*.example.com")
        assert not InteractiveWizard._matches_scope("example.com", "*.example.com")

    def test_cidr_matches_ips_inside_network(self):
        assert InteractiveWizard._matches_scope("192.0.2.55", "192.0.2.0/24")
        assert not InteractiveWizard._matches_scope("192.0.3.1", "192.0.2.0/24")
        assert InteractiveWizard._matches_scope("2001:db8::1", "2001:db8::/32")

    def test_invalid_patterns_match_nothing(self):
        assert not InteractiveWizard._matches_scope("example.com", "not an ip/24")
        assert not InteractiveWizard._matches_scope("example.com", "")
        assert not InteractiveWizard._matches_scope("", "example.com")
        assert not InteractiveWizard._matches_scope("example.com", None)


class TestNarrowTargets:
    def test_exclusions_drop_matches(self):
        kept, dropped = InteractiveWizard._narrow_targets(
            ["a.example.com", "secret.example.com", "b.example.com"],
            scope=[],
            exclusions=["secret.example.com"],
        )
        assert kept == ["a.example.com", "b.example.com"]
        assert dropped == [("secret.example.com", "excluded")]

    def test_scope_limits_keep_list(self):
        kept, dropped = InteractiveWizard._narrow_targets(
            ["example.com", "other.io"],
            scope=["example.com"],
            exclusions=[],
        )
        assert kept == ["example.com"]
        assert dropped == [("other.io", "out of scope")]

    def test_exclusion_wins_over_scope(self):
        kept, dropped = InteractiveWizard._narrow_targets(
            ["secret.example.com"], scope=["example.com"], exclusions=["secret.example.com"]
        )
        assert kept == []
        assert dropped == [("secret.example.com", "excluded")]

    def test_empty_everything_keeps_all(self):
        kept, dropped = InteractiveWizard._narrow_targets(["a.com", "b.com"], [], [])
        assert kept == ["a.com", "b.com"]
        assert dropped == []


class TestAuthorizationGate:
    def test_confirmed_passes(self, w, monkeypatch):
        monkeypatch.setattr(wizard_mod.Confirm, "ask", staticmethod(lambda *a, **k: True))
        w._confirm_authorization(["example.com"])  # must not raise

    def test_declined_exits_cleanly(self, w, monkeypatch, capsys):
        monkeypatch.setattr(wizard_mod.Confirm, "ask", staticmethod(lambda *a, **k: False))
        with pytest.raises(SystemExit) as exc:
            w._confirm_authorization(["example.com"])
        assert exc.value.code == 0
        assert "cancelled" in capsys.readouterr().out.lower()

    def test_declined_defaults_to_cancel(self, w, monkeypatch):
        # Confirm.ask default=False: pressing enter must cancel the scan
        monkeypatch.setattr(
            wizard_mod.Confirm, "ask",
            staticmethod(lambda *a, **k: k.get("default", False)),
        )
        with pytest.raises(SystemExit):
            w._confirm_authorization(["example.com"])


class TestScopeAskFlow:
    def test_scope_narrows_targets_and_notices(self, w, monkeypatch):
        answers = iter(["example.com", "secret.example.com"])
        monkeypatch.setattr(wizard_mod.Prompt, "ask", staticmethod(lambda *a, **k: next(answers)))
        kept, scope, exclusions = w._ask_scope_and_exclusions(
            ["api.example.com", "secret.example.com"]
        )
        assert kept == ["api.example.com"]
        assert scope == ["example.com"]
        assert exclusions == ["secret.example.com"]

    def test_all_targets_dropped_exits(self, w, monkeypatch):
        answers = iter(["other.io", ""])
        monkeypatch.setattr(wizard_mod.Prompt, "ask", staticmethod(lambda *a, **k: next(answers)))
        with pytest.raises(SystemExit):
            w._ask_scope_and_exclusions(["example.com"])


class TestFullFlow:
    def _script_wizard(self, monkeypatch, target, scope, exclusions, authorized,
                       depth="normal", use_ai=True, cache=True, stealth=False,
                       rich_out=False, output="", agent=False, pdf=False,
                       dashboard=False, cypher=False):
        seq = [
            target,        # targets
            scope,         # scope limit
            exclusions,    # exclusions
            authorized,    # authorization confirm
            depth,         # depth
            use_ai,        # local AI?
            cache,         # cache?
            stealth,       # stealth?
            rich_out,      # rich output?
            output,        # output base name
            agent,         # red team playbook?
            pdf,           # pdf?
            dashboard,     # dashboard?
            cypher,        # cypher?
        ]
        idx = {"i": 0}

        def prompt_ask(*a, **k):
            value = seq[idx["i"]]
            idx["i"] += 1
            return value

        def confirm_ask(*a, **k):
            value = seq[idx["i"]]
            idx["i"] += 1
            if not isinstance(value, bool):
                value = str(value).strip().lower() in ("y", "yes", "true", "1")
            return value

        monkeypatch.setattr(wizard_mod.Prompt, "ask", staticmethod(prompt_ask))
        monkeypatch.setattr(wizard_mod.Confirm, "ask", staticmethod(confirm_ask))
        monkeypatch.setattr(wizard_mod.console, "clear", lambda *a, **k: None)

    def test_full_flow_authorized_with_scope(self, w, monkeypatch):
        self._script_wizard(
            monkeypatch,
            target="example.com, secret.example.com",
            scope="example.com",
            exclusions="secret.example.com",
            authorized=True,
        )
        args = w.start()
        # the excluded target never reaches the CLI
        assert "example.com" in args
        assert "secret.example.com" not in args
        assert "--no-ai" not in args

    def test_full_flow_unauthorized_aborts(self, w, monkeypatch):
        self._script_wizard(
            monkeypatch,
            target="example.com",
            scope="",
            exclusions="",
            authorized=False,
        )
        with pytest.raises(SystemExit) as exc:
            w.start()
        assert exc.value.code == 0
