"""Tests for the wizard's target-format validation (wizard-validacion-target).

All offline: rich Prompt/Confirm are monkeypatched with scripted answers.
Accepted target formats: bare domains (RFC-style labels, punycode ok),
IPv4/IPv6 addresses and CIDR networks. URL-like input triggers a warning
and an interactive host swap; invalid input lists reasons and re-asks.
"""

import pytest

from ui import wizard as wizard_mod
from ui.wizard import InteractiveWizard


@pytest.fixture()
def w():
    return InteractiveWizard()


class TestValidateTarget:
    @pytest.mark.parametrize(
        "target",
        [
            "scanme.example.org",
            "EXAMPLE.com.",
            "a-b.example.io",
            "localhost",
            "xn--bcher-kva.example",  # punycode label
            "192.0.2.1",
            "::1",
            "2001:db8::1",
            "192.0.2.0/24",  # CIDR
            "10.0.0.0/8",
            "2001:db8::/32",
        ],
    )
    def test_valid_targets(self, target):
        ok, reason = InteractiveWizard._validate_target(target)
        assert ok, reason

    @pytest.mark.parametrize(
        ("target", "why"),
        [
            ("", "empty"),
            ("*.example.com", "wildcard"),
            ("192.0.2.0/99", "CIDR"),
            ("example.com/24", "CIDR"),
            ("-bad.example.com", "hyphen"),
            ("bad-.example.com", "hyphen"),
            ("ba d.example.com", "space"),
            ("a..b.com", "double dot"),
            ("exa_mple.com", "underscore"),
            ("example.com:8080", "port"),
            ("café.example.com", "unicode"),
        ],
    )
    def test_invalid_targets(self, target, why):
        ok, reason = InteractiveWizard._validate_target(target)
        assert not ok, f"'{target}' should be invalid ({why})"
        assert reason

    def test_long_label_rejected(self):
        ok, reason = InteractiveWizard._validate_target("x" * 64 + ".com")
        assert not ok
        assert "63" in reason

    def test_long_domain_rejected(self):
        label = "a" * 63
        ok, _ = InteractiveWizard._validate_target(".".join([label] * 5))
        assert not ok

    def test_reasons_are_actionable(self):
        _, reason = InteractiveWizard._validate_target("*.example.com")
        assert "scope" in reason


class TestLooksLikeUrl:
    @pytest.mark.parametrize(
        "token",
        [
            "https://example.com",
            "http://example.com/admin",
            "example.com/admin",
            "user@example.com",
            "example.com:8080",
            "192.0.2.1:443",
            "[::1]:8080",
            "ftp://files.example.com",
        ],
    )
    def test_url_like(self, token):
        assert InteractiveWizard._looks_like_url(token)

    @pytest.mark.parametrize(
        "token",
        [
            "example.com",
            "192.0.2.1",
            "192.0.2.0/24",  # valid CIDR, not a URL
            "2001:db8::/32",
            "::1",
            "2001:db8::1",
            "",
        ],
    )
    def test_not_url_like(self, token):
        assert not InteractiveWizard._looks_like_url(token)


class TestHostFromUrl:
    @pytest.mark.parametrize(
        ("token", "host"),
        [
            ("https://EXAMPLE.com/admin?t=1", "EXAMPLE.com"),
            ("http://example.com/", "example.com"),
            ("example.com/admin", "example.com"),
            ("user@host.com", "host.com"),
            ("[::1]:8080", "::1"),
            ("example.com:8080", "example.com"),
            ("notaurl", "notaurl"),
            ("https://", ""),
        ],
    )
    def test_extraction(self, token, host):
        assert InteractiveWizard._host_from_url(token) == host


class TestValidateTargetsBatch:
    def test_mixed_batch_routes_clean_and_bad(self):
        clean, bad = InteractiveWizard._validate_targets(
            ["example.com", "192.0.2.0/24", "bad!.com"]
        )
        assert clean == ["example.com", "192.0.2.0/24"]
        assert [t for t, _ in bad] == ["bad!.com"]
        assert bad[0][1]

    def test_url_like_fails_in_batch_with_reason(self):
        clean, bad = InteractiveWizard._validate_targets(["https://example.com"])
        assert clean == []
        assert bad == [("https://example.com", "looks like a URL — use the bare host")]


class TestAskTargetsFlow:
    @staticmethod
    def _script(monkeypatch, prompts, confirms):
        prompts = iter(prompts)
        confirms = iter(confirms)
        monkeypatch.setattr(
            wizard_mod.Prompt, "ask", staticmethod(lambda *a, **k: next(prompts))
        )
        monkeypatch.setattr(
            wizard_mod.Confirm, "ask", staticmethod(lambda *a, **k: next(confirms))
        )

    def test_happy_path_domain_ip_cidr(self, w, monkeypatch):
        self._script(monkeypatch, ["example.com, 192.0.2.0/24"], [])
        assert w._ask_targets() == ["example.com", "192.0.2.0/24"]

    def test_empty_then_valid(self, w, monkeypatch):
        self._script(monkeypatch, ["", "example.com"], [])
        assert w._ask_targets() == ["example.com"]

    def test_invalid_batch_retries(self, w, monkeypatch):
        self._script(
            monkeypatch, ["bad!.com, example.com", "example.com"], []
        )
        assert w._ask_targets() == ["example.com"]

    def test_url_swap_accepted(self, w, monkeypatch):
        self._script(monkeypatch, ["https://example.com/admin"], [True])
        assert w._ask_targets() == ["example.com"]

    def test_url_swap_declined_retries(self, w, monkeypatch):
        self._script(
            monkeypatch, ["https://example.com/admin", "example.com"], [False]
        )
        assert w._ask_targets() == ["example.com"]

    def test_url_swap_dedupes_bare_host(self, w, monkeypatch):
        self._script(
            monkeypatch, ["example.com, https://example.com/x"], [True]
        )
        assert w._ask_targets() == ["example.com"]

    def test_swapped_host_still_validated(self, w, monkeypatch):
        # The host extracted from the URL is itself invalid → batch retries
        self._script(monkeypatch, ["https://bad!.com/admin", "example.com"], [True])
        assert w._ask_targets() == ["example.com"]

    def test_cidr_not_flagged_as_url(self, w, monkeypatch):
        self._script(monkeypatch, ["2001:db8::/32, 10.0.0.0/8"], [])
        assert w._ask_targets() == ["2001:db8::/32", "10.0.0.0/8"]


class TestFullFlowStillWorks:
    def test_start_returns_validated_targets(self, w, monkeypatch):
        # Minimal happy path through the whole wizard with valid targets.
        seq = [
            "example.com, 192.0.2.55",  # targets
            "",                          # scope
            "",                          # exclusions
            True,                        # authorized
            "quick",                     # depth
            False,                       # local AI?  → --no-ai
            True,                        # cache?
            False,                       # stealth?
            True,                        # rich output?
            "",                          # output base name (default)
            False,                       # red team playbook?
            False,                       # pdf?
            False,                       # dashboard?
            False,                       # cypher?
        ]
        idx = {"i": 0}

        def next_answer(*_a, **_k):
            value = seq[idx["i"]]
            idx["i"] += 1
            return value

        monkeypatch.setattr(wizard_mod.Prompt, "ask", staticmethod(next_answer))
        monkeypatch.setattr(wizard_mod.Confirm, "ask", staticmethod(next_answer))
        monkeypatch.setattr(wizard_mod.console, "clear", lambda *a, **k: None)

        args = w.start()
        assert args[0:2] == ["example.com", "192.0.2.55"]
        assert "--no-ai" in args
