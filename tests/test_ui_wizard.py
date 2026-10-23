"""Offline tests for the interactive wizard (ui/wizard.py).

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""
from unittest.mock import patch


class TestInteractiveWizard:
    def test_start_returns_valid_args(self):
        from ui import wizard as wiz

        prompt_answers = iter(
            [
                "example.com, www.example.com",  # targets (deduped)
                "deep",  # depth
                "osint_eye_custom",  # output base
            ]
        )
        confirm_answers = iter(
            [False, False, True, True, False, False, False, False]
        )  # ai, cache, stealth, rich, agent, pdf, dashboard, cypher

        with patch.object(wiz.Prompt, "ask", staticmethod(lambda *a, **k: next(prompt_answers))), \
             patch.object(wiz.Confirm, "ask", staticmethod(lambda *a, **k: next(confirm_answers))):
            args = wiz.InteractiveWizard().start()

        assert isinstance(args, list)
        assert all(isinstance(a, str) for a in args)
        assert args[0] == "example.com"
        assert "www.example.com" in args  # second target kept
        assert args[args.index("--depth") + 1] == "deep"
        assert "--no-ai" in args
        assert "--no-cache" in args
        assert "--stealth" in args
        assert "--rich" in args
        assert "--output" in args
        assert args[args.index("--output") + 1] == "osint_eye_custom"

    def test_flags_exist_in_parser_contract(self):
        """Every flag the wizard emits must exist in osint_eye's argparse."""
        valid = {
            "--depth", "--stealth", "--no-ai", "--no-cache", "--rich",
            "--output", "--agent", "--pdf", "--dashboard", "--export-cypher",
        }
        from ui import wizard as wiz

        assert wiz._VALID_FLAGS & valid == valid

    def test_target_parsing(self):
        from ui.wizard import InteractiveWizard

        assert InteractiveWizard._parse_targets("a.com, b.com  c.com") == ["a.com", "b.com", "c.com"]
        assert InteractiveWizard._parse_targets("dup.com dup.com") == ["dup.com"]
        assert InteractiveWizard._parse_targets("") == []


class TestWizardMarkupTarget:
    def test_start_survives_hostile_target(self):
        from ui import wizard as wiz

        prompt_answers = iter(["x[/bold]y.com", "normal", "osint_eye_x"])
        confirm_answers = iter(
            [True, True, False, False, False, False, False, False]
        )  # ai, cache, stealth, rich, agent, pdf, dashboard, cypher

        with patch.object(wiz.Prompt, "ask", staticmethod(lambda *a, **k: next(prompt_answers))), \
             patch.object(wiz.Confirm, "ask", staticmethod(lambda *a, **k: next(confirm_answers))):
            args = wiz.InteractiveWizard().start()

        assert args[0] == "x[/bold]y.com"
