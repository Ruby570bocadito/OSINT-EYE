"""Offline tests for the Rich CLI renderer (ui/rich_cli.py).

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""

from tests.conftest import FULL_RESULTS, _record_console


class TestRichCLI:
    def test_print_banner(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_banner()
        out = cli.console.export_text()
        assert "AI-POWERED ATTACK SURFACE INTELLIGENCE" in out
        assert "v2.1" in out

    def test_print_scan_header(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_scan_header("example.com", "deep", stealth=True)
        out = cli.console.export_text()
        assert "example.com" in out
        assert "DEEP" in out
        assert "STEALTH" in out

    def test_print_summary_empty_results(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_summary({})  # must not raise
        cli.print_summary({"target": "example.com", "modules": {}})
        out = cli.console.export_text()
        assert "SCAN SUMMARY" in out
        assert "example.com" in out
        assert "0/100" in out

    def test_print_summary_full_results(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_summary(FULL_RESULTS)
        out = cli.console.export_text()
        assert "example.com" in out
        assert "78/100" in out
        assert "HIGH" in out
        assert "MODULE COVERAGE" in out
        assert "TOP FINDINGS" in out
        assert "CVE-2024-1234" in out

    def test_print_summary_never_keyerror(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        # Malformed shapes must not crash the renderer
        cli.print_summary({"target": "x", "modules": None, "correlation": None, "mitre": None, "attack_chains": None, "ai_analysis": None, "errors": None})
        cli.print_summary({"target": "y", "modules": {"dns": None, "network": {"services": None}}})
        out = cli.console.export_text()
        assert "SCAN SUMMARY" in out

    def test_print_full_results(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.print_full_results(FULL_RESULTS)
        out = cli.console.export_text()
        assert "FULL RESULTS BY MODULE" in out
        for section in (
            "DNS RECONNAISSANCE",
            "CERT TRANSPARENCY",
            "WAYBACK MACHINE",
            "Open Ports",
            "CVE CORRELATION",
            "MITRE ATT&CK",
            "ATTACK CHAINS",
            "CLOUD STORAGE",
            "EMAIL ADDRESSES",
            "GITHUB LEAKS",
            "SUBDOMAIN TAKEOVER",
            "CDN / WAF DETECTION",
        ):
            assert section in out, f"missing section: {section}"

    def test_print_full_results_markup_safe(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        hostile = {
            "target": "[bold red]not-markup[/]",
            "modules": {
                "dns": {"subdomains": ["<script>alert(1)</script>.evil.com"], "records": {"TXT": ["[it] is not markup"]}}
            },
        }
        cli.print_full_results(hostile)  # must not raise
        out = cli.console.export_text()
        assert "<script>alert(1)</script>.evil.com" in out

    def test_log_helpers(self):
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        cli.log_info("starting")
        cli.log_success("done")
        cli.log_warning("slow")
        cli.log_error("boom")
        cli.print_phase(1, "Recon")
        cli.print_phase_done(1, 1.5)
        out = cli.console.export_text()
        for token in ("starting", "done", "slow", "boom", "PHASE 1"):
            assert token in out


class TestRichCLIHelperRegression:
    def test_l_returns_list_not_dict(self):
        from ui.rich_cli import _l

        assert _l(None) == []
        assert _l("abc") == []
        assert _l({"a": 1}) == []
        assert _l([1, 2]) == [1, 2]

    def test_print_full_results_survives_dict_steps(self):
        """A chain whose 'steps' is a dict used to raise TypeError ({}[:3])."""
        from ui.rich_cli import RichCLI

        cli = RichCLI(console=_record_console())
        weird = {
            "target": "example.com",
            "attack_chains": [
                {"name": "bad chain", "risk_score": 90, "steps": {"step": 1, "action": "x"}},
                {"name": "bad chain 2", "risk_score": 10, "steps": "not-a-list"},
            ],
            "modules": {
                "wayback": {
                    "total_snapshots": 5,
                    "interesting_urls": {"url": "not-a-list"},
                    "by_year": "2020",
                },
                "mitre": {"findings": {"tactic": "Recon"}},
            },
            "mitre": {"findings": {"tactic": "Recon"}, "total_findings": "x"},
        }
        cli.print_full_results(weird)  # must not raise
        out = cli.console.export_text()
        assert "FULL RESULTS BY MODULE" in out
        assert "bad chain" in out

    def test_gauge_clamps_out_of_range_values(self):
        from ui.rich_cli import _gauge

        assert _gauge(150, width=28).plain.count("█") <= 28
        assert _gauge(-5).plain.count("█") == 0
        assert _gauge("not-a-number").plain.count("█") == 0


class TestRichCLICountCoercion:
    def test_print_summary_survives_string_counters(self):
        """Hand-loaded JSON with "total_snapshots": "many" crashed max()/int()."""
        from ui.rich_cli import RichCLI

        cli = RichCLI()
        results = {
            "target": "t",
            "modules": {
                "wayback": {"total_snapshots": "many"},
                "permutation": {"total_found": "lots"},
                "github": {"total_findings": None},
                "endpoints": {"total_found": "12"},
            },
            "correlation": {
                "attack_surface_score": {"score": 10, "severity": "LOW", "factors": []}
            },
            "errors": [],
        }
        cli.print_summary(results)  # must not raise
