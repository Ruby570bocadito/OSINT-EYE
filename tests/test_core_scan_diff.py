"""Tests for ScanDiff reuse safety (core/scan_diff.py) — offline.

Regression tests for the IMP-2 request: compare() must never keep
entries from a previous comparison on a reused instance.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scan_diff import ScanDiff  # noqa: E402


def _scan(subdomains, ports):
    return {
        "target": "example.com",
        "modules": {
            "dns": {"subdomains": list(subdomains)},
            "network": {
                "services": [
                    {"host": "example.com", "port": p, "state": "open",
                     "service": "http", "version": ""}
                    for p in ports
                ]
            },
        },
    }


class TestScanDiffReuse:
    def test_compare_is_safe_to_reuse(self):
        differ = ScanDiff()

        first = differ.compare(
            _scan([], []), _scan(["a.example.com"], [80, 443])
        )
        assert first["new_subdomains"] == ["a.example.com"]
        assert {p["port"] for p in first["new_ports"]} == {80, 443}

        # Second comparison with DIFFERENT, smaller inputs on the same
        # instance: no residue from the first run.
        second = differ.compare(
            _scan([], []), _scan(["b.example.com"], [8080])
        )
        assert second["new_subdomains"] == ["b.example.com"]
        assert second["new_ports"], "segunda comparación debe tener puertos nuevos"
        assert {p["port"] for p in second["new_ports"]} == {8080}
        assert all(p["port"] != 80 and p["port"] != 443 for p in second["new_ports"])

    def test_identical_scans_yield_empty_diff_after_reuse(self):
        differ = ScanDiff()
        differ.compare(_scan(["a.example.com"], [80]), _scan(["a.example.com"], [80]))
        empty = differ.compare(_scan([], []), _scan([], []))
        for key in ScanDiff.DIFF_KEYS:
            if key == "score_change":
                assert empty[key] == {"before": 0, "after": 0, "delta": 0}
            else:
                assert empty[key] == [], f"{key} debería quedar vacío"

    def test_summary_matches_last_compare_only(self):
        differ = ScanDiff()
        differ.compare(_scan(["old.example.com"], [80]), _scan(["new.example.com"], []))
        differ.compare(_scan([], []), _scan([], []))
        summary = differ.get_summary()
        # The stale subdomain names must not leak into the second summary.
        assert "old.example.com" not in summary
        assert "new.example.com" not in summary
