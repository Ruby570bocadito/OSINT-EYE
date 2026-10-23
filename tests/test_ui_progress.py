"""Tests for the live per-module progress tracker (ui/rich_cli.py).

All offline: no engine run, no network. The tracker is exercised directly
and via instrument_engine() against a stub engine object.
"""

import threading
import time

import pytest

from ui.rich_cli import ModuleProgressTracker, _finding_count, instrument_engine


class StubEngine:
    """Minimal engine surface: results dict + a couple of run_* methods."""

    def __init__(self):
        self.results = {"modules": {}, "errors": []}
        self.calls = []

    def run_dns(self):
        self.calls.append("dns")
        self.results["modules"]["dns"] = {"subdomains": ["a.example.com", "b.example.com"]}

    def run_certs(self):
        self.calls.append("certs")
        self.results["modules"]["certs"] = {"subdomains": ["a.example.com"]}

    def run_correlation(self):
        self.calls.append("correlation")
        self.results["correlation"] = {"attack_surface_score": {"score": 42}}

    def run_takeover_check(self):
        self.calls.append("boom")
        raise RuntimeError("module exploded")

    def run_web(self):
        self.calls.append("web-silent")
        self.results["errors"].append("[web] source down")

class TestModuleProgressTracker:
    def test_lifecycle_states_and_timing(self):
        tracker = ModuleProgressTracker(live=False)
        tracker.ensure_module("dns")
        snapshot = tracker.snapshot()
        assert snapshot["dns"]["state"] == "pending"

        tracker.start("dns")
        time.sleep(0.01)
        tracker.finish("dns", findings=5, errors=0)
        row = tracker.snapshot()["dns"]
        assert row["state"] == "done"
        assert row["findings"] == 5
        assert row["errors"] == 0
        assert isinstance(row["elapsed"], float)
        assert row["elapsed"] >= 0

    def test_error_state_on_explicit_flag_or_error_count(self):
        tracker = ModuleProgressTracker(live=False)
        tracker.start("web")
        tracker.finish("web", findings=0, errors=2)
        assert tracker.snapshot()["web"]["state"] == "error"

        tracker.start("cve")
        tracker.finish("cve", findings=1, errors=0, error=True)
        assert tracker.snapshot()["cve"]["state"] == "error"

    def test_finish_without_start_keeps_pending_elapsed_none(self):
        tracker = ModuleProgressTracker(live=False)
        tracker.finish("whois", findings=1)
        row = tracker.snapshot()["whois"]
        assert row["state"] == "done"
        assert row["elapsed"] is None

    def test_concurrent_starts_and_finishes_are_consistent(self):
        tracker = ModuleProgressTracker(live=False)
        names = [f"mod-{i}" for i in range(8)]

        def worker(name):
            tracker.start(name)
            time.sleep(0.005)
            tracker.finish(name, findings=3, errors=0)

        threads = [threading.Thread(target=worker, args=(n,)) for n in names]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snapshot = tracker.snapshot()
        assert len(snapshot) == 8
        assert all(row["state"] == "done" and row["findings"] == 3 for row in snapshot.values())

    def test_start_live_and_stop_are_idempotent(self):
        tracker = ModuleProgressTracker(live=False)
        tracker.start_live()
        tracker.start_live()  # second call is a no-op
        tracker.stop_live()
        tracker.stop_live()  # no live session -> no-op, never raises


class TestFindingCount:
    def test_counts_top_level_lists(self):
        assert _finding_count({"subdomains": ["a", "b"], "records": {}}) == 2

    def test_counts_one_level_nested_dict_lists(self):
        assert _finding_count({"technologies": {"technologies": ["Nginx", "PHP"]}}) == 2

    def test_graph_nodes_and_edges(self):
        assert _finding_count({"nodes": [1, 2], "edges": [1]}) == 3

    def test_non_dict_and_empty(self):
        assert _finding_count(None) == 0
        assert _finding_count("flat") == 0
        assert _finding_count({}) == 0


class TestInstrumentEngine:
    def test_wrapped_methods_drive_the_tracker(self):
        engine = StubEngine()
        tracker = instrument_engine(engine)

        engine.run_dns()
        engine.run_correlation()

        snapshot = tracker.snapshot()
        assert engine.calls == ["dns", "correlation"]  # originals ran once
        assert snapshot["dns"]["state"] == "done"
        assert snapshot["dns"]["findings"] == 2  # two subdomains
        assert snapshot["correlation"]["findings"] == 0  # score dict, no lists

    def test_exception_marks_error_and_reraises(self):
        engine = StubEngine()
        tracker = instrument_engine(engine, ModuleProgressTracker(live=False))

        with pytest.raises(RuntimeError):
            engine.run_takeover_check()

        row = tracker.snapshot()["takeover"]
        assert row["state"] == "error"
        assert row["errors"] == 1

    def test_error_delta_from_results_errors(self):
        engine = StubEngine()
        tracker = instrument_engine(engine, ModuleProgressTracker(live=False))

        engine.run_web()
        row = tracker.snapshot()["web"]
        assert row["state"] == "error"  # results["errors"] grew by 1
        assert row["errors"] == 1

    def test_instrument_is_idempotent(self):
        engine = StubEngine()
        first = instrument_engine(engine, ModuleProgressTracker(live=False))
        second = instrument_engine(engine, first)

        assert first is second
        engine.run_dns()
        assert engine.calls == ["dns"]  # not double-wrapped

    def test_engine_without_results_dict_is_ignored(self):
        class Weird:
            pass

        weird = Weird()
        tracker = instrument_engine(weird, ModuleProgressTracker(live=False))
        assert tracker.snapshot() == {}

    def test_all_real_engine_modules_are_registered(self):
        from osint_eye import OSINTEye

        engine = OSINTEye("example.com", ai=False, cache=False)
        tracker = instrument_engine(engine, ModuleProgressTracker(live=False))
        labels = set(tracker.snapshot())
        for expected in ("dns", "certs", "wayback", "whois", "network", "web", "cve",
                         "cloud", "emails", "correlation", "graph", "mitre", "chains"):
            assert expected in labels, expected
        # double instrument on the real engine must not re-wrap either
        assert instrument_engine(engine, tracker) is tracker
