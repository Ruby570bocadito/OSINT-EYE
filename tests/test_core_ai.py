"""Offline tests for the local risk scorer (ai/llm_engine.py).

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""



class TestRiskScorerShapes:
    """AIEngine.analyze() is fed the modules dict, not a flat payload — the
    scorer must understand both shapes (the modules shape used to score ~0)."""

    def test_modules_shape_scores(self):
        from ai.llm_engine import RiskScorer

        scorer = RiskScorer()
        modules = {
            "dns": {"subdomains": [f"s{i}.example.com" for i in range(5)]},
            "network": {"services": [{"port": 22, "service": "ssh", "state": "open"}]},
            "wayback": {"interesting_urls": [{"url": "https://example.com/.env"}]},
        }
        result = scorer.calculate_risk_score(modules)
        assert result["score"] >= 30
        assert any("subdomains" in f for f in result["factors"])
        assert any("22" in f for f in result["factors"])
        assert any("Wayback" in f for f in result["factors"])

    def test_flat_shape_still_scores(self):
        from ai.llm_engine import RiskScorer

        scorer = RiskScorer()
        result = scorer.calculate_risk_score({"subdomains": ["a.example.com"], "services": [], "wayback": {}})
        assert result["score"] == 2

    def test_non_dict_services_entries_ignored(self):
        from ai.llm_engine import RiskScorer

        scorer = RiskScorer()
        result = scorer.calculate_risk_score({"services": ["http", None, 42]})
        assert result["score"] == 0
