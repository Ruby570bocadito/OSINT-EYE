"""Offline tests for the graph builder (graph/builder.py).

All tests are byte-identical relocations from the legacy tests/test_core.py
(no test was modified).
"""



class TestGraphBuilder:
    def test_ingest_and_export(self):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()

        test_data = {
            "modules": {
                "dns": {
                    "domain": "example.com",
                    "subdomains": ["www.example.com"],
                    "records": {"A": ["93.184.216.34"]},
                },
                "network": {
                    "host": "93.184.216.34",
                    "services": [{"port": 80, "state": "open", "service": "http"}],
                },
            }
        }

        builder.ingest_all(test_data)
        assert builder.graph.number_of_nodes() > 0
        assert builder.graph.number_of_edges() > 0

        export = builder.export_json()
        assert "nodes" in export
        assert "edges" in export
        assert "stats" in export


class TestGraphIngestsPermutation:
    def test_permutation_subdomains_become_nodes_and_edges(self):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.ingest_all(
            {
                "modules": {
                    "permutation": {
                        "domain": "example.com",
                        "subdomains": ["api-dev.example.com"],
                    }
                }
            }
        )
        assert builder.graph.has_node("api-dev.example.com")
        assert builder.graph.has_edge("example.com", "api-dev.example.com")

    def test_empty_or_missing_domain_is_noop(self):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.ingest_all({"modules": {"permutation": {"domain": "", "subdomains": ["x.com"]}}})
        assert builder.graph.number_of_nodes() == 0
