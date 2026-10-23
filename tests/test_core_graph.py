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

class TestGraphIngestsCerts:
    def test_ct_subdomains_connect_to_domain_hub(self):
        """CT subdomains must link to the target domain, not float as orphans.

        Regression: _ingest_certs only wired cert_domain -> issuer, so 456
        CT entries rendered as an unconnected ring in the interactive graph.
        """
        from graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.ingest_all(
            {
                "modules": {
                    "certs": {
                        "domain": "mozilla.org",
                        "certificates": [
                            {"domain": "ftp.mozilla.org", "issuer": "DigiCert Inc"},
                            {"domain": "mozilla.org", "issuer": "DigiCert Inc"},
                            {"domain": "other.tld", "issuer": "Let's Encrypt"},
                        ],
                    }
                }
            }
        )
        # subdomains of the scanned domain connect to the hub...
        assert builder.graph.has_edge("mozilla.org", "ftp.mozilla.org")
        # ...the domain itself never self-loops...
        assert not builder.graph.has_edge("mozilla.org", "mozilla.org")
        # ...unrelated cert domains stay unlinked to the hub...
        assert not builder.graph.has_edge("mozilla.org", "other.tld")
        # ...and issuer chains are preserved.
        assert builder.graph.has_edge("ftp.mozilla.org", "DigiCert Inc")

    def test_certs_without_parent_domain_still_renders_issuer_chain(self):
        from graph.builder import GraphBuilder

        builder = GraphBuilder()
        builder.ingest_all(
            {
                "modules": {
                    "certs": {
                        "certificates": [
                            {"domain": "host.example.net", "issuer": "R3"}
                        ]
                    }
                }
            }
        )
        assert builder.graph.has_node("host.example.net")
        assert builder.graph.has_edge("host.example.net", "R3")
        assert builder.graph.number_of_edges() == 1
