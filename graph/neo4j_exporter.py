"""OSINT EYE - Neo4j Cypher Graqh Exporter"""

import json
from typing import Dict, List

class Neo4jExporter:
    """Exports OSINT EYE Graph to Neo4j Cypher queries"""

    def __init__(self, graph_data: Dict):
        self.nodes = graph_data.get("nodes", [])
        self.edges = graph_data.get("edges", [])

    def generate_cypher(self) -> str:
        """Generates the full .cypher import script"""
        queries = []
        
        # 1. Create constraints for uniqueness (Neo4j best practice)
        queries.append("// --- Constraints ---")
        queries.append("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Domain) REQUIRE n.id IS UNIQUE;")
        queries.append("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Subdomain) REQUIRE n.id IS UNIQUE;")
        queries.append("CREATE CONSTRAINT IF NOT EXISTS FOR (n:IP) REQUIRE n.id IS UNIQUE;")
        queries.append("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE;")
        queries.append("")

        # 2. Add Nodes
        queries.append("// --- Nodes ---")
        for node in self.nodes:
            nid = node.get("id", "").replace("'", "\\'")
            ntype = str(node.get("type", "Unknown")).capitalize()
            label = node.get("label", "").replace("'", "\\'")
            color = node.get("color", "")
            
            queries.append(
                f"MERGE (n:{ntype} {{id: '{nid}'}}) "
                f"SET n.label = '{label}', n.color = '{color}';"
            )
            
        queries.append("")

        # 3. Add Edges
        queries.append("// --- Edges ---")
        for edge in self.edges:
            source = edge.get("source", "").replace("'", "\\'")
            target = edge.get("target", "").replace("'", "\\'")
            rel_type = str(edge.get("label", "RELATED_TO")).upper().replace(" ", "_").replace("-", "_")
            if not rel_type:
                rel_type = "RELATED_TO"

            # Find source and target types to construct the MATCH clause
            src_node = next((n for n in self.nodes if n.get("id") == source), None)
            tgt_node = next((n for n in self.nodes if n.get("id") == target), None)
            
            if src_node and tgt_node:
                src_type = str(src_node.get("type", "Unknown")).capitalize()
                tgt_type = str(tgt_node.get("type", "Unknown")).capitalize()
                
                queries.append(
                    f"MATCH (s:{src_type} {{id: '{source}'}}), (t:{tgt_type} {{id: '{target}'}}) "
                    f"MERGE (s)-[:{rel_type}]->(t);"
                )

        return "\n".join(queries)

    def export_file(self, filename: str) -> None:
        """Writes the cypher queries to a file"""
        cypher_script = self.generate_cypher()
        with open(filename, "w") as f:
            f.write(cypher_script)
