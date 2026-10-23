"""OSINT EYE - Neo4j Cypher Graph Exporter"""

import re
from typing import Any


def _cypher_str(value: Any) -> str:
    """Escape a Python value as a single-quoted Cypher string literal."""
    if value is None:
        return ""
    s = str(value)
    # Escape backslashes first, then single quotes (Cypher accepts \' inside
    # single-quoted literals).
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _neo4j_label(value: Any, default: str = "Unknown") -> str:
    """Sanitize a node type into a valid Neo4j label (PascalCase-ish)."""
    text = str(value or default).strip()
    # Keep only word characters; Neo4j labels cannot contain spaces/symbols.
    text = re.sub(r"[^\w]", "_", text)
    if not text or text[0].isdigit():
        text = f"_{text}"
    return text[0].upper() + text[1:]


def _neo4j_rel_type(value: Any, default: str = "RELATED_TO") -> str:
    """Sanitize an edge label into a valid Neo4j relationship type (UPPER_SNAKE)."""
    text = str(value or "").strip().upper()
    text = re.sub(r"[^\w]", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or default


class Neo4jExporter:
    """Exports OSINT EYE Graph to Neo4j Cypher queries (Neo4j 5+ syntax)."""

    def __init__(self, graph_data: dict[str, Any]):
        self.nodes: list[dict[str, Any]] = graph_data.get("nodes") or []
        self.edges: list[dict[str, Any]] = graph_data.get("edges") or []

    def generate_cypher(self) -> str:
        """Generates the full .cypher import script"""
        queries = []

        # 1. Create constraints for uniqueness (Neo4j best practice)
        node_labels = sorted({_neo4j_label(n.get("type")) for n in self.nodes})
        queries.append("// --- Constraints ---")
        for label in node_labels:
            queries.append(
                f"CREATE CONSTRAINT IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE n.id IS UNIQUE;"
            )
        queries.append("")

        # 2. Add Nodes
        queries.append("// --- Nodes ---")
        for node in self.nodes:
            raw_id = node.get("id")
            if raw_id is None or raw_id == "":
                continue
            nid = str(raw_id)
            ntype = _neo4j_label(node.get("type"))
            label = _cypher_str(node.get("label", nid))
            color = _cypher_str(node.get("color", ""))

            queries.append(
                f"MERGE (n:{ntype} {{id: '{_cypher_str(nid)}'}}) "
                f"SET n.label = '{label}', n.color = '{color}';"
            )

        queries.append("")

        # 3. Add Edges (edges whose endpoints were skipped are ignored)
        queries.append("// --- Edges ---")
        node_by_id: dict[str, dict[str, Any]] = {}
        for n in self.nodes:
            raw_nid: Any = n.get("id")
            if raw_nid is not None and raw_nid != "":
                node_by_id[str(raw_nid)] = n
        for edge in self.edges:
            # GraphBuilder uses "source"/"target"; AssetCorrelator graphs use
            # "from"/"to" (with integer ids). Accept both.
            raw_source = edge.get("source", edge.get("from"))
            raw_target = edge.get("target", edge.get("to"))
            if raw_source is None or raw_target is None:
                continue
            source = str(raw_source)
            target = str(raw_target)

            src_node = node_by_id.get(source)
            tgt_node = node_by_id.get(target)
            if src_node is None or tgt_node is None:
                continue

            src_type = _neo4j_label(src_node.get("type"))
            tgt_type = _neo4j_label(tgt_node.get("type"))
            rel_type = _neo4j_rel_type(edge.get("label"))

            queries.append(
                f"MATCH (s:{src_type} {{id: '{_cypher_str(source)}'}}), "
                f"(t:{tgt_type} {{id: '{_cypher_str(target)}'}}) "
                f"MERGE (s)-[:{rel_type}]->(t);"
            )

        return "\n".join(queries)

    def export_file(self, filename: str) -> None:
        """Writes the cypher queries to a file (creating parent dirs if needed)"""
        from pathlib import Path

        parent = Path(filename).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)

        cypher_script = self.generate_cypher()
        with open(filename, "w", encoding="utf-8") as f:
            f.write(cypher_script)
