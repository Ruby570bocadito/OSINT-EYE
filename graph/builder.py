"""OSINT EYE - Attack Surface Graph Builder & Visualizer"""

from core.logging_config import get_logger

import networkx as nx
from pyvis.network import Network
from typing import Dict, List, Set
from datetime import datetime

logger = get_logger(__name__)


def _node_tech_set(raw) -> Set[str]:
    """Normalize a technologies payload (dict/list/set) into a set of strings."""
    if isinstance(raw, dict):
        return set(raw.get("technologies") or [])
    if isinstance(raw, (set, list, tuple)):
        return set(raw)
    return set()


def _cve_score(cve: Dict) -> float:
    """Extract the CVSS score from a CVE entry ([{"score": x, ...}])."""
    severity = cve.get("severity")
    if isinstance(severity, list) and severity and isinstance(severity[0], dict):
        return float(severity[0].get("score") or 0)
    return 0.0


class GraphBuilder:
    """Build attack surface graph from OSINT data"""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_colors = {
            "domain": "#3498db",
            "subdomain": "#2ecc71",
            "ip": "#e74c3c",
            "port": "#f39c12",
            "service": "#9b59b6",
            "technology": "#1abc9c",
            "certificate": "#e67e22",
            "email": "#34495e",
            "vulnerability": "#c0392b",
            "cloud_bucket": "#27ae60",
            "endpoint": "#8e44ad",
            "nameserver": "#16a085",
            "mail_server": "#d35400",
            "registrar": "#7f8c8d",
            "issuer": "#f1c40f",
            "cdn": "#e84393",
            "waf": "#6c5ce7",
        }
        self.node_sizes = {
            "domain": 40,
            "subdomain": 30,
            "ip": 35,
            "port": 20,
            "service": 25,
            "technology": 20,
            "certificate": 25,
            "email": 15,
            "vulnerability": 30,
            "cloud_bucket": 25,
            "endpoint": 15,
            "nameserver": 20,
            "mail_server": 20,
            "registrar": 20,
            "issuer": 20,
            "cdn": 25,
            "waf": 25,
        }

    def ingest_all(self, scan_results: Dict):
        """Ingest all scan results into graph"""
        modules = scan_results.get("modules", {})

        if "dns" in modules:
            self._ingest_dns(modules["dns"])

        if "permutation" in modules:
            self._ingest_permutation(modules["permutation"])

        if "certs" in modules:
            self._ingest_certs(modules["certs"])

        if "network" in modules:
            self._ingest_network(modules["network"])

        if "whois" in modules:
            self._ingest_whois(modules["whois"])

        if "web" in modules:
            self._ingest_web(modules["web"])

        if "cloud_buckets" in modules:
            self._ingest_cloud(modules["cloud_buckets"])

        if "emails" in modules:
            self._ingest_emails(modules["emails"])

        if "cve" in modules:
            self._ingest_cves(modules["cve"])

        if "cdn_waf" in modules:
            self._ingest_cdn_waf(modules["cdn_waf"])

    def _add_node(self, node_id: str, node_type: str, label: str = None, **kwargs):
        """Add a node to the graph"""
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                label=label or node_id,
                type=node_type,
                color=self.node_colors.get(node_type, "#95a5a6"),
                size=self.node_sizes.get(node_type, 20),
                **kwargs,
            )

    def _add_edge(self, source: str, target: str, label: str = ""):
        """Add an edge to the graph.

        Endpoints are auto-registered as generic nodes if unseen, so edges
        never create attribute-less orphans (they render colorless/undefined).
        """
        if source == target:
            return
        if not self.graph.has_node(source):
            self._add_node(source, "unknown", str(source)[:50])
        if not self.graph.has_node(target):
            self._add_node(target, "unknown", str(target)[:50])
        if not self.graph.has_edge(source, target):
            self.graph.add_edge(source, target, label=label, title=label)

    def _ingest_dns(self, dns_data: Dict):
        """Ingest DNS data"""
        domain = dns_data.get("domain", "")
        if not domain:
            return

        self._add_node(domain, "domain", domain)

        for subdomain in dns_data.get("subdomains", []):
            self._add_node(subdomain, "subdomain", subdomain)
            self._add_edge(domain, subdomain, "has_subdomain")

        records = dns_data.get("records", {})
        for rtype, values in records.items():
            for value in values:
                if rtype == "A":
                    self._add_node(value, "ip", value)
                    self._add_edge(domain, value, "resolves_to")
                elif rtype == "MX":
                    self._add_node(value, "mail_server", value)
                    self._add_edge(domain, value, "mail_server")
                elif rtype == "NS":
                    self._add_node(value, "nameserver", value)
                    self._add_edge(domain, value, "nameserver")

    def _ingest_permutation(self, permutation_data: Dict):
        """Ingest resolved permutation subdomains (verified hosts).

        osint_eye stores them under modules["permutation"]; without this
        the interactive graph silently missed every permutation hit even
        though the correlator counted them.
        """
        domain = permutation_data.get("domain", "") or ""
        if not domain:
            return

        self._add_node(domain, "domain", domain)

        for subdomain in permutation_data.get("subdomains") or []:
            if not subdomain:
                continue
            self._add_node(subdomain, "subdomain", subdomain)
            self._add_edge(domain, subdomain, "has_subdomain")

    def _ingest_certs(self, cert_data: Dict):
        """Ingest certificate data"""
        for cert in cert_data.get("certificates", []):
            cert_domain = cert.get("domain", "")
            if not cert_domain:
                continue

            self._add_node(cert_domain, "subdomain", cert_domain)

            issuer = cert.get("issuer", "")
            if issuer:
                self._add_node(issuer, "issuer", issuer[:50])
                self._add_edge(cert_domain, issuer, "issued_by")

    def _ingest_network(self, network_data: Dict):
        """Ingest network scan data"""
        host = network_data.get("host", "")
        if not host:
            return

        self._add_node(host, "ip", host)

        for svc in network_data.get("services", []):
            port = svc.get("port")
            if svc.get("state") == "open" and port is not None:
                port_key = f"{host}:{port}"
                self._add_node(port_key, "port", f"Port {port}")
                self._add_edge(host, port_key, "has_port")

                service_name = svc.get("service", "unknown")
                self._add_node(service_name, "service", service_name)
                self._add_edge(port_key, service_name, "runs")

                version = svc.get("version", "")
                if version:
                    version_key = f"{service_name}:{version}"
                    self._add_node(version_key, "technology", version_key)
                    self._add_edge(port_key, version_key, "version")

    def _ingest_whois(self, whois_data: Dict):
        """Ingest WHOIS data"""
        domain = whois_data.get("domain", "")
        if not domain:
            return

        self._add_node(domain, "domain", domain)

        registrar = whois_data.get("registrar", "")
        if registrar:
            self._add_node(registrar, "registrar", registrar[:50])
            self._add_edge(domain, registrar, "registered_via")

        for ns in whois_data.get("name_servers", []):
            self._add_node(ns, "nameserver", ns)
            self._add_edge(domain, ns, "nameserver")

    def _ingest_web(self, web_data: Dict):
        """Ingest web scan data"""
        for tech in _node_tech_set(web_data.get("technologies")):
            self._add_node(tech, "technology", tech)

    def _ingest_cloud(self, cloud_data: Dict):
        """Ingest cloud bucket data"""
        for bucket in cloud_data.get("found", []):
            bucket_url = bucket.get("url", "")
            if bucket_url:
                self._add_node(bucket_url, "cloud_bucket", bucket_url[:60])
                provider = bucket.get("provider", "")
                if provider:
                    self._add_node(provider, "technology", provider)
                    self._add_edge(bucket_url, provider, "hosted_on")

    def _ingest_emails(self, email_data: Dict):
        """Ingest email data"""
        domain = email_data.get("domain", "") or ""
        for email in email_data.get("emails_found") or []:
            if not email:
                continue
            self._add_node(email, "email", email)
            if domain:
                self._add_edge(domain, email, "contact_email")

    def _ingest_cves(self, cve_data: Dict):
        """Ingest CVE data"""
        for cve in (cve_data.get("cves") or [])[:20]:
            cve_id = cve.get("id", "")
            if cve_id:
                score = _cve_score(cve)
                self._add_node(cve_id, "vulnerability", cve_id, score=score)

    def _ingest_cdn_waf(self, cdn_data: Dict):
        """Ingest CDN/WAF data"""
        if cdn_data.get("cdn"):
            self._add_node(cdn_data["cdn"], "cdn", cdn_data["cdn"])

        if cdn_data.get("waf"):
            self._add_node(cdn_data["waf"], "waf", cdn_data["waf"])

    def get_stats(self) -> Dict:
        """Get graph statistics"""
        type_counts = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")
            type_counts[node_type] = type_counts.get(node_type, 0) + 1

        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "node_types": type_counts,
            "density": nx.density(self.graph),
        }

    def find_critical_paths(self) -> List[Dict]:
        """Find critical attack paths"""
        paths = []

        domains = [
            n for n, d in self.graph.nodes(data=True) if d.get("type") == "domain"
        ]
        vulnerabilities = [
            n
            for n, d in self.graph.nodes(data=True)
            if d.get("type") == "vulnerability"
        ]

        for domain in domains:
            for vuln in vulnerabilities:
                try:
                    path = nx.shortest_path(self.graph, domain, vuln)
                    if len(path) <= 5:
                        paths.append(
                            {
                                "source": domain,
                                "target": vuln,
                                "path": path,
                                "length": len(path),
                            }
                        )
                except nx.NetworkXNoPath:
                    continue

        return sorted(paths, key=lambda x: x["length"])[:10]

    def export_json(self) -> Dict:
        """Export graph as JSON"""
        nodes = []
        for node, data in self.graph.nodes(data=True):
            nodes.append({"id": node, **data})

        edges = []
        for source, target, data in self.graph.edges(data=True):
            edges.append({"source": source, "target": target, **data})

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": self.get_stats(),
            "critical_paths": self.find_critical_paths(),
            "generated_at": datetime.now().isoformat(),
        }

    def export_html(self, filename=None):
        """Export interactive HTML visualization.

        Uses pyvis with inline (bundled) JS so the file is self-contained:
        no CDN calls and no extra lib/ folder next to the output. Safe for
        empty graphs (0 nodes).
        """
        if not filename:
            filename = "attack_surface_graph.html"

        try:
            net = Network(
                height="800px",
                width="100%",
                bgcolor="#14141f",
                font_color="#e0e0e8",
                directed=True,
                cdn_resources="in_line",
            )
        except TypeError:
            # Older pyvis without the cdn_resources argument.
            net = Network(
                height="800px",
                width="100%",
                bgcolor="#14141f",
                font_color="#e0e0e8",
                directed=True,
            )

        # Soft physics: gentle repulsion + heavier damping for a calm layout.
        net.set_options(
            """
            {
                "physics": {
                    "enabled": true,
                    "stabilization": {"iterations": 150, "fit": true},
                    "barnesHut": {
                        "gravitationalConstant": -2000,
                        "centralGravity": 0.4,
                        "springLength": 120,
                        "springConstant": 0.03,
                        "damping": 0.18,
                        "avoidOverlap": 0.4
                    }
                },
                "interaction": {
                    "hover": true,
                    "tooltipDelay": 200,
                    "zoomView": true,
                    "dragView": true,
                    "navigationButtons": true
                },
                "nodes": {
                    "shape": "dot",
                    "scaling": {"min": 10, "max": 40},
                    "font": {"size": 13, "color": "#e0e0e8", "face": "monospace"},
                    "borderWidth": 2,
                    "shadow": true
                },
                "edges": {
                    "width": 1,
                    "arrows": {"to": {"enabled": true, "scaleFactor": 0.6}},
                    "color": {"color": "#3d3d5c", "highlight": "#00d2ff", "hover": "#5c5c8a"},
                    "smooth": {"enabled": true, "type": "continuous"}
                }
            }
            """
        )

        for node, data in self.graph.nodes(data=True):
            net.add_node(
                node,
                label=str(data.get("label", node))[:30],
                color=data.get("color", "#95a5a6"),
                size=data.get("size", 20),
                title=f"{node}\nType: {data.get('type', 'unknown')}",
            )

        for source, target, data in self.graph.edges(data=True):
            net.add_edge(source, target, title=data.get("label", ""))

        # write_html() instead of show(): show() prints the filename bare
        # to stdout (pyvis quirk) and pollutes the CLI output.
        net.write_html(filename, notebook=False)

        # pyvis' template always injects two bootstrap CDN tags (only used by
        # the optional filter/select menus, which are disabled here). Strip
        # them so the exported HTML is fully self-contained/offline.
        try:
            import re

            with open(filename, "r", encoding="utf-8") as f:
                html = f.read()
            cleaned = re.sub(
                r"<(?:script|link)[^>]*bootstrap[^>]*>(?:\s*</script>)?",
                "",
                html,
                flags=re.IGNORECASE,
            )
            if cleaned != html:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(cleaned)
        except OSError as e:
            logger.warning("Could not strip CDN tags from %s: %s", filename, e)

        logger.info("Graph exported to: %s", filename)


class GraphAnalyzer:
    """Analyze attack surface graph"""

    def __init__(self, graph_builder: GraphBuilder):
        self.graph = graph_builder.graph

    def get_central_nodes(self, top_n: int = 10) -> List[Dict]:
        """Get most connected nodes"""
        centrality = nx.degree_centrality(self.graph)
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)

        results = []
        for node, score in sorted_nodes[:top_n]:
            data = self.graph.nodes[node]
            results.append(
                {
                    "node": node,
                    "type": data.get("type", "unknown"),
                    "centrality": round(score, 4),
                    "connections": self.graph.degree[node],
                }
            )

        return results

    def find_clusters(self) -> List[Dict]:
        """Find clusters in the graph"""
        try:
            components = list(nx.weakly_connected_components(self.graph))
            clusters = []

            for i, component in enumerate(components):
                clusters.append(
                    {
                        "cluster_id": i,
                        "size": len(component),
                        "nodes": list(component)[:20],
                    }
                )

            return sorted(clusters, key=lambda x: x["size"], reverse=True)
        except Exception:
            return []

    def get_attack_surface_summary(self) -> Dict:
        """Get attack surface summary"""
        type_counts = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")
            type_counts[node_type] = type_counts.get(node_type, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "type_counts": type_counts,
            "density": round(nx.density(self.graph), 4),
        }


if __name__ == "__main__":
    import json

    builder = GraphBuilder()

    test_data = {
        "modules": {
            "dns": {
                "domain": "example.com",
                "subdomains": ["www.example.com", "api.example.com"],
                "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
            },
            "network": {
                "host": "93.184.216.34",
                "services": [
                    {
                        "port": 80,
                        "state": "open",
                        "service": "http",
                        "version": "Apache 2.4",
                    },
                    {"port": 443, "state": "open", "service": "https"},
                ],
            },
        }
    }

    builder.ingest_all(test_data)
    print(json.dumps(builder.export_json(), indent=2))
