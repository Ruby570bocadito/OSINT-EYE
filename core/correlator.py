"""OSINT EYE - Asset Correlation Engine"""

import json
import hashlib
from typing import Dict, List, Set, Optional
from datetime import datetime
from collections import defaultdict


class AssetCorrelator:
    """Correlate assets across all OSINT modules"""

    def __init__(self):
        self.assets = defaultdict(set)
        self.relationships = []
        self.risk_map = {}

    def ingest_dns(self, dns_data: Dict):
        """Ingest DNS data"""
        domain = dns_data.get("domain", "")

        for subdomain in dns_data.get("subdomains", []):
            self.assets["subdomains"].add(subdomain)
            self._add_relationship("subdomain_of", subdomain, domain)

        for rtype, values in dns_data.get("records", {}).items():
            for value in values:
                if rtype == "A":
                    self.assets["ips"].add(value)
                    self._add_relationship("resolves_to", domain, value)
                elif rtype == "MX":
                    self.assets["mail_servers"].add(value)
                    self._add_relationship("mail_server", domain, value)
                elif rtype == "NS":
                    self.assets["nameservers"].add(value)
                    self._add_relationship("nameserver", domain, value)
                elif rtype == "TXT":
                    if "v=spf1" in value.lower():
                        self.assets["spf_records"].add(value)
                    elif "v=dmarc1" in value.lower():
                        self.assets["dmarc_records"].add(value)

    def ingest_certs(self, cert_data: Dict):
        """Ingest certificate data"""
        for cert in cert_data.get("certificates", []):
            domain = cert.get("domain", "")
            issuer = cert.get("issuer", "")

            if domain:
                self.assets["cert_domains"].add(domain)
                if issuer:
                    self.assets["issuers"].add(issuer)
                    self._add_relationship("issued_by", domain, issuer)

    def ingest_network(self, network_data: Dict):
        """Ingest network scan data"""
        host = network_data.get("host", "")
        self.assets["scanned_hosts"].add(host)

        for svc in network_data.get("services", []):
            if svc.get("state") == "open":
                port_key = f"{host}:{svc['port']}/{svc.get('protocol', '')}"
                self.assets["open_ports"].add(port_key)

                service_name = svc.get("service", "unknown")
                version = svc.get("version", "")
                product = svc.get("product", "")

                self.assets["services"].add(service_name)
                self._add_relationship("runs_on", port_key, host)

                if version:
                    self.assets["versions"].add(f"{service_name}:{version}")
                    self._add_relationship(
                        "version_of", f"{service_name}:{version}", service_name
                    )

    def ingest_wayback(self, wayback_data: Dict):
        """Ingest Wayback data"""
        domain = wayback_data.get("domain", "")

        for url_info in wayback_data.get("interesting_urls", []):
            url = url_info.get("url", "")
            if url:
                self.assets["interesting_urls"].add(url)
                self._add_relationship("archived_url_of", url, domain)

        for path in wayback_data.get("unique_paths", []):
            if path:
                self.assets["discovered_paths"].add(path)
                self._add_relationship("path_of", path, domain)

    def ingest_whois(self, whois_data: Dict):
        """Ingest WHOIS data"""
        domain = whois_data.get("domain", "")

        if whois_data.get("registrar"):
            self.assets["registrars"].add(whois_data["registrar"])
            self._add_relationship("registered_via", domain, whois_data["registrar"])

        for ns in whois_data.get("name_servers", []):
            self.assets["nameservers"].add(ns.lower())
            self._add_relationship("nameserver", domain, ns.lower())

        if whois_data.get("emails"):
            for email in whois_data["emails"]:
                self.assets["emails"].add(email)
                self._add_relationship("contact_email", domain, email)

    def _add_relationship(self, rel_type: str, source: str, target: str):
        """Add a relationship between assets"""
        self.relationships.append(
            {
                "type": rel_type,
                "source": source,
                "target": target,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def find_shared_infrastructure(self) -> Dict:
        """Find shared infrastructure across assets"""
        ip_to_domains = defaultdict(set)

        for rel in self.relationships:
            if rel["type"] == "resolves_to":
                ip_to_domains[rel["target"]].add(rel["source"])

        shared = {}
        for ip, domains in ip_to_domains.items():
            if len(domains) > 1:
                shared[ip] = sorted(list(domains))

        return shared

    def find_hidden_relationships(self) -> List[Dict]:
        """Find non-obvious relationships"""
        findings = []

        cdn_origins = self._detect_cdn_origins()
        if cdn_origins:
            findings.append(
                {
                    "type": "cdn_origin_exposure",
                    "description": "Possible CDN origin server exposed",
                    "details": cdn_origins,
                }
            )

        shared_mail = self._find_shared_mail_infrastructure()
        if shared_mail:
            findings.append(
                {
                    "type": "shared_mail_infrastructure",
                    "description": "Multiple domains share mail infrastructure",
                    "details": shared_mail,
                }
            )

        cert_overlap = self._find_cert_overlap()
        if cert_overlap:
            findings.append(
                {
                    "type": "certificate_overlap",
                    "description": "Certificates span multiple unexpected domains",
                    "details": cert_overlap,
                }
            )

        return findings

    def _detect_cdn_origins(self) -> Dict:
        """Detect if CDN origin IP is exposed"""
        cdn_indicators = ["cloudflare", "akamai", "fastly", "cloudfront", "incapsula"]

        for rel in self.relationships:
            if rel["type"] == "resolves_to":
                subdomain = rel["source"].lower()
                if any(cdn in subdomain for cdn in cdn_indicators):
                    return {"cdn_subdomain": rel["source"], "ip": rel["target"]}

        return {}

    def _find_shared_mail_infrastructure(self) -> Dict:
        """Find domains sharing mail servers"""
        mail_servers = defaultdict(set)

        for rel in self.relationships:
            if rel["type"] == "mail_server":
                mail_servers[rel["target"]].add(rel["source"])

        shared = {}
        for server, domains in mail_servers.items():
            if len(domains) > 1:
                shared[server] = sorted(list(domains))

        return shared

    def _find_cert_overlap(self) -> Dict:
        """Find certificates that cover unexpected domain combinations"""
        issuer_to_domains = defaultdict(set)

        for rel in self.relationships:
            if rel["type"] == "issued_by":
                issuer_to_domains[rel["target"]].add(rel["source"])

        overlap = {}
        for issuer, domains in issuer_to_domains.items():
            if len(domains) > 3:
                overlap[issuer] = sorted(list(domains))

        return overlap

    def calculate_attack_surface_score(self) -> Dict:
        """Calculate overall attack surface score"""
        score = 0
        factors = []

        subdomain_count = len(self.assets["subdomains"])
        score += min(subdomain_count * 2, 25)
        factors.append(f"{subdomain_count} subdomains")

        open_port_count = len(self.assets["open_ports"])
        score += min(open_port_count * 3, 30)
        factors.append(f"{open_port_count} open ports")

        service_count = len(self.assets["services"])
        score += min(service_count * 2, 20)
        factors.append(f"{service_count} unique services")

        interesting_url_count = len(self.assets["interesting_urls"])
        score += min(interesting_url_count * 1, 15)
        factors.append(f"{interesting_url_count} interesting historical URLs")

        email_count = len(self.assets["emails"])
        score += min(email_count * 2, 10)
        factors.append(f"{email_count} exposed emails")

        shared = self.find_shared_infrastructure()
        score += min(len(shared) * 5, 20)
        factors.append(f"{len(shared)} shared infrastructure points")

        score = min(score, 100)

        severity = "LOW"
        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"

        return {
            "score": score,
            "severity": severity,
            "factors": factors,
            "asset_counts": {k: len(v) for k, v in self.assets.items()},
        }

    def generate_attack_graph(self) -> Dict:
        """Generate attack surface graph data"""
        nodes = []
        edges = []
        node_ids = {}

        node_counter = 0

        for asset_type, assets in self.assets.items():
            for asset in assets:
                if asset not in node_ids:
                    node_ids[asset] = node_counter
                    nodes.append(
                        {
                            "id": node_counter,
                            "label": str(asset)[:50],
                            "type": asset_type,
                            "size": max(5, min(20, len(str(asset)) // 3)),
                        }
                    )
                    node_counter += 1

        for rel in self.relationships:
            source_id = node_ids.get(rel["source"])
            target_id = node_ids.get(rel["target"])

            if source_id is not None and target_id is not None:
                edges.append(
                    {
                        "from": source_id,
                        "to": target_id,
                        "label": rel["type"],
                        "arrows": "to",
                    }
                )

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "asset_types": list(self.assets.keys()),
            },
        }

    def export_report(self) -> Dict:
        """Export full correlation report"""
        return {
            "assets": {k: sorted(list(v)) for k, v in self.assets.items()},
            "relationships": self.relationships,
            "shared_infrastructure": self.find_shared_infrastructure(),
            "hidden_relationships": self.find_hidden_relationships(),
            "attack_surface_score": self.calculate_attack_surface_score(),
            "attack_graph": self.generate_attack_graph(),
            "generated_at": datetime.now().isoformat(),
        }


if __name__ == "__main__":
    correlator = AssetCorrelator()

    test_dns = {
        "domain": "example.com",
        "subdomains": ["www.example.com", "api.example.com", "mail.example.com"],
        "records": {
            "A": ["93.184.216.34"],
            "MX": ["mail.example.com"],
            "NS": ["ns1.example.com"],
        },
    }

    correlator.ingest_dns(test_dns)

    report = correlator.export_report()
    print(json.dumps(report, indent=2))
