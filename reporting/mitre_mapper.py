"""OSINT EYE - MITRE ATT&CK Mapper"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class MitreFinding:
    technique_id: str
    technique_name: str
    tactic: str
    evidence: str
    severity: str
    source_module: str
    url: str = ""


class MitreMapper:
    """Map OSINT findings to MITRE ATT&CK techniques"""

    def __init__(self):
        self.findings: List[MitreFinding] = []

        self.mapping_rules = {
            "subdomains": [
                {
                    "technique_id": "T1595.002",
                    "technique_name": "Active Scanning: Vulnerability Scanning",
                    "tactic": "Reconnaissance",
                    "severity": "INFO",
                },
                {
                    "technique_id": "T1592",
                    "technique_name": "Gather Victim Host Information",
                    "tactic": "Reconnaissance",
                    "severity": "INFO",
                },
            ],
            "open_ports": [
                {
                    "technique_id": "T1046",
                    "technique_name": "Network Service Discovery",
                    "tactic": "Discovery",
                    "severity": "MEDIUM",
                },
            ],
            "services": [
                {
                    "technique_id": "T1592.002",
                    "technique_name": "Gather Victim Host Information: Software",
                    "tactic": "Reconnaissance",
                    "severity": "MEDIUM",
                },
            ],
            "technologies": [
                {
                    "technique_id": "T1592.002",
                    "technique_name": "Gather Victim Host Information: Software",
                    "tactic": "Reconnaissance",
                    "severity": "INFO",
                },
            ],
            "email_addresses": [
                {
                    "technique_id": "T1589.002",
                    "technique_name": "Gather Victim Identity Information: Email Addresses",
                    "tactic": "Reconnaissance",
                    "severity": "MEDIUM",
                },
            ],
            "cloud_buckets": [
                {
                    "technique_id": "T1530",
                    "technique_name": "Data from Cloud Storage",
                    "tactic": "Collection",
                    "severity": "HIGH",
                },
                {
                    "technique_id": "T1538",
                    "technique_name": "Cloud Service Dashboard",
                    "tactic": "Discovery",
                    "severity": "HIGH",
                },
            ],
            "sensitive_files": [
                {
                    "technique_id": "T1083",
                    "technique_name": "File and Directory Discovery",
                    "tactic": "Discovery",
                    "severity": "HIGH",
                },
                {
                    "technique_id": "T1552.001",
                    "technique_name": "Unsecured Credentials: Credentials In Files",
                    "tactic": "Credential Access",
                    "severity": "CRITICAL",
                },
            ],
            "api_keys_found": [
                {
                    "technique_id": "T1552.004",
                    "technique_name": "Unsecured Credentials: Private Keys",
                    "tactic": "Credential Access",
                    "severity": "CRITICAL",
                },
            ],
            "cves": [
                {
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                    "severity": "HIGH",
                },
            ],
            "wayback_interesting": [
                {
                    "technique_id": "T1593.002",
                    "technique_name": "Search Owned Websites: Search Engines",
                    "tactic": "Reconnaissance",
                    "severity": "LOW",
                },
            ],
            "github_leaks": [
                {
                    "technique_id": "T1593.001",
                    "technique_name": "Search Owned Websites: Code Repositories",
                    "tactic": "Reconnaissance",
                    "severity": "HIGH",
                },
                {
                    "technique_id": "T1552.001",
                    "technique_name": "Unsecured Credentials: Credentials In Files",
                    "tactic": "Credential Access",
                    "severity": "CRITICAL",
                },
            ],
            "cdn_waf": [
                {
                    "technique_id": "T1595.001",
                    "technique_name": "Active Scanning: Scanning IP Blocks",
                    "tactic": "Reconnaissance",
                    "severity": "INFO",
                },
            ],
            "tls_vulns": [
                {
                    "technique_id": "T1040",
                    "technique_name": "Network Sniffing",
                    "tactic": "Credential Access",
                    "severity": "HIGH",
                },
            ],
            "security_headers_missing": [
                {
                    "technique_id": "T1189",
                    "technique_name": "Drive-by Compromise",
                    "tactic": "Initial Access",
                    "severity": "MEDIUM",
                },
            ],
            "takeover_vulnerable": [
                {
                    "technique_id": "T1583.001",
                    "technique_name": "Acquire Infrastructure: Domains",
                    "tactic": "Resource Development",
                    "severity": "CRITICAL",
                },
            ],
        }

        self.tactic_colors = {
            "Reconnaissance": "#7f8c8d",
            "Resource Development": "#e67e22",
            "Initial Access": "#e74c3c",
            "Execution": "#c0392b",
            "Persistence": "#8e44ad",
            "Privilege Escalation": "#9b59b6",
            "Defense Evasion": "#3498db",
            "Credential Access": "#d35400",
            "Discovery": "#2ecc71",
            "Lateral Movement": "#1abc9c",
            "Collection": "#f39c12",
            "Command and Control": "#e84393",
            "Exfiltration": "#6c5ce7",
            "Impact": "#c0392b",
        }

    def map_findings(self, scan_results: Dict) -> List[MitreFinding]:
        """Map all scan findings to MITRE ATT&CK"""
        self.findings = []
        modules = scan_results.get("modules", {})

        if modules.get("dns", {}).get("subdomains"):
            count = len(modules["dns"]["subdomains"])
            self.findings.append(
                MitreFinding(
                    technique_id="T1595.002",
                    technique_name="Active Scanning: Vulnerability Scanning",
                    tactic="Reconnaissance",
                    evidence=f"{count} subdomains discovered",
                    severity="INFO",
                    source_module="dns",
                )
            )

        net = modules.get("network", {})
        open_ports = [s for s in net.get("services", []) if s.get("state") == "open"]
        if open_ports:
            port_list = ", ".join([str(s["port"]) for s in open_ports[:5]])
            self.findings.append(
                MitreFinding(
                    technique_id="T1046",
                    technique_name="Network Service Discovery",
                    tactic="Discovery",
                    evidence=f"Open ports: {port_list}",
                    severity="MEDIUM",
                    source_module="network",
                )
            )

        web = modules.get("web", {})
        techs = web.get("technologies", {}).get("technologies", [])
        if techs:
            self.findings.append(
                MitreFinding(
                    technique_id="T1592.002",
                    technique_name="Gather Victim Host Information: Software",
                    tactic="Reconnaissance",
                    evidence=f"Technologies: {', '.join(techs[:5])}",
                    severity="INFO",
                    source_module="web",
                )
            )

        endpoints = web.get("endpoints", {})
        sensitive = endpoints.get("sensitive", [])
        if sensitive:
            paths = ", ".join([s.get("path", "") for s in sensitive[:3]])
            self.findings.append(
                MitreFinding(
                    technique_id="T1552.001",
                    technique_name="Unsecured Credentials: Credentials In Files",
                    tactic="Credential Access",
                    evidence=f"Sensitive files: {paths}",
                    severity="CRITICAL",
                    source_module="web",
                )
            )

        cloud = modules.get("cloud_buckets", {})
        if cloud.get("public"):
            self.findings.append(
                MitreFinding(
                    technique_id="T1530",
                    technique_name="Data from Cloud Storage",
                    tactic="Collection",
                    evidence=f"{len(cloud['public'])} public cloud buckets",
                    severity="HIGH",
                    source_module="cloud_buckets",
                )
            )

        emails = modules.get("emails", {}).get("emails_found", [])
        if emails:
            self.findings.append(
                MitreFinding(
                    technique_id="T1589.002",
                    technique_name="Gather Victim Identity Information: Email Addresses",
                    tactic="Reconnaissance",
                    evidence=f"{len(emails)} emails discovered",
                    severity="MEDIUM",
                    source_module="emails",
                )
            )

        cves = modules.get("cve", {}).get("cves", [])
        if cves:
            def is_critical(c):
                sev = c.get("severity")
                if isinstance(sev, list) and len(sev) > 0:
                    try:
                        return float(sev[0].get("score", 0)) >= 9.0
                    except (ValueError, TypeError):
                        pass
                return False

            critical_cves = [c for c in cves if is_critical(c)]
            if critical_cves:
                self.findings.append(
                    MitreFinding(
                        technique_id="T1190",
                        technique_name="Exploit Public-Facing Application",
                        tactic="Initial Access",
                        evidence=f"{len(critical_cves)} critical CVEs: {', '.join([c.get('id', 'Unknown') for c in critical_cves[:3]])}",
                        severity="CRITICAL",
                        source_module="cve",
                    )
                )

        github = modules.get("github", {})
        if github.get("total_findings", 0) > 0:
            self.findings.append(
                MitreFinding(
                    technique_id="T1552.001",
                    technique_name="Unsecured Credentials: Credentials In Files",
                    tactic="Credential Access",
                    evidence=f"{github['total_findings']} potential leaks on GitHub",
                    severity="CRITICAL",
                    source_module="github",
                )
            )

        takeover = modules.get("takeover", {}).get("vulnerable", [])
        if takeover:
            self.findings.append(
                MitreFinding(
                    technique_id="T1583.001",
                    technique_name="Acquire Infrastructure: Domains",
                    tactic="Resource Development",
                    evidence=f"{len(takeover)} subdomains vulnerable to takeover",
                    severity="CRITICAL",
                    source_module="takeover",
                )
            )

        return self.findings

    def get_tactic_summary(self) -> Dict[str, List[MitreFinding]]:
        """Group findings by tactic"""
        tactics = {}
        for finding in self.findings:
            if finding.tactic not in tactics:
                tactics[finding.tactic] = []
            tactics[finding.tactic].append(finding)
        return tactics

    def get_heatmap_data(self) -> List[Dict]:
        """Generate heatmap data for visualization"""
        tactic_counts = {}
        for finding in self.findings:
            tactic = finding.tactic
            if tactic not in tactic_counts:
                tactic_counts[tactic] = {
                    "count": 0,
                    "max_severity": "INFO",
                    "techniques": set(),
                }
            tactic_counts[tactic]["count"] += 1
            tactic_counts[tactic]["techniques"].add(finding.technique_id)

            severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if severity_order.index(finding.severity) > severity_order.index(
                tactic_counts[tactic]["max_severity"]
            ):
                tactic_counts[tactic]["max_severity"] = finding.severity

        return [
            {
                "tactic": tactic,
                "count": data["count"],
                "max_severity": data["max_severity"],
                "technique_count": len(data["techniques"]),
                "color": self.tactic_colors.get(tactic, "#95a5a6"),
            }
            for tactic, data in tactic_counts.items()
        ]

    def export_json(self) -> Dict:
        """Export MITRE mapping as JSON"""
        return {
            "findings": [
                {
                    "technique_id": f.technique_id,
                    "technique_name": f.technique_name,
                    "tactic": f.tactic,
                    "evidence": f.evidence,
                    "severity": f.severity,
                    "source_module": f.source_module,
                }
                for f in self.findings
            ],
            "tactic_summary": {
                tactic: [
                    {
                        "technique_id": f.technique_id,
                        "name": f.technique_name,
                        "severity": f.severity,
                    }
                    for f in findings
                ]
                for tactic, findings in self.get_tactic_summary().items()
            },
            "heatmap": self.get_heatmap_data(),
            "total_findings": len(self.findings),
            "critical_count": len(
                [f for f in self.findings if f.severity == "CRITICAL"]
            ),
            "high_count": len([f for f in self.findings if f.severity == "HIGH"]),
        }

    def export_navigator_layer(self) -> Dict:
        """Export as MITRE ATT&CK Navigator layer"""
        techniques = []
        for finding in self.findings:
            score = {
                "CRITICAL": 100,
                "HIGH": 75,
                "MEDIUM": 50,
                "LOW": 25,
                "INFO": 10,
            }.get(finding.severity, 0)
            techniques.append(
                {
                    "techniqueID": finding.technique_id.split(".")[0],
                    "subID": finding.technique_id.split(".")[1]
                    if "." in finding.technique_id
                    else None,
                    "score": score,
                    "color": "",
                    "comment": finding.evidence,
                    "enabled": True,
                    "metadata": [
                        {"name": "Source", "value": finding.source_module},
                        {"name": "Severity", "value": finding.severity},
                    ],
                }
            )

        return {
            "name": f"OSINT EYE - Attack Surface Mapping",
            "versions": {
                "attack": "15",
                "navigator": "5.0.0",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": "Generated by OSINT EYE",
            "filters": {"platforms": []},
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
            },
            "hideDisabled": True,
            "techniques": techniques,
        }

    def generate_summary_table(self) -> str:
        """Generate a text summary table"""
        if not self.findings:
            return "No MITRE ATT&CK findings."

        lines = [
            "MITRE ATT&CK Mapping Summary",
            "=" * 80,
            f"{'Technique':<15} {'Name':<50} {'Tactic':<20} {'Severity':<10}",
            "-" * 80,
        ]

        for f in sorted(
            self.findings,
            key=lambda x: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(
                x.severity
            ),
            reverse=True,
        ):
            lines.append(
                f"{f.technique_id:<15} {f.technique_name:<50} {f.tactic:<20} {f.severity:<10}"
            )

        lines.append("-" * 80)
        lines.append(f"Total: {len(self.findings)} findings")
        lines.append(
            f"Critical: {len([f for f in self.findings if f.severity == 'CRITICAL'])}"
        )
        lines.append(f"High: {len([f for f in self.findings if f.severity == 'HIGH'])}")

        return "\n".join(lines)


if __name__ == "__main__":
    mapper = MitreMapper()

    test_results = {
        "modules": {
            "dns": {"subdomains": ["www.example.com", "api.example.com"]},
            "network": {"services": [{"port": 80, "state": "open", "service": "http"}]},
            "emails": {"emails_found": ["admin@example.com"]},
            "cloud_buckets": {"public": [{"url": "s3://example-bucket"}]},
            "cve": {
                "cves": [
                    {
                        "id": "CVE-2024-1234",
                        "severity": [{"score": 9.8, "severity": "CRITICAL"}],
                    }
                ]
            },
            "takeover": {"vulnerable": [{"subdomain": "old.example.com"}]},
        }
    }

    findings = mapper.map_findings(test_results)
    print(mapper.generate_summary_table())
    print("\n" + json.dumps(mapper.export_json(), indent=2))
