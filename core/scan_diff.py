"""OSINT EYE - Scan Diff & Comparison Engine"""

import json
from typing import Dict, List, Set, Optional
from datetime import datetime


class ScanDiff:
    """Compare two scan results and identify changes"""

    def __init__(self):
        self.diff = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_ports": [],
            "closed_ports": [],
            "changed_services": [],
            "new_technologies": [],
            "removed_technologies": [],
            "new_emails": [],
            "new_cves": [],
            "new_cloud_buckets": [],
            "score_change": {"before": 0, "after": 0, "delta": 0},
        }

    def compare(self, old_results: Dict, new_results: Dict) -> Dict:
        """Compare two scan results"""
        old_modules = old_results.get("modules", {})
        new_modules = new_results.get("modules", {})

        self._diff_subdomains(old_modules, new_modules)
        self._diff_ports(old_modules, new_modules)
        self._diff_technologies(old_modules, new_modules)
        self._diff_emails(old_modules, new_modules)
        self._diff_cves(old_modules, new_modules)
        self._diff_cloud(old_modules, new_modules)
        self._diff_scores(old_results, new_results)

        return self.diff

    def _diff_subdomains(self, old: Dict, new: Dict):
        old_subs = set(old.get("dns", {}).get("subdomains", []))
        old_subs.update(old.get("certs", {}).get("subdomains", []))
        old_subs.update(old.get("permutation", {}).get("subdomains", []))

        new_subs = set(new.get("dns", {}).get("subdomains", []))
        new_subs.update(new.get("certs", {}).get("subdomains", []))
        new_subs.update(new.get("permutation", {}).get("subdomains", []))

        self.diff["new_subdomains"] = sorted(list(new_subs - old_subs))
        self.diff["removed_subdomains"] = sorted(list(old_subs - new_subs))

    def _diff_ports(self, old: Dict, new: Dict):
        old_services = {}
        for svc in old.get("network", {}).get("services", []):
            key = (svc.get("host"), svc.get("port"))
            old_services[key] = svc

        new_services = {}
        for svc in new.get("network", {}).get("services", []):
            key = (svc.get("host"), svc.get("port"))
            new_services[key] = svc

        old_keys = set(old_services.keys())
        new_keys = set(new_services.keys())

        for key in new_keys - old_keys:
            svc = new_services[key]
            self.diff["new_ports"].append(
                {
                    "host": key[0],
                    "port": key[1],
                    "service": svc.get("service"),
                    "version": svc.get("version"),
                }
            )

        for key in old_keys - new_keys:
            svc = old_services[key]
            self.diff["closed_ports"].append(
                {
                    "host": key[0],
                    "port": key[1],
                    "service": svc.get("service"),
                }
            )

        for key in old_keys & new_keys:
            old_svc = old_services[key]
            new_svc = new_services[key]
            if old_svc.get("version") != new_svc.get("version"):
                self.diff["changed_services"].append(
                    {
                        "host": key[0],
                        "port": key[1],
                        "service": new_svc.get("service"),
                        "old_version": old_svc.get("version"),
                        "new_version": new_svc.get("version"),
                    }
                )

    def _diff_technologies(self, old: Dict, new: Dict):
        old_techs_raw = old.get("web", {}).get("technologies", {})
        new_techs_raw = new.get("web", {}).get("technologies", {})

        if isinstance(old_techs_raw, dict):
            old_techs = set(old_techs_raw.get("technologies", []))
        elif isinstance(old_techs_raw, set):
            old_techs = old_techs_raw
        else:
            old_techs = set()

        if isinstance(new_techs_raw, dict):
            new_techs = set(new_techs_raw.get("technologies", []))
        elif isinstance(new_techs_raw, set):
            new_techs = new_techs_raw
        else:
            new_techs = set()

        self.diff["new_technologies"] = sorted(list(new_techs - old_techs))
        self.diff["removed_technologies"] = sorted(list(old_techs - new_techs))

    def _diff_emails(self, old: Dict, new: Dict):
        old_emails = set(old.get("emails", {}).get("emails_found", []))
        new_emails = set(new.get("emails", {}).get("emails_found", []))

        self.diff["new_emails"] = sorted(list(new_emails - old_emails))

    def _diff_cves(self, old: Dict, new: Dict):
        old_cves = {c.get("id") for c in old.get("cve", {}).get("cves", [])}
        new_cves = {c.get("id") for c in new.get("cve", {}).get("cves", [])}

        new_cve_list = []
        for cve in new.get("cve", {}).get("cves", []):
            if cve.get("id") in (new_cves - old_cves):
                new_cve_list.append(cve)

        self.diff["new_cves"] = new_cve_list

    def _diff_cloud(self, old: Dict, new: Dict):
        old_buckets = {
            b.get("url") for b in old.get("cloud_buckets", {}).get("found", [])
        }
        new_buckets = {
            b.get("url") for b in new.get("cloud_buckets", {}).get("found", [])
        }

        new_bucket_list = []
        for b in new.get("cloud_buckets", {}).get("found", []):
            if b.get("url") in (new_buckets - old_buckets):
                new_bucket_list.append(b)

        self.diff["new_cloud_buckets"] = new_bucket_list

    def _diff_scores(self, old: Dict, new: Dict):
        old_score = (
            old.get("correlation", {}).get("attack_surface_score", {}).get("score", 0)
        )
        new_score = (
            new.get("correlation", {}).get("attack_surface_score", {}).get("score", 0)
        )

        self.diff["score_change"] = {
            "before": old_score,
            "after": new_score,
            "delta": new_score - old_score,
        }

    def get_summary(self) -> str:
        lines = ["Scan Comparison Summary", "=" * 60]

        if self.diff["new_subdomains"]:
            lines.append(f"\n[+] {len(self.diff['new_subdomains'])} new subdomains:")
            for sub in self.diff["new_subdomains"][:10]:
                lines.append(f"    + {sub}")

        if self.diff["removed_subdomains"]:
            lines.append(
                f"\n[-] {len(self.diff['removed_subdomains'])} removed subdomains:"
            )
            for sub in self.diff["removed_subdomains"][:10]:
                lines.append(f"    - {sub}")

        if self.diff["new_ports"]:
            lines.append(f"\n[+] {len(self.diff['new_ports'])} new open ports:")
            for p in self.diff["new_ports"]:
                lines.append(f"    + {p['host']}:{p['port']} ({p.get('service', '')})")

        if self.diff["closed_ports"]:
            lines.append(f"\n[-] {len(self.diff['closed_ports'])} closed ports:")
            for p in self.diff["closed_ports"]:
                lines.append(f"    - {p['host']}:{p['port']} ({p.get('service', '')})")

        if self.diff["changed_services"]:
            lines.append(
                f"\n[~] {len(self.diff['changed_services'])} changed services:"
            )
            for s in self.diff["changed_services"]:
                lines.append(
                    f"    ~ {s['host']}:{s['port']} {s.get('service')}: {s.get('old_version')} -> {s.get('new_version')}"
                )

        if self.diff["new_technologies"]:
            lines.append(
                f"\n[+] New technologies: {', '.join(self.diff['new_technologies'])}"
            )

        if self.diff["new_emails"]:
            lines.append(f"\n[+] {len(self.diff['new_emails'])} new emails")

        if self.diff["new_cves"]:
            lines.append(f"\n[+] {len(self.diff['new_cves'])} new CVEs")

        if self.diff["new_cloud_buckets"]:
            lines.append(
                f"\n[+] {len(self.diff['new_cloud_buckets'])} new cloud buckets"
            )

        score = self.diff["score_change"]
        delta = score["delta"]
        arrow = "↑" if delta > 0 else "↓" if delta < 0 else "="
        lines.append(
            f"\n[Score] {score['before']} -> {score['after']} ({arrow}{abs(delta)})"
        )

        return "\n".join(lines)


class AttackChainBuilder:
    """Build attack chains from findings"""

    def __init__(self):
        self.chains = []

    def build(self, scan_results: Dict) -> List[Dict]:
        """Build potential attack chains"""
        self.chains = []
        modules = scan_results.get("modules", {})

        self._build_initial_access_chains(modules)
        self._build_credential_chains(modules)
        self._build_cloud_chains(modules)
        self._build_supply_chain(modules)

        self.chains.sort(key=lambda c: c.get("risk_score", 0), reverse=True)

        return self.chains

    def _build_initial_access_chains(self, modules: Dict):
        cves = modules.get("cve", {}).get("cves", [])
        services = modules.get("network", {}).get("services", [])
        subdomains = modules.get("dns", {}).get("subdomains", [])

        for cve in cves[:5]:
            sev = cve.get("severity", [{}])[0] if cve.get("severity") else {}
            score = sev.get("score", 0)

            if score >= 7.0:
                chain = {
                    "name": f"Exploit {cve.get('id')} on public service",
                    "risk_score": min(score * 10, 100),
                    "steps": [
                        {
                            "step": 1,
                            "action": f"Identify vulnerable service via port scan",
                            "evidence": f"{len([s for s in services if s.get('state') == 'open'])} open ports found",
                        },
                        {
                            "step": 2,
                            "action": f"Exploit {cve.get('id')} (CVSS {score})",
                            "evidence": cve.get("description", "")[:100],
                        },
                        {
                            "step": 3,
                            "action": "Gain initial access",
                            "evidence": "Public-facing service",
                        },
                    ],
                    "mitre_tactics": ["Initial Access"],
                    "difficulty": "Easy" if score >= 9.0 else "Medium",
                }
                self.chains.append(chain)

        takeover = modules.get("takeover", {}).get("vulnerable", [])
        for t in takeover:
            chain = {
                "name": f"Subdomain takeover: {t.get('subdomain', 'unknown')}",
                "risk_score": 85,
                "steps": [
                    {
                        "step": 1,
                        "action": "Identify dangling DNS record",
                        "evidence": t.get("subdomain", ""),
                    },
                    {
                        "step": 2,
                        "action": f"Claim resource on {t.get('service', 'cloud provider')}",
                        "evidence": t.get("signature", ""),
                    },
                    {
                        "step": 3,
                        "action": "Host malicious content or phishing page",
                        "evidence": "Trusted subdomain of target",
                    },
                ],
                "mitre_tactics": ["Resource Development", "Initial Access"],
                "difficulty": "Easy",
            }
            self.chains.append(chain)

    def _build_credential_chains(self, modules: Dict):
        emails = modules.get("emails", {}).get("emails_found", [])
        github = modules.get("github", {})
        web = modules.get("web", {})

        if github.get("total_findings", 0) > 0:
            chain = {
                "name": "Credential theft via GitHub leaks",
                "risk_score": 90,
                "steps": [
                    {
                        "step": 1,
                        "action": "Find leaked credentials on GitHub",
                        "evidence": f"{github['total_findings']} potential leaks",
                    },
                    {
                        "step": 2,
                        "action": "Validate credentials against target services",
                        "evidence": "Automated credential testing",
                    },
                    {
                        "step": 3,
                        "action": "Access internal systems",
                        "evidence": "Valid credentials",
                    },
                ],
                "mitre_tactics": ["Credential Access", "Initial Access"],
                "difficulty": "Easy",
            }
            self.chains.append(chain)

        if emails:
            chain = {
                "name": f"Phishing campaign targeting {len(emails)} employees",
                "risk_score": 65,
                "steps": [
                    {
                        "step": 1,
                        "action": "Enumerate employee email addresses",
                        "evidence": f"{len(emails)} emails discovered",
                    },
                    {
                        "step": 2,
                        "action": "Craft targeted phishing emails",
                        "evidence": "Use company branding and context",
                    },
                    {
                        "step": 3,
                        "action": "Capture credentials via cloned login page",
                        "evidence": "Subdomain takeover or lookalike domain",
                    },
                ],
                "mitre_tactics": ["Reconnaissance", "Credential Access"],
                "difficulty": "Medium",
            }
            self.chains.append(chain)

    def _build_cloud_chains(self, modules: Dict):
        buckets = modules.get("cloud_buckets", {}).get("public", [])

        for bucket in buckets:
            chain = {
                "name": f"Data exfiltration via public cloud bucket",
                "risk_score": 80,
                "steps": [
                    {
                        "step": 1,
                        "action": "Discover public cloud bucket",
                        "evidence": bucket.get("url", ""),
                    },
                    {
                        "step": 2,
                        "action": "Enumerate bucket contents",
                        "evidence": f"Provider: {bucket.get('provider', '')}",
                    },
                    {
                        "step": 3,
                        "action": "Download sensitive data",
                        "evidence": "Public read access",
                    },
                ],
                "mitre_tactics": ["Discovery", "Collection", "Exfiltration"],
                "difficulty": "Easy",
            }
            self.chains.append(chain)

    def _build_supply_chain(self, modules: Dict):
        techs_raw = modules.get("web", {}).get("technologies", {})
        if isinstance(techs_raw, dict):
            techs = techs_raw.get("technologies", [])
        elif isinstance(techs_raw, set):
            techs = list(techs_raw)
        else:
            techs = []

        known_vuln_stacks = {
            "WordPress": "Plugin/theme vulnerabilities common",
            "Magento": "Frequent e-commerce platform exploits",
            "Joomla": "Historical RCE vulnerabilities",
            "Drupal": "Drupalgeddon-style attacks",
        }

        for tech in techs:
            if tech in known_vuln_stacks:
                chain = {
                    "name": f"Supply chain attack via {tech}",
                    "risk_score": 70,
                    "steps": [
                        {
                            "step": 1,
                            "action": f"Identify {tech} installation",
                            "evidence": f"Technology: {tech}",
                        },
                        {
                            "step": 2,
                            "action": f"Research known {tech} vulnerabilities",
                            "evidence": known_vuln_stacks[tech],
                        },
                        {
                            "step": 3,
                            "action": "Exploit vulnerable plugin/theme",
                            "evidence": "Public exploits available",
                        },
                    ],
                    "mitre_tactics": ["Initial Access", "Execution"],
                    "difficulty": "Medium",
                }
                self.chains.append(chain)

    def get_summary(self) -> str:
        if not self.chains:
            return "No attack chains identified."

        lines = ["Attack Chain Analysis", "=" * 60]

        for i, chain in enumerate(self.chains, 1):
            lines.append(f"\n{'=' * 50}")
            lines.append(f"Chain #{i}: {chain['name']}")
            lines.append(
                f"Risk Score: {chain['risk_score']}/100 | Difficulty: {chain['difficulty']}"
            )
            lines.append(f"Tactics: {', '.join(chain['mitre_tactics'])}")
            lines.append("-" * 50)

            for step in chain["steps"]:
                lines.append(f"  Step {step['step']}: {step['action']}")
                lines.append(f"    Evidence: {step['evidence'][:80]}")

        return "\n".join(lines)


class BountyReporter:
    """Generate bug bounty ready reports"""

    def generate(self, scan_results: Dict, program_name: str = None) -> str:
        target = scan_results.get("target", "unknown")
        program = program_name or target
        modules = scan_results.get("modules", {})

        filename = f"bounty_report_{target}.md"

        techs = modules.get("web", {}).get("technologies", {})
        if isinstance(techs, dict):
            tech_list = techs.get("technologies", [])
        elif isinstance(techs, set):
            tech_list = list(techs)
        else:
            tech_list = []
        techs_str = ", ".join(tech_list[:5]) if tech_list else "None detected"

        report = f"""# Bug Bounty Reconnaissance Report - {program}

## Target Information
- **Program**: {program}
- **Target**: {target}
- **Date**: {scan_results.get("scan_date", datetime.now().isoformat())}
- **Tool**: OSINT EYE v1.0

## Executive Summary

This reconnaissance report identifies the attack surface of **{target}**.
All findings are derived from publicly available information and passive/active scanning techniques.

## Key Findings

### Attack Surface Overview
- **Subdomains**: {len(modules.get("dns", {}).get("subdomains", []))} discovered
- **Open Ports**: {len([s for s in modules.get("network", {}).get("services", []) if s.get("state") == "open"])}
- **Technologies**: {techs_str}
- **Email Addresses**: {len(modules.get("emails", {}).get("emails_found", []))} enumerated
- **Cloud Buckets**: {len(modules.get("cloud_buckets", {}).get("public", []))} public buckets found
- **CVEs**: {len(modules.get("cve", {}).get("cves", []))} potential vulnerabilities

## Critical Findings

"""
        critical_findings = []

        takeover = modules.get("takeover", {}).get("vulnerable", [])
        if takeover:
            critical_findings.append(f"""### Subdomain Takeover (Critical)
{len(takeover)} subdomain(s) vulnerable to takeover:
""")
            for t in takeover:
                critical_findings.append(
                    f"- `{t.get('subdomain')}` - {t.get('service')} ({t.get('signature')})"
                )

        buckets = modules.get("cloud_buckets", {}).get("public", [])
        if buckets:
            critical_findings.append(f"""### Public Cloud Storage Buckets (High)
{len(buckets)} public bucket(s) discovered:
""")
            for b in buckets:
                critical_findings.append(f"- `{b.get('url')}` ({b.get('provider')})")

        github = modules.get("github", {})
        if github.get("total_findings", 0) > 0:
            critical_findings.append(f"""### Leaked Credentials on GitHub (Critical)
{github["total_findings"]} potential credential leak(s) found in public repositories.

**Recommendation**: Immediately rotate all exposed credentials and remove them from repositories.
""")

        if not critical_findings:
            critical_findings.append(
                "No critical findings identified during this assessment."
            )

        report += "\n".join(critical_findings)

        report += f"""

## Recommendations

1. **Immediate**: Address all Critical and High severity findings
2. **Short-term**: Implement continuous subdomain monitoring
3. **Long-term**: Establish automated attack surface management

## Methodology

This assessment used the following techniques:
- DNS enumeration (bruteforce + permutation + certificate transparency)
- Network port scanning (Nmap)
- Web technology fingerprinting
- Cloud storage bucket discovery
- Public credential leak detection
- CVE correlation

---

*Report generated by OSINT EYE - For authorized security assessment only*
"""

        with open(filename, "w") as f:
            f.write(report)

        print(f"[+] Bounty report saved to: {filename}")
        return filename


if __name__ == "__main__":
    diff = ScanDiff()

    old = {
        "modules": {
            "dns": {"subdomains": ["www.example.com"]},
            "network": {
                "services": [
                    {
                        "host": "1.2.3.4",
                        "port": 80,
                        "state": "open",
                        "service": "http",
                        "version": "Apache",
                    }
                ]
            },
            "emails": {"emails_found": ["admin@example.com"]},
        },
        "correlation": {"attack_surface_score": {"score": 30}},
    }

    new = {
        "modules": {
            "dns": {
                "subdomains": ["www.example.com", "api.example.com", "dev.example.com"]
            },
            "network": {
                "services": [
                    {
                        "host": "1.2.3.4",
                        "port": 80,
                        "state": "open",
                        "service": "http",
                        "version": "Apache 2.4.50",
                    },
                    {
                        "host": "1.2.3.4",
                        "port": 443,
                        "state": "open",
                        "service": "https",
                    },
                ]
            },
            "emails": {"emails_found": ["admin@example.com", "dev@example.com"]},
        },
        "correlation": {"attack_surface_score": {"score": 55}},
    }

    result = diff.compare(old, new)
    print(diff.get_summary())
