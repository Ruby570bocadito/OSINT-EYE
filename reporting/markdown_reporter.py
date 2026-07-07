"""OSINT EYE - Markdown Report Generator"""

import json
from datetime import datetime
from typing import Dict, List


class MarkdownReporter:
    """Generate professional Markdown reports"""

    def __init__(self):
        self.report_data = {}

    def load_results(self, results: Dict):
        """Load scan results"""
        self.report_data = results

    def generate(self, output_file=None) -> str:
        """Generate full Markdown report"""
        if not output_file:
            target = self.report_data.get("target", "unknown")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"report_{target}_{timestamp}.md"

        report = self._build_report()

        with open(output_file, "w") as f:
            f.write(report)

        print(f"[+] Report saved to: {output_file}")
        return output_file

    def _build_report(self) -> str:
        """Build the full report"""
        sections = [
            self._header(),
            self._executive_summary(),
            self._attack_surface_score(),
            self._dns_findings(),
            self._network_findings(),
            self._web_findings(),
            self._cloud_findings(),
            self._email_findings(),
            self._cve_findings(),
            self._correlation_findings(),
            self._recommendations(),
            self._footer(),
        ]
        return "\n\n".join(sections)

    def _header(self) -> str:
        target = self.report_data.get("target", "Unknown")
        date = self.report_data.get("scan_date", datetime.now().isoformat())
        depth = self.report_data.get("depth", "normal")

        return f"""# OSINT EYE - Reconnaissance Report

| Field | Value |
|-------|-------|
| **Target** | {target} |
| **Date** | {date} |
| **Scan Depth** | {depth} |
| **Tool** | OSINT EYE v1.0 |
| **Classification** | CONFIDENTIAL |

---

## Disclaimer

This report was generated for authorized security assessment purposes only.
All findings should be handled according to your organization's security policies.
"""

    def _executive_summary(self) -> str:
        modules = self.report_data.get("modules", {})

        dns_count = len(modules.get("dns", {}).get("subdomains", []))
        perm_count = modules.get("permutation", {}).get("total_found", 0)
        cert_count = len(modules.get("certs", {}).get("subdomains", []))
        net_services = modules.get("network", {}).get("services", [])
        open_ports = len([s for s in net_services if s.get("state") == "open"])
        web_techs = (
            modules.get("web", {}).get("technologies", {}).get("technologies", [])
        )
        email_count = len(modules.get("emails", {}).get("emails_found", []))
        bucket_count = len(modules.get("cloud_buckets", {}).get("found", []))
        cve_count = len(modules.get("cve", {}).get("cves", []))

        return f"""## Executive Summary

A comprehensive reconnaissance assessment was performed against **{self.report_data.get("target", "the target")}**.
The following key findings were identified:

- **{dns_count + perm_count}** subdomains discovered
- **{cert_count}** additional subdomains via Certificate Transparency
- **{open_ports}** open ports with active services
- **{len(web_techs)}** web technologies identified ({", ".join(web_techs[:5]) if web_techs else "none"})
- **{email_count}** email addresses enumerated
- **{bucket_count}** cloud storage buckets found
- **{cve_count}** potential CVEs identified
"""

    def _attack_surface_score(self) -> str:
        corr = self.report_data.get("correlation", {})
        score = corr.get("attack_surface_score", {})

        if not score:
            return "## Attack Surface Score\n\nNo correlation data available."

        severity = score.get("severity", "Unknown")
        score_val = score.get("score", 0)
        factors = score.get("factors", [])

        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
        }.get(severity, "⚪")

        factors_md = (
            "\n".join(f"- {f}" for f in factors)
            if factors
            else "- No factors identified"
        )

        return f"""## Attack Surface Score

{severity_emoji} **Score: {score_val}/100** - **{severity}**

### Contributing Factors

{factors_md}
"""

    def _dns_findings(self) -> str:
        dns = self.report_data.get("modules", {}).get("dns", {})

        if not dns:
            return "## DNS Findings\n\nNo DNS data available."

        lines = ["## DNS Findings\n"]

        records = dns.get("records", {})
        if records:
            lines.append("### DNS Records\n")
            lines.append("| Type | Value |")
            lines.append("|------|-------|")
            for rtype, values in records.items():
                if values:
                    lines.append(f"| {rtype} | {', '.join(values[:5])} |")

        subdomains = dns.get("subdomains", [])
        if subdomains:
            lines.append(f"\n### Subdomains ({len(subdomains)} found)\n")
            for sub in subdomains[:20]:
                lines.append(f"- `{sub}`")
            if len(subdomains) > 20:
                lines.append(f"\n... and {len(subdomains) - 20} more")

        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        if spf or dmarc:
            lines.append("\n### Email Security\n")
            if spf:
                lines.append(
                    f"- **SPF**: {'Configured' if spf.get('exists') else 'Not found'}"
                )
            if dmarc:
                lines.append(
                    f"- **DMARC**: {'Configured' if dmarc.get('exists') else 'Not found'}"
                )

        return "\n".join(lines)

    def _network_findings(self) -> str:
        network = self.report_data.get("modules", {}).get("network", {})

        if not network:
            return "## Network Findings\n\nNo network data available."

        lines = ["## Network Findings\n"]

        lines.append(f"**Host**: {network.get('host', 'Unknown')}")
        lines.append(f"**Status**: {network.get('status', 'Unknown')}\n")

        services = network.get("services", [])
        open_services = [s for s in services if s.get("state") == "open"]

        if open_services:
            lines.append("### Open Ports\n")
            lines.append("| Port | Protocol | Service | Version |")
            lines.append("|------|----------|---------|---------|")
            for svc in open_services:
                lines.append(
                    f"| {svc.get('port')} | {svc.get('protocol')} | {svc.get('service')} | {svc.get('version', '')} |"
                )

        return "\n".join(lines)

    def _web_findings(self) -> str:
        web = self.report_data.get("modules", {}).get("web", {})

        if not web:
            return "## Web Findings\n\nNo web data available."

        lines = ["## Web Findings\n"]

        techs = web.get("technologies", {}).get("technologies", [])
        if techs:
            lines.append("### Detected Technologies\n")
            for tech in techs:
                lines.append(f"- {tech}")

        endpoints = web.get("endpoints", {})
        found = endpoints.get("found", [])
        if found:
            lines.append(f"\n### Discovered Endpoints ({len(found)} found)\n")
            lines.append("| Status | Path | Size |")
            lines.append("|--------|------|------|")
            for ep in found[:20]:
                lines.append(
                    f"| {ep.get('status')} | {ep.get('path')} | {ep.get('size', 0)} |"
                )

        sensitive = endpoints.get("sensitive", [])
        if sensitive:
            lines.append(f"\n### Sensitive Files ({len(sensitive)} found)\n")
            for s in sensitive[:10]:
                lines.append(f"- ⚠️ `{s.get('path')}` [{s.get('status')}]")

        return "\n".join(lines)

    def _cloud_findings(self) -> str:
        cloud = self.report_data.get("modules", {}).get("cloud_buckets", {})

        if not cloud:
            return "## Cloud Findings\n\nNo cloud data available."

        lines = ["## Cloud Findings\n"]

        found = cloud.get("found", [])
        public = cloud.get("public", [])

        lines.append(f"- **Total buckets found**: {len(found)}")
        lines.append(f"- **Public buckets**: {len(public)}\n")

        if found:
            lines.append("### Bucket Details\n")
            lines.append("| URL | Provider | Public | Listable |")
            lines.append("|-----|----------|--------|----------|")
            for b in found:
                lines.append(
                    f"| {b.get('url', '')} | {b.get('provider', '')} | {'Yes' if b.get('public') else 'No'} | {'Yes' if b.get('listable') else 'No'} |"
                )

        cdn = self.report_data.get("modules", {}).get("cdn_waf", {})
        if cdn:
            lines.append("\n### CDN/WAF Detection\n")
            lines.append(f"- **CDN**: {cdn.get('cdn', 'None detected')}")
            lines.append(f"- **WAF**: {cdn.get('waf', 'None detected')}")

        return "\n".join(lines)

    def _email_findings(self) -> str:
        emails = self.report_data.get("modules", {}).get("emails", {})

        if not emails:
            return "## Email Findings\n\nNo email data available."

        lines = ["## Email Findings\n"]

        found = emails.get("emails_found", [])
        lines.append(f"**{len(found)}** email addresses discovered:\n")

        for email in found[:20]:
            lines.append(f"- `{email}`")

        return "\n".join(lines)

    def _cve_findings(self) -> str:
        cves = self.report_data.get("modules", {}).get("cve", {})

        if not cves:
            return "## CVE Findings\n\nNo CVE data available."

        lines = ["## CVE Findings\n"]

        cve_list = cves.get("cves", [])
        lines.append(f"**{len(cve_list)}** potential CVEs identified:\n")

        for cve in cve_list[:15]:
            cve_id = cve.get("id", "Unknown")
            severity = cve.get("severity", [{}])[0] if cve.get("severity") else {}
            score = severity.get("score", "N/A")
            sev = severity.get("severity", "N/A")
            desc = cve.get("description", "")[:150]

            lines.append(f"### {cve_id}")
            lines.append(f"- **Score**: {score} ({sev})")
            lines.append(f"- **Description**: {desc}...\n")

        return "\n".join(lines)

    def _correlation_findings(self) -> str:
        corr = self.report_data.get("correlation", {})

        if not corr:
            return "## Asset Correlation\n\nNo correlation data available."

        lines = ["## Asset Correlation\n"]

        shared = corr.get("shared_infrastructure", {})
        if shared:
            lines.append("### Shared Infrastructure\n")
            for ip, domains in shared.items():
                lines.append(f"- **{ip}**: {', '.join(domains)}")

        hidden = corr.get("hidden_relationships", [])
        if hidden:
            lines.append("\n### Hidden Relationships\n")
            for h in hidden:
                lines.append(f"- **{h['type']}**: {h['description']}")

        graph = corr.get("attack_graph", {})
        stats = graph.get("stats", {})
        if stats:
            lines.append(f"\n### Attack Graph")
            lines.append(f"- **Nodes**: {stats.get('total_nodes', 0)}")
            lines.append(f"- **Edges**: {stats.get('total_edges', 0)}")

        return "\n".join(lines)

    def _recommendations(self) -> str:
        lines = ["## Recommendations\n"]

        modules = self.report_data.get("modules", {})

        if modules.get("cloud_buckets", {}).get("public"):
            lines.append("### 🔴 Critical\n")
            lines.append(
                "1. **Public cloud buckets detected** - Immediately review and restrict access to exposed storage buckets"
            )

        if modules.get("takeover", {}).get("vulnerable"):
            lines.append(
                "2. **Subdomain takeover vulnerabilities** - Remove or claim dangling DNS records"
            )

        if modules.get("endpoints", {}).get("sensitive"):
            lines.append(
                "3. **Sensitive files exposed** - Remove or restrict access to configuration files, backups, and debug endpoints"
            )

        lines.append("\n### 🟠 High\n")
        lines.append("1. Review all open ports and close unnecessary services")
        lines.append("2. Implement WAF if not already in place")
        lines.append("3. Review and update SPF/DMARC records")

        lines.append("\n### 🟡 Medium\n")
        lines.append("1. Monitor for new subdomains regularly")
        lines.append("2. Implement certificate transparency monitoring")
        lines.append("3. Review exposed email addresses for potential phishing risk")

        lines.append("\n### 🟢 Low\n")
        lines.append("1. Implement rate limiting on all public APIs")
        lines.append("2. Remove unnecessary HTTP headers revealing technology stack")
        lines.append("3. Regularly update all discovered services to latest versions")

        return "\n".join(lines)

    def _footer(self) -> str:
        return f"""---

*Report generated by OSINT EYE v1.0 on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
*This report is confidential and intended for authorized personnel only.*
"""


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python markdown_reporter.py <results.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        results = json.load(f)

    reporter = MarkdownReporter()
    reporter.load_results(results)
    reporter.generate()
