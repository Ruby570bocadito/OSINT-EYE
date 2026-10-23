"""OSINT EYE - Markdown Report Generator"""

import json
from core.logging_config import get_logger
from datetime import datetime
from typing import Dict, List

logger = get_logger(__name__)


def _d(value) -> Dict:
    """Return value if dict else {} (defensive accessor for scan data)."""
    return value if isinstance(value, dict) else {}


def _l(value) -> List:
    """Return value if list else []."""
    return value if isinstance(value, list) else []


def _cve_sev(cve: Dict) -> Dict:
    """Normalise the many shapes a CVE 'severity' field can take."""
    sev = cve.get("severity")
    if isinstance(sev, list) and sev and isinstance(sev[0], dict):
        return sev[0]
    if isinstance(sev, dict):
        return sev
    return {}


class MarkdownReporter:
    """Generate professional Markdown reports.

    Works with minimal results (``{}`` is valid input); every section is
    emitted even when its module data is missing, so consumers (and tests)
    can always rely on the canonical headings.
    """

    def __init__(self):
        self.report_data: Dict = {}

    def load_results(self, results: Dict):
        """Load scan results (None-safe; non-dict input is ignored)."""
        self.report_data = results if isinstance(results, dict) else {}

    def build_text(self) -> str:
        """Build the full Markdown report and return it as text.

        In-memory variant of :meth:`generate` for consumers that don't
        want a file on disk (dashboard downloads, email bodies, API
        responses). Same output byte-for-byte as generate() writes.
        """
        return self._build_report()

    def generate(self, output_file=None) -> str:
        """Generate the Markdown report and return the output path."""
        if not output_file:
            target = self.report_data.get("target", "unknown")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"report_{target}_{timestamp}.md"

        report = self.build_text()

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)

        logger.info("Report saved to: %s", output_file)
        return output_file

    def _modules(self) -> Dict:
        return _d(self.report_data.get("modules"))

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
        target = self.report_data.get("target") or "Unknown"
        date = self.report_data.get("scan_date") or datetime.now().isoformat()
        depth = self.report_data.get("depth") or "normal"

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
        modules = self._modules()

        dns_count = len(_l(_d(modules.get("dns")).get("subdomains")))
        perm_count = _d(modules.get("permutation")).get("total_found", 0) or 0
        cert_count = len(_l(_d(modules.get("certs")).get("subdomains")))
        net_services = _l(_d(modules.get("network")).get("services"))
        open_ports = len([s for s in net_services if _d(s).get("state") == "open"])
        web_techs = _l(_d(_d(modules.get("web")).get("technologies")).get("technologies"))
        email_count = len(_l(_d(modules.get("emails")).get("emails_found")))
        bucket_count = len(_l(_d(modules.get("cloud_buckets")).get("found")))
        cve_count = len(_l(_d(modules.get("cve")).get("cves")))

        return f"""## Executive Summary

A comprehensive reconnaissance assessment was performed against **{self.report_data.get("target") or "the target"}**.
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
        corr = _d(self.report_data.get("correlation"))
        score = _d(corr.get("attack_surface_score"))

        if not score:
            return "## Attack Surface Score\n\nNo correlation data available."

        severity = str(score.get("severity", "Unknown"))
        score_val = score.get("score", 0)
        factors = _l(score.get("factors"))

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
        dns = _d(self._modules().get("dns"))

        lines = ["## DNS Findings\n"]

        if not dns:
            lines.append("No DNS data available.")
            return "\n".join(lines)

        records = _d(dns.get("records"))
        if records:
            lines.append("### DNS Records\n")
            lines.append("| Type | Value |")
            lines.append("|------|-------|")
            for rtype, values in records.items():
                if values:
                    if isinstance(values, str):
                        values = [values]
                    lines.append(f"| {rtype} | {', '.join(str(v) for v in list(values)[:5])} |")

        subdomains = _l(dns.get("subdomains"))
        if subdomains:
            lines.append(f"\n### Subdomains ({len(subdomains)} found)\n")
            for sub in subdomains[:20]:
                lines.append(f"- `{sub}`")
            if len(subdomains) > 20:
                lines.append(f"\n... and {len(subdomains) - 20} more")

        spf = _d(dns.get("spf"))
        dmarc = _d(dns.get("dmarc"))
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
        network = _d(self._modules().get("network"))

        lines = ["## Network Findings\n"]

        if not network:
            lines.append("No network data available.")
            return "\n".join(lines)

        lines.append(f"**Host**: {network.get('host', 'Unknown')}")
        lines.append(f"**Status**: {network.get('status', 'Unknown')}\n")

        services = _l(network.get("services"))
        open_services = [s for s in services if _d(s).get("state") == "open"]

        if open_services:
            lines.append("### Open Ports\n")
            lines.append("| Port | Protocol | Service | Version |")
            lines.append("|------|----------|---------|---------|")
            for svc in open_services:
                svc = _d(svc)
                lines.append(
                    f"| {svc.get('port', '')} | {svc.get('protocol', '')} | {svc.get('service', '')} | {svc.get('version', '')} |"
                )
        else:
            lines.append("No open ports identified.")

        return "\n".join(lines)

    def _web_findings(self) -> str:
        web = _d(self._modules().get("web"))
        alt_endpoints = _d(self._modules().get("endpoints"))

        if not web and not alt_endpoints:
            return "## Web Findings\n\nNo web data available."

        lines = ["## Web Findings\n"]

        techs = _l(_d(web.get("technologies")).get("technologies"))
        if techs:
            lines.append("### Detected Technologies\n")
            for tech in techs:
                lines.append(f"- {tech}")

        endpoints = _d(web.get("endpoints"))
        found = _l(endpoints.get("found"))
        # osint_eye stores discovery in modules["endpoints"]; prefer that shape
        if alt_endpoints:
            found = _l(alt_endpoints.get("found")) or found
        if found:
            lines.append(f"\n### Discovered Endpoints ({len(found)} found)\n")
            lines.append("| Status | Path | Size |")
            lines.append("|--------|------|------|")
            for ep in found[:20]:
                ep = _d(ep)
                lines.append(
                    f"| {ep.get('status', '')} | {ep.get('path', '')} | {ep.get('size', 0)} |"
                )

        sensitive = _l(endpoints.get("sensitive"))
        alt_sensitive = _l(alt_endpoints.get("sensitive"))
        if alt_sensitive:
            sensitive = alt_sensitive
        if sensitive:
            lines.append(f"\n### Sensitive Files ({len(sensitive)} found)\n")
            for s in sensitive[:10]:
                s = _d(s)
                lines.append(f"- ⚠️ `{s.get('path', '')}` [{s.get('status', '')}]")

        return "\n".join(lines)

    def _cloud_findings(self) -> str:
        cloud = _d(self._modules().get("cloud_buckets"))

        if not cloud:
            return "## Cloud Findings\n\nNo cloud data available."

        lines = ["## Cloud Findings\n"]

        found = _l(cloud.get("found"))
        public = _l(cloud.get("public"))

        lines.append(f"- **Total buckets found**: {len(found)}")
        lines.append(f"- **Public buckets**: {len(public)}\n")

        if found:
            lines.append("### Bucket Details\n")
            lines.append("| URL | Provider | Public | Listable |")
            lines.append("|-----|----------|--------|----------|")
            for b in found:
                b = _d(b)
                lines.append(
                    f"| {b.get('url', '')} | {b.get('provider', '')} | {'Yes' if b.get('public') else 'No'} | {'Yes' if b.get('listable') else 'No'} |"
                )

        cdn = _d(self._modules().get("cdn_waf"))
        if cdn:
            lines.append("\n### CDN/WAF Detection\n")
            lines.append(f"- **CDN**: {cdn.get('cdn', 'None detected')}")
            lines.append(f"- **WAF**: {cdn.get('waf', 'None detected')}")

        return "\n".join(lines)

    def _email_findings(self) -> str:
        emails = _d(self._modules().get("emails"))

        if not emails:
            return "## Email Findings\n\nNo email data available."

        lines = ["## Email Findings\n"]

        found = _l(emails.get("emails_found"))
        lines.append(f"**{len(found)}** email addresses discovered:\n")

        for email in found[:20]:
            lines.append(f"- `{email}`")

        return "\n".join(lines)

    def _cve_findings(self) -> str:
        cves = _d(self._modules().get("cve"))

        if not cves:
            return "## CVE Findings\n\nNo CVE data available."

        lines = ["## CVE Findings\n"]

        cve_list = _l(cves.get("cves"))
        lines.append(f"**{len(cve_list)}** potential CVEs identified:\n")

        for cve in cve_list[:15]:
            cve = _d(cve)
            cve_id = cve.get("id", "Unknown")
            severity = _cve_sev(cve)
            score = severity.get("score", "N/A")
            sev = severity.get("severity", "N/A")
            desc = str(cve.get("description", ""))[:150]

            lines.append(f"### {cve_id}")
            lines.append(f"- **Score**: {score} ({sev})")
            lines.append(f"- **Description**: {desc}...\n")

        return "\n".join(lines)

    def _correlation_findings(self) -> str:
        corr = _d(self.report_data.get("correlation"))

        if not corr:
            return "## Asset Correlation\n\nNo correlation data available."

        lines = ["## Asset Correlation\n"]

        shared = _d(corr.get("shared_infrastructure"))
        if shared:
            lines.append("### Shared Infrastructure\n")
            for ip, domains in shared.items():
                if isinstance(domains, list):
                    domains = ", ".join(str(d) for d in domains)
                lines.append(f"- **{ip}**: {domains}")

        hidden = _l(corr.get("hidden_relationships"))
        if hidden:
            lines.append("\n### Hidden Relationships\n")
            for h in hidden:
                h = _d(h)
                lines.append(f"- **{h.get('type', 'relation')}**: {h.get('description', '')}")

        stats = _d(_d(corr.get("attack_graph")).get("stats"))
        if stats:
            lines.append("\n### Attack Graph")
            lines.append(f"- **Nodes**: {stats.get('total_nodes', 0)}")
            lines.append(f"- **Edges**: {stats.get('total_edges', 0)}")

        return "\n".join(lines)

    def _recommendations(self) -> str:
        lines = ["## Recommendations\n"]

        modules = self._modules()

        critical_items = []
        if _l(_d(modules.get("cloud_buckets")).get("public")):
            critical_items.append(
                "**Public cloud buckets detected** - Immediately review and restrict access to exposed storage buckets"
            )
        if _l(_d(modules.get("takeover")).get("vulnerable")):
            critical_items.append(
                "**Subdomain takeover vulnerabilities** - Remove or claim dangling DNS records"
            )
        if _l(_d(modules.get("endpoints")).get("sensitive")):
            critical_items.append(
                "**Sensitive files exposed** - Remove or restrict access to configuration files, backups, and debug endpoints"
            )

        if critical_items:
            lines.append("### Critical\n")
            for i, item in enumerate(critical_items, 1):
                lines.append(f"{i}. {item}")

        lines.append("\n### High\n")
        lines.append("1. Review all open ports and close unnecessary services")
        lines.append("2. Implement WAF if not already in place")
        lines.append("3. Review and update SPF/DMARC records")

        lines.append("\n### Medium\n")
        lines.append("1. Monitor for new subdomains regularly")
        lines.append("2. Implement certificate transparency monitoring")
        lines.append("3. Review exposed email addresses for potential phishing risk")

        lines.append("\n### Low\n")
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
