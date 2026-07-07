"""OSINT EYE - CSV & HTML Export"""

import csv
import io
from typing import Dict, List
from datetime import datetime


class CSVExporter:
    """Export scan results to CSV"""

    def export_subdomains(self, results: Dict, filename: str = None) -> str:
        if not filename:
            filename = f"subdomains_{results.get('target', 'unknown')}.csv"

        rows = []
        modules = results.get("modules", {})

        for sub in modules.get("dns", {}).get("subdomains", []):
            rows.append({"subdomain": sub, "source": "dns", "ip": ""})

        for sub in modules.get("certs", {}).get("subdomains", []):
            rows.append({"subdomain": sub, "source": "cert_transparency", "ip": ""})

        for sub in modules.get("permutation", {}).get("subdomains", []):
            rows.append({"subdomain": sub, "source": "permutation", "ip": ""})

        seen = set()
        unique_rows = []
        for row in rows:
            if row["subdomain"] not in seen:
                seen.add(row["subdomain"])
                unique_rows.append(row)

        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["subdomain", "source", "ip"])
            writer.writeheader()
            writer.writerows(unique_rows)

        return filename

    def export_ports(self, results: Dict, filename: str = None) -> str:
        if not filename:
            filename = f"ports_{results.get('target', 'unknown')}.csv"

        rows = []
        services = results.get("modules", {}).get("network", {}).get("services", [])

        for svc in services:
            rows.append(
                {
                    "host": results.get("modules", {})
                    .get("network", {})
                    .get("host", ""),
                    "port": svc.get("port", ""),
                    "protocol": svc.get("protocol", ""),
                    "service": svc.get("service", ""),
                    "version": svc.get("version", ""),
                    "state": svc.get("state", ""),
                }
            )

        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["host", "port", "protocol", "service", "version", "state"],
            )
            writer.writeheader()
            writer.writerows(rows)

        return filename

    def export_emails(self, results: Dict, filename: str = None) -> str:
        if not filename:
            filename = f"emails_{results.get('target', 'unknown')}.csv"

        emails = results.get("modules", {}).get("emails", {}).get("emails_found", [])

        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["email"])
            for email in emails:
                writer.writerow([email])

        return filename

    def export_cves(self, results: Dict, filename: str = None) -> str:
        if not filename:
            filename = f"cves_{results.get('target', 'unknown')}.csv"

        rows = []
        for cve in results.get("modules", {}).get("cve", {}).get("cves", []):
            sev = cve.get("severity", [{}])[0] if cve.get("severity") else {}
            rows.append(
                {
                    "cve_id": cve.get("id", ""),
                    "score": sev.get("score", ""),
                    "severity": sev.get("severity", ""),
                    "description": cve.get("description", "")[:200],
                }
            )

        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["cve_id", "score", "severity", "description"]
            )
            writer.writeheader()
            writer.writerows(rows)

        return filename

    def export_all(self, results: Dict, prefix: str = None) -> List[str]:
        if not prefix:
            prefix = f"osint_eye_{results.get('target', 'unknown')}"

        files = []
        files.append(self.export_subdomains(results, f"{prefix}_subdomains.csv"))
        files.append(self.export_ports(results, f"{prefix}_ports.csv"))
        files.append(self.export_emails(results, f"{prefix}_emails.csv"))
        files.append(self.export_cves(results, f"{prefix}_cves.csv"))

        return files


class HTMLReporter:
    """Generate HTML reports with embedded CSS"""

    def generate(self, results: Dict, filename: str = None) -> str:
        if not filename:
            filename = f"report_{results.get('target', 'unknown')}.html"

        html = self._build_html(results)

        with open(filename, "w") as f:
            f.write(html)

        print(f"[+] HTML report saved to: {filename}")
        return filename

    def _build_html(self, results: Dict) -> str:
        target = results.get("target", "Unknown")
        date = results.get("scan_date", datetime.now().isoformat())
        modules = results.get("modules", {})

        sections = []
        sections.append(self._html_header(target, date))
        sections.append(self._html_summary(modules))
        sections.append(self._html_dns(modules.get("dns", {})))
        sections.append(self._html_network(modules.get("network", {})))
        sections.append(self._html_web(modules.get("web", {})))
        sections.append(self._html_cloud(modules.get("cloud_buckets", {})))
        sections.append(self._html_emails(modules.get("emails", {})))
        sections.append(self._html_cves(modules.get("cve", {})))
        sections.append(self._html_footer())

        return "\n".join(sections)

    def _html_header(self, target: str, date: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT EYE Report - {target}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: #2c3e50; margin-top: 30px; }}
.card {{ background: white; border-radius: 8px; padding: 20px; margin: 15px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th {{ background: #3498db; color: white; padding: 10px; text-align: left; }}
td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
tr:hover {{ background: #f8f9fa; }}
.badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }}
.badge-critical {{ background: #c0392b; }}
.badge-high {{ background: #e74c3c; }}
.badge-medium {{ background: #f39c12; }}
.badge-low {{ background: #3498db; }}
.badge-info {{ background: #95a5a6; }}
.stat {{ display: inline-block; text-align: center; padding: 15px 25px; margin: 5px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
.stat-value {{ font-size: 32px; font-weight: bold; color: #3498db; }}
.stat-label {{ font-size: 14px; color: #7f8c8d; }}
.footer {{ text-align: center; color: #95a5a6; margin-top: 40px; padding: 20px; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>OSINT EYE - Reconnaissance Report</h1>
<p><strong>Target:</strong> {target} | <strong>Date:</strong> {date}</p>"""

    def _html_summary(self, modules: Dict) -> str:
        dns_count = len(modules.get("dns", {}).get("subdomains", []))
        perm_count = modules.get("permutation", {}).get("total_found", 0)
        net_services = modules.get("network", {}).get("services", [])
        open_ports = len([s for s in net_services if s.get("state") == "open"])
        email_count = len(modules.get("emails", {}).get("emails_found", []))
        cve_count = len(modules.get("cve", {}).get("cves", []))

        return f"""<div class="card">
<h2>Summary</h2>
<div class="stat"><div class="stat-value">{dns_count + perm_count}</div><div class="stat-label">Subdomains</div></div>
<div class="stat"><div class="stat-value">{open_ports}</div><div class="stat-label">Open Ports</div></div>
<div class="stat"><div class="stat-value">{email_count}</div><div class="stat-label">Emails</div></div>
<div class="stat"><div class="stat-value">{cve_count}</div><div class="stat-label">CVEs</div></div>
</div>"""

    def _html_dns(self, dns: Dict) -> str:
        if not dns:
            return ""

        html = '<div class="card"><h2>DNS Findings</h2>'

        subs = dns.get("subdomains", [])
        if subs:
            html += (
                f"<h3>Subdomains ({len(subs)})</h3><table><tr><th>Subdomain</th></tr>"
            )
            for sub in subs[:50]:
                html += f"<tr><td><code>{sub}</code></td></tr>"
            html += "</table>"

        html += "</div>"
        return html

    def _html_network(self, network: Dict) -> str:
        if not network:
            return ""

        html = '<div class="card"><h2>Network Findings</h2>'
        services = [s for s in network.get("services", []) if s.get("state") == "open"]

        if services:
            html += "<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>"
            for svc in services:
                html += f"<tr><td>{svc.get('port')}</td><td>{svc.get('protocol')}</td><td>{svc.get('service')}</td><td>{svc.get('version', '')}</td></tr>"
            html += "</table>"

        html += "</div>"
        return html

    def _html_web(self, web: Dict) -> str:
        if not web:
            return ""

        html = '<div class="card"><h2>Web Findings</h2>'

        techs = web.get("technologies", {}).get("technologies", [])
        if techs:
            html += f"<h3>Technologies</h3><p>{', '.join(techs)}</p>"

        sensitive = web.get("endpoints", {}).get("sensitive", [])
        if sensitive:
            html += f"<h3>Sensitive Files ({len(sensitive)})</h3><table><tr><th>Path</th><th>Status</th></tr>"
            for s in sensitive:
                html += f"<tr><td><code>{s.get('path')}</code></td><td>{s.get('status')}</td></tr>"
            html += "</table>"

        html += "</div>"
        return html

    def _html_cloud(self, cloud: Dict) -> str:
        if not cloud:
            return ""

        html = '<div class="card"><h2>Cloud Buckets</h2>'
        found = cloud.get("found", [])

        if found:
            html += "<table><tr><th>URL</th><th>Provider</th><th>Public</th></tr>"
            for b in found:
                badge = (
                    '<span class="badge badge-critical">PUBLIC</span>'
                    if b.get("public")
                    else '<span class="badge badge-info">Private</span>'
                )
                html += f"<tr><td>{b.get('url')}</td><td>{b.get('provider')}</td><td>{badge}</td></tr>"
            html += "</table>"

        html += "</div>"
        return html

    def _html_emails(self, emails: Dict) -> str:
        if not emails:
            return ""

        html = '<div class="card"><h2>Email Addresses</h2>'
        found = emails.get("emails_found", [])

        if found:
            html += "<table><tr><th>Email</th></tr>"
            for email in found:
                html += f"<tr><td>{email}</td></tr>"
            html += "</table>"

        html += "</div>"
        return html

    def _html_cves(self, cves: Dict) -> str:
        if not cves:
            return ""

        html = '<div class="card"><h2>CVEs</h2>'
        cve_list = cves.get("cves", [])

        if cve_list:
            html += "<table><tr><th>CVE</th><th>Score</th><th>Severity</th><th>Description</th></tr>"
            for cve in cve_list[:20]:
                sev = cve.get("severity", [{}])[0] if cve.get("severity") else {}
                score = sev.get("score", "N/A")
                severity = sev.get("severity", "N/A")
                badge_class = {
                    "CRITICAL": "critical",
                    "HIGH": "high",
                    "MEDIUM": "medium",
                    "LOW": "low",
                }.get(severity, "info")
                desc = cve.get("description", "")[:100]
                html += f"<tr><td>{cve.get('id')}</td><td>{score}</td><td><span class='badge badge-{badge_class}'>{severity}</span></td><td>{desc}</td></tr>"
            html += "</table>"

        html += "</div>"
        return html

    def _html_footer(self) -> str:
        return f"""<div class="footer">
<p>Generated by OSINT EYE v1.0 on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>CONFIDENTIAL - For authorized personnel only</p>
</div>
</div>
</body>
</html>"""


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python export.py <results.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        results = json.load(f)

    csv_exp = CSVExporter()
    files = csv_exp.export_all(results)
    print(f"CSV files: {files}")

    html_rep = HTMLReporter()
    html_rep.generate(results)
