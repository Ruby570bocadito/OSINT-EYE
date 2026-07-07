"""OSINT EYE - PDF Report Generator (ReportLab)"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    ListFlowable,
    ListItem,
    HRFlowable,
    Image,
    KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from datetime import datetime
from typing import Dict, List


class PDFReporter:
    """Generate professional PDF reports"""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._custom_styles()

    def _custom_styles(self):
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Title"],
                fontSize=28,
                textColor=colors.HexColor("#1a1a2e"),
                spaceAfter=5,
                alignment=TA_CENTER,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="ReportSubtitle",
                parent=self.styles["Normal"],
                fontSize=14,
                textColor=colors.HexColor("#7f8c8d"),
                spaceAfter=20,
                alignment=TA_CENTER,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading1"],
                fontSize=16,
                textColor=colors.HexColor("#0f3460"),
                spaceBefore=20,
                spaceAfter=10,
                borderWidth=1,
                borderColor=colors.HexColor("#00d2ff"),
                borderPadding=5,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SubSection",
                parent=self.styles["Heading2"],
                fontSize=13,
                textColor=colors.HexColor("#16213e"),
                spaceBefore=12,
                spaceAfter=6,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BodyText2",
                parent=self.styles["Normal"],
                fontSize=10,
                leading=14,
                spaceAfter=6,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="CodeBlock",
                parent=self.styles["Normal"],
                fontSize=9,
                fontName="Courier",
                textColor=colors.HexColor("#c0392b"),
                leftIndent=20,
            )
        )

    def generate(self, results: Dict, filename: str = None) -> str:
        if not filename:
            target = results.get("target", "unknown")
            filename = f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
            title=f"OSINT EYE Report - {results.get('target', '')}",
            author="OSINT EYE v2.0",
        )

        story = self._build_story(results)
        doc.build(story)

        print(f"[+] PDF report saved to: {filename}")
        return filename

    def _build_story(self, results: Dict) -> list:
        story = []
        target = results.get("target", "Unknown")
        date = results.get("scan_date", datetime.now().isoformat())
        modules = results.get("modules", {})

        story.append(Paragraph("OSINT EYE", self.styles["ReportTitle"]))
        story.append(
            Paragraph(
                "Attack Surface Intelligence Report", self.styles["ReportSubtitle"]
            )
        )
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#00d2ff"),
                spaceAfter=20,
            )
        )

        story.append(self._cover_page(target, date, modules))
        story.append(PageBreak())

        story.append(Paragraph("1. Executive Summary", self.styles["SectionHeader"]))
        story.append(self._executive_summary(modules, results))
        story.append(Spacer(1, 12))

        story.append(Paragraph("2. DNS Reconnaissance", self.styles["SectionHeader"]))
        story.append(self._dns_section(modules.get("dns", {})))
        story.append(Spacer(1, 12))

        story.append(Paragraph("3. Network Analysis", self.styles["SectionHeader"]))
        story.append(self._network_section(modules.get("network", {})))
        story.append(Spacer(1, 12))

        story.append(Paragraph("4. Web Intelligence", self.styles["SectionHeader"]))
        story.append(
            self._web_section(modules.get("web", {}), modules.get("endpoints", {}))
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("5. Cloud Infrastructure", self.styles["SectionHeader"]))
        story.append(
            self._cloud_section(
                modules.get("cloud_buckets", {}), modules.get("cdn_waf", {})
            )
        )
        story.append(Spacer(1, 12))

        story.append(
            Paragraph("6. Vulnerability Assessment", self.styles["SectionHeader"])
        )
        story.append(self._cve_section(modules.get("cve", {})))
        story.append(Spacer(1, 12))

        story.append(Paragraph("7. MITRE ATT&CK Mapping", self.styles["SectionHeader"]))
        story.append(self._mitre_section(results.get("mitre", {})))
        story.append(Spacer(1, 12))

        story.append(Paragraph("8. Attack Chains", self.styles["SectionHeader"]))
        story.append(self._chains_section(results.get("attack_chains", [])))
        story.append(Spacer(1, 12))

        story.append(Paragraph("9. Recommendations", self.styles["SectionHeader"]))
        story.append(self._recommendations_section(modules))
        story.append(PageBreak())

        story.append(Paragraph("10. Appendix", self.styles["SectionHeader"]))
        story.append(Paragraph("Scan Metadata", self.styles["SubSection"]))
        story.append(self._metadata_table(results))

        return story

    def _cover_page(self, target: str, date: str, modules: Dict):
        elements = []
        elements.append(Spacer(1, 100))

        data = [
            ["Target:", target],
            ["Date:", date[:10]],
            ["Depth:", "Full Reconnaissance"],
            ["Tool:", "OSINT EYE v2.0"],
            ["Classification:", "CONFIDENTIAL"],
        ]
        t = Table(data, colWidths=[2 * inch, 4 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 12),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0f3460")),
                    ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#333333")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#00d2ff")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(t)

        return KeepTogether(elements)

    def _executive_summary(self, modules: Dict, results: Dict):
        elements = []

        dns_count = len(modules.get("dns", {}).get("subdomains", []))
        perm_count = modules.get("permutation", {}).get("total_found", 0)
        net_services = modules.get("network", {}).get("services", [])
        open_ports = len([s for s in net_services if s.get("state") == "open"])
        email_count = len(modules.get("emails", {}).get("emails_found", []))
        cve_count = len(modules.get("cve", {}).get("cves", []))
        bucket_count = len(modules.get("cloud_buckets", {}).get("public", []))

        score = results.get("correlation", {}).get("attack_surface_score", {})

        elements.append(
            Paragraph(
                f"A comprehensive reconnaissance assessment identified <b>{dns_count + perm_count} subdomains</b>, "
                f"<b>{open_ports} open ports</b>, <b>{email_count} email addresses</b>, "
                f"<b>{cve_count} potential CVEs</b>, and <b>{bucket_count} public cloud buckets</b>.",
                self.styles["BodyText2"],
            )
        )

        if score:
            severity_color = {
                "CRITICAL": "#c0392b",
                "HIGH": "#e74c3c",
                "MEDIUM": "#f39c12",
                "LOW": "#3498db",
            }.get(score.get("severity", ""), "#95a5a6")
            elements.append(
                Paragraph(
                    f"<b>Attack Surface Score:</b> <font color='{severity_color}'>{score.get('score', 0)}/100 ({score.get('severity', 'Unknown')})</font>",
                    self.styles["BodyText2"],
                )
            )

        return KeepTogether(elements)

    def _dns_section(self, dns: Dict):
        elements = []

        subs = dns.get("subdomains", [])
        if subs:
            elements.append(
                Paragraph(
                    f"Subdomains Discovered: {len(subs)}", self.styles["SubSection"]
                )
            )
            data = [["#", "Subdomain"]]
            for i, sub in enumerate(subs[:50], 1):
                data.append([str(i), sub])
            t = Table(data, colWidths=[0.5 * inch, 5.5 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f0f4f8")],
                        ),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )
            elements.append(t)

        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        if spf or dmarc:
            elements.append(
                Paragraph("Email Security Configuration", self.styles["SubSection"])
            )
            email_data = [
                [
                    "SPF",
                    "Configured" if spf.get("exists") else "Not found",
                    spf.get("policy", ""),
                ],
                [
                    "DMARC",
                    "Configured" if dmarc.get("exists") else "Not found",
                    dmarc.get("policy", ""),
                ],
            ]
            t = Table(email_data, colWidths=[1.5 * inch, 2 * inch, 2.5 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0f3460")),
                        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
                    ]
                )
            )
            elements.append(t)

        return KeepTogether(elements)

    def _network_section(self, network: Dict):
        elements = []
        services = [s for s in network.get("services", []) if s.get("state") == "open"]

        if services:
            data = [["Port", "Protocol", "Service", "Version"]]
            for svc in services:
                data.append(
                    [
                        str(svc.get("port", "")),
                        svc.get("protocol", ""),
                        svc.get("service", ""),
                        svc.get("version", ""),
                    ]
                )
            t = Table(data, colWidths=[0.8 * inch, 1 * inch, 1.5 * inch, 2.7 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f0f4f8")],
                        ),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
                    ]
                )
            )
            elements.append(t)

        return KeepTogether(elements)

    def _web_section(self, web: Dict, endpoints: Dict):
        elements = []

        techs = web.get("technologies", {}).get("technologies", [])
        if techs:
            elements.append(
                Paragraph("Detected Technologies", self.styles["SubSection"])
            )
            elements.append(Paragraph(", ".join(techs), self.styles["BodyText2"]))

        sensitive = endpoints.get("sensitive", [])
        if sensitive:
            elements.append(
                Paragraph(
                    f"Sensitive Files ({len(sensitive)})", self.styles["SubSection"]
                )
            )
            data = [["Path", "Status"]]
            for s in sensitive[:20]:
                data.append([s.get("path", ""), str(s.get("status", ""))])
            t = Table(data, colWidths=[4 * inch, 1.5 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
                    ]
                )
            )
            elements.append(t)

        return KeepTogether(elements)

    def _cloud_section(self, cloud: Dict, cdn: Dict):
        elements = []

        found = cloud.get("found", [])
        if found:
            data = [["URL", "Provider", "Public"]]
            for b in found:
                data.append(
                    [
                        b.get("url", ""),
                        b.get("provider", ""),
                        "YES" if b.get("public") else "No",
                    ]
                )
            t = Table(data, colWidths=[3 * inch, 1.5 * inch, 1 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
                        ("BACKGROUND", (2, 1), (2, -1), colors.HexColor("#ffebee")),
                    ]
                )
            )
            elements.append(t)

        if cdn:
            elements.append(Paragraph("CDN/WAF Detection", self.styles["SubSection"]))
            elements.append(
                Paragraph(
                    f"CDN: {cdn.get('cdn', 'None detected')}", self.styles["BodyText2"]
                )
            )
            elements.append(
                Paragraph(
                    f"WAF: {cdn.get('waf', 'None detected')}", self.styles["BodyText2"]
                )
            )

        return KeepTogether(elements)

    def _cve_section(self, cves: Dict):
        elements = []
        cve_list = cves.get("cves", [])

        if cve_list:
            data = [["CVE ID", "Score", "Severity", "Description"]]
            for cve in cve_list[:20]:
                sev = cve.get("severity", [{}])[0] if cve.get("severity") else {}
                data.append(
                    [
                        cve.get("id", ""),
                        str(sev.get("score", "")),
                        sev.get("severity", ""),
                        cve.get("description", "")[:80],
                    ]
                )
            t = Table(data, colWidths=[1.2 * inch, 0.6 * inch, 0.8 * inch, 3.4 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f0f4f8")],
                        ),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
                    ]
                )
            )
            elements.append(t)
        else:
            elements.append(Paragraph("No CVEs identified.", self.styles["BodyText2"]))

        return KeepTogether(elements)

    def _mitre_section(self, mitre: Dict):
        elements = []
        findings = mitre.get("findings", [])

        if findings:
            data = [["Technique", "Name", "Tactic", "Severity"]]
            for f in findings:
                data.append(
                    [
                        f["technique_id"],
                        f["technique_name"][:40],
                        f["tactic"],
                        f["severity"],
                    ]
                )
            t = Table(data, colWidths=[1 * inch, 2.5 * inch, 1.3 * inch, 1 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#f0f4f8")],
                        ),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ddd")),
                    ]
                )
            )
            elements.append(t)

        return KeepTogether(elements)

    def _chains_section(self, chains: List):
        elements = []

        for chain in chains[:5]:
            elements.append(
                Paragraph(
                    f"{chain.get('name', '')} (Risk: {chain.get('risk_score', 0)})",
                    self.styles["SubSection"],
                )
            )
            for step in chain.get("steps", []):
                elements.append(
                    Paragraph(
                        f"<b>Step {step['step']}:</b> {step['action']}",
                        self.styles["BodyText2"],
                    )
                )

        return KeepTogether(elements)

    def _recommendations_section(self, modules: Dict):
        elements = []

        critical = []
        high = []
        medium = []

        if modules.get("cloud_buckets", {}).get("public"):
            critical.append(
                "Immediately restrict access to public cloud storage buckets"
            )
        if modules.get("takeover", {}).get("vulnerable"):
            critical.append(
                "Fix subdomain takeover vulnerabilities by removing dangling DNS records"
            )
        if modules.get("endpoints", {}).get("sensitive"):
            critical.append(
                "Remove or restrict access to exposed sensitive files and configuration"
            )
        if modules.get("github", {}).get("total_findings", 0) > 0:
            critical.append(
                "Rotate all credentials found in public GitHub repositories"
            )

        high.append("Implement Web Application Firewall (WAF) if not already in place")
        high.append("Review and harden all open ports and services")
        high.append("Implement SPF, DMARC, and DKIM for email security")

        medium.append("Implement continuous subdomain monitoring")
        medium.append("Regular vulnerability scanning and patch management")
        medium.append("Implement rate limiting on all public APIs")

        if critical:
            elements.append(Paragraph("Critical", self.styles["SubSection"]))
            for item in critical:
                elements.append(Paragraph(f"• {item}", self.styles["BodyText2"]))

        if high:
            elements.append(Paragraph("High", self.styles["SubSection"]))
            for item in high:
                elements.append(Paragraph(f"• {item}", self.styles["BodyText2"]))

        if medium:
            elements.append(Paragraph("Medium", self.styles["SubSection"]))
            for item in medium:
                elements.append(Paragraph(f"• {item}", self.styles["BodyText2"]))

        return KeepTogether(elements)

    def _metadata_table(self, results: Dict):
        data = [
            ["Target", results.get("target", "")],
            ["Scan Date", results.get("scan_date", "")],
            ["Depth", results.get("depth", "")],
            ["Tool", "OSINT EYE v2.0"],
            ["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Classification", "CONFIDENTIAL"],
        ]
        t = Table(data, colWidths=[2 * inch, 4 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0f3460")),
                    ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#ddd")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return t


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python pdf_reporter.py <results.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        results = json.load(f)

    reporter = PDFReporter()
    reporter.generate(results)
