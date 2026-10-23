"""OSINT EYE - PDF Report Generator (ReportLab)

Professional paginated PDF report. Handles empty results, arbitrary unicode
in scan data (non-latin1 characters are transliterated — the base-14 fonts
have a limited glyph set but generation never crashes) and long tables that
span multiple pages (headers repeat on every page).
"""

from core.logging_config import get_logger

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.enums import TA_CENTER
from datetime import datetime
from typing import Dict, List

logger = get_logger(__name__)


def _d(value) -> Dict:
    """Return value if dict else {} (defensive accessor for scan data)."""
    return value if isinstance(value, dict) else {}


def _l(value) -> List:
    """Return value if list else []."""
    return value if isinstance(value, list) else []


def safe(text) -> str:
    """Make arbitrary scan data safe for the base-14 PDF fonts.

    Non-encodable unicode and control characters are replaced instead of
    crashing reportlab's latin-1 encoder; XML/HTML entities are escaped so
    Paragraph markup cannot break on values like ``<script>``.
    """
    if text is None:
        return ""
    text = str(text)
    text = text.encode("latin-1", "replace").decode("latin-1")
    text = "".join(c for c in text if c >= " " or c in "\t")
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _cve_sev(cve: Dict) -> Dict:
    """Normalise the many shapes a CVE 'severity' field can take."""
    sev = cve.get("severity")
    if isinstance(sev, list) and sev and isinstance(sev[0], dict):
        return sev[0]
    if isinstance(sev, dict):
        return sev
    return {}


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

    # ── table helper ─────────────────────────────────────────────────────
    def _styled_table(self, header: List[str], rows: List[List[str]], col_widths) -> Table:
        """Zebra-striped table that repeats its header across pages."""
        data = [[safe(h) for h in header]]
        for row in rows:
            data.append([safe(cell) for cell in row])
        t = Table(data, colWidths=col_widths, repeatRows=1)
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
        return t

    # ── main entry ───────────────────────────────────────────────────────
    def generate(self, results: Dict, filename: str = None) -> str:
        """Build the PDF and return the output path (never raises on data)."""
        results = _d(results)
        if not filename:
            target = results.get("target") or "unknown"
            filename = f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
            title=f"OSINT EYE Report - {results.get('target') or ''}",
            author="OSINT EYE v2.0",
        )

        story = self._build_story(results)
        doc.build(story, onFirstPage=self._page_footer, onLaterPages=self._page_footer)

        logger.info("PDF report saved to: %s", filename)
        return filename

    @staticmethod
    def _page_footer(canvas, doc):
        """Page footer: confidentiality note + page numbers on every page."""
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#95a5a6"))
        canvas.drawString(
            72,
            40,
            "OSINT EYE - CONFIDENTIAL. For authorized personnel only.",
        )
        canvas.drawRightString(
            A4[0] - 72,
            40,
            f"Page {doc.page}",
        )
        canvas.restoreState()

    def _build_story(self, results: Dict) -> list:
        results = _d(results)
        target = results.get("target") or "Unknown"
        date = str(results.get("scan_date") or datetime.now().isoformat())
        depth = str(results.get("depth") or "full")
        modules = _d(results.get("modules"))

        story = []
        story.append(Paragraph("OSINT EYE", self.styles["ReportTitle"]))
        story.append(
            Paragraph("Attack Surface Intelligence Report", self.styles["ReportSubtitle"])
        )
        story.append(
            HRFlowable(
                width="100%",
                thickness=2,
                color=colors.HexColor("#00d2ff"),
                spaceAfter=20,
            )
        )

        story.append(self._cover_page(target, date, depth))
        story.append(PageBreak())

        story.append(Paragraph("1. Executive Summary", self.styles["SectionHeader"]))
        story.append(self._executive_summary(modules, results))
        story.append(Spacer(1, 12))

        story.append(Paragraph("2. DNS Reconnaissance", self.styles["SectionHeader"]))
        story.append(self._dns_section(_d(modules.get("dns"))))
        story.append(Spacer(1, 12))

        story.append(Paragraph("3. Network Analysis", self.styles["SectionHeader"]))
        story.append(self._network_section(_d(modules.get("network"))))
        story.append(Spacer(1, 12))

        story.append(Paragraph("4. Web Intelligence", self.styles["SectionHeader"]))
        story.append(
            self._web_section(_d(modules.get("web")), _d(modules.get("endpoints")))
        )
        story.append(Spacer(1, 12))

        story.append(Paragraph("5. Cloud Infrastructure", self.styles["SectionHeader"]))
        story.append(
            self._cloud_section(
                _d(modules.get("cloud_buckets")), _d(modules.get("cdn_waf"))
            )
        )
        story.append(Spacer(1, 12))

        story.append(
            Paragraph("6. Vulnerability Assessment", self.styles["SectionHeader"])
        )
        story.append(self._cve_section(_d(modules.get("cve"))))
        story.append(Spacer(1, 12))

        story.append(Paragraph("7. MITRE ATT&CK Mapping", self.styles["SectionHeader"]))
        story.append(self._mitre_section(_d(results.get("mitre"))))
        story.append(Spacer(1, 12))

        story.append(Paragraph("8. Attack Chains", self.styles["SectionHeader"]))
        story.append(self._chains_section(_l(results.get("attack_chains"))))
        story.append(Spacer(1, 12))

        story.append(Paragraph("9. Recommendations", self.styles["SectionHeader"]))
        story.append(self._recommendations_section(modules))
        story.append(PageBreak())

        story.append(Paragraph("10. Appendix", self.styles["SectionHeader"]))
        story.append(Paragraph("Scan Metadata", self.styles["SubSection"]))
        story.append(self._metadata_table(results))

        return story

    def _cover_page(self, target: str, date: str, depth: str):
        elements = [Spacer(1, 100)]

        data = [
            ["Target:", safe(target)],
            ["Date:", safe(date[:10])],
            ["Depth:", safe(depth.upper())],
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
        modules = _d(modules)
        results = _d(results)
        elements = []

        dns_count = len(_l(_d(modules.get("dns")).get("subdomains")))
        perm_count = _d(modules.get("permutation")).get("total_found", 0) or 0
        net_services = _l(_d(modules.get("network")).get("services"))
        open_ports = len([s for s in net_services if _d(s).get("state") == "open"])
        email_count = len(_l(_d(modules.get("emails")).get("emails_found")))
        cve_count = len(_l(_d(modules.get("cve")).get("cves")))
        bucket_count = len(_l(_d(modules.get("cloud_buckets")).get("public")))

        score = _d(_d(results.get("correlation")).get("attack_surface_score"))

        elements.append(
            Paragraph(
                safe(
                    f"A comprehensive reconnaissance assessment identified {dns_count + perm_count} subdomains, "
                    f"{open_ports} open ports, {email_count} email addresses, "
                    f"{cve_count} potential CVEs, and {bucket_count} public cloud buckets."
                ),
                self.styles["BodyText2"],
            )
        )

        if score:
            severity_color = {
                "CRITICAL": "#c0392b",
                "HIGH": "#e74c3c",
                "MEDIUM": "#f39c12",
                "LOW": "#3498db",
            }.get(str(score.get("severity", "")), "#95a5a6")
            elements.append(
                Paragraph(
                    safe(
                        f"<b>Attack Surface Score:</b> <font color='{severity_color}'>"
                        f"{score.get('score', 0)}/100 ({score.get('severity', 'Unknown')})</font>"
                    ),
                    self.styles["BodyText2"],
                )
            )

        return KeepTogether(elements)

    def _dns_section(self, dns: Dict):
        dns = _d(dns)
        elements = []

        subs = _l(dns.get("subdomains"))
        if subs:
            elements.append(
                Paragraph(f"Subdomains Discovered: {len(subs)}", self.styles["SubSection"])
            )
            elements.append(
                self._styled_table(
                    ["#", "Subdomain"],
                    [[str(i), sub] for i, sub in enumerate(subs[:50], 1)],
                    [0.5 * inch, 5.5 * inch],
                )
            )
        else:
            elements.append(
                Paragraph("No DNS data collected during this scan.", self.styles["BodyText2"])
            )

        spf = _d(dns.get("spf"))
        dmarc = _d(dns.get("dmarc"))
        if spf or dmarc:
            elements.append(
                Paragraph("Email Security Configuration", self.styles["SubSection"])
            )
            email_data = [
                [
                    "SPF",
                    "Configured" if spf.get("exists") else "Not found",
                    safe(spf.get("policy", "") or ""),
                ],
                [
                    "DMARC",
                    "Configured" if dmarc.get("exists") else "Not found",
                    safe(dmarc.get("policy", "") or ""),
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
        network = _d(network)
        services = [
            _d(s) for s in _l(network.get("services")) if _d(s).get("state") == "open"
        ]

        if not services:
            return Paragraph(
                "No open ports identified during the network scan.",
                self.styles["BodyText2"],
            )

        rows = [
            [
                svc.get("port", ""),
                svc.get("protocol", ""),
                svc.get("service", ""),
                svc.get("version", ""),
            ]
            for svc in services
        ]
        return self._styled_table(
            ["Port", "Protocol", "Service", "Version"],
            rows,
            [0.8 * inch, 1 * inch, 1.5 * inch, 2.7 * inch],
        )

    def _web_section(self, web: Dict, endpoints: Dict):
        elements = []
        web = _d(web)
        endpoints = _d(endpoints)

        techs = _l(_d(web.get("technologies")).get("technologies"))
        if techs:
            elements.append(
                Paragraph("Detected Technologies", self.styles["SubSection"])
            )
            elements.append(
                Paragraph(safe(", ".join(str(t) for t in techs)), self.styles["BodyText2"])
            )

        sensitive = _l(endpoints.get("sensitive"))
        if sensitive:
            elements.append(
                Paragraph(f"Sensitive Files ({len(sensitive)})", self.styles["SubSection"])
            )
            rows = []
            for s in sensitive[:20]:
                s = _d(s)
                rows.append([s.get("path", ""), str(s.get("status", ""))])
            elements.append(
                self._styled_table(["Path", "Status"], rows, [4 * inch, 1.5 * inch])
            )

        if not elements:
            elements.append(
                Paragraph("No web intelligence collected.", self.styles["BodyText2"])
            )
        return KeepTogether(elements)

    def _cloud_section(self, cloud: Dict, cdn: Dict):
        elements = []
        cloud = _d(cloud)
        cdn = _d(cdn)

        found = _l(cloud.get("found"))
        if found:
            rows = []
            for b in found:
                b = _d(b)
                rows.append(
                    [b.get("url", ""), b.get("provider", ""), "YES" if b.get("public") else "No"]
                )
            t = self._styled_table(
                ["URL", "Provider", "Public"], rows, [3 * inch, 1.5 * inch, 1 * inch]
            )
            t.setStyle(TableStyle([("BACKGROUND", (2, 1), (2, -1), colors.HexColor("#ffebee"))]))
            elements.append(t)

        if cdn:
            elements.append(Paragraph("CDN/WAF Detection", self.styles["SubSection"]))
            elements.append(
                Paragraph(
                    safe(f"CDN: {cdn.get('cdn') or 'None detected'}"),
                    self.styles["BodyText2"],
                )
            )
            elements.append(
                Paragraph(
                    safe(f"WAF: {cdn.get('waf') or 'None detected'}"),
                    self.styles["BodyText2"],
                )
            )

        if not elements:
            elements.append(
                Paragraph("No cloud infrastructure data collected.", self.styles["BodyText2"])
            )
        return KeepTogether(elements)

    def _cve_section(self, cves: Dict):
        cves = _d(cves)
        cve_list = _l(cves.get("cves"))

        if not cve_list:
            return Paragraph("No CVEs identified.", self.styles["BodyText2"])

        rows = []
        for cve in cve_list[:20]:
            cve = _d(cve)
            sev = _cve_sev(cve)
            rows.append(
                [
                    cve.get("id", ""),
                    str(sev.get("score", "")),
                    sev.get("severity", ""),
                    str(cve.get("description", ""))[:80],
                ]
            )
        return self._styled_table(
            ["CVE ID", "Score", "Severity", "Description"],
            rows,
            [1.2 * inch, 0.6 * inch, 0.8 * inch, 3.4 * inch],
        )

    def _mitre_section(self, mitre: Dict):
        mitre = _d(mitre)
        findings = _l(mitre.get("findings"))

        if not findings:
            return Paragraph(
                "No MITRE ATT&CK mappings were produced for this scan.",
                self.styles["BodyText2"],
            )

        rows = [
            [
                _d(f).get("technique_id", ""),
                str(_d(f).get("technique_name", ""))[:40],
                _d(f).get("tactic", ""),
                _d(f).get("severity", ""),
            ]
            for f in findings
        ]
        return self._styled_table(
            ["Technique", "Name", "Tactic", "Severity"],
            rows,
            [1 * inch, 2.5 * inch, 1.3 * inch, 1 * inch],
        )

    def _chains_section(self, chains: List):
        elements = []
        for chain in chains[:5]:
            chain = _d(chain)
            elements.append(
                Paragraph(
                    safe(f"{chain.get('name', 'chain')} (Risk: {chain.get('risk_score', 0)})"),
                    self.styles["SubSection"],
                )
            )
            for step in _l(chain.get("steps")):
                step = _d(step)
                elements.append(
                    Paragraph(
                        safe(
                            f"<b>Step {step.get('step', '?')}:</b> {step.get('action', '')}"
                        ),
                        self.styles["BodyText2"],
                    )
                )
        if not elements:
            elements.append(
                Paragraph("No attack chains identified.", self.styles["BodyText2"])
            )
        return KeepTogether(elements)

    def _recommendations_section(self, modules: Dict):
        modules = _d(modules)
        elements = []

        critical = []
        if _l(_d(modules.get("cloud_buckets")).get("public")):
            critical.append("Immediately restrict access to public cloud storage buckets")
        if _l(_d(modules.get("takeover")).get("vulnerable")):
            critical.append(
                "Fix subdomain takeover vulnerabilities by removing dangling DNS records"
            )
        if _l(_d(modules.get("endpoints")).get("sensitive")):
            critical.append(
                "Remove or restrict access to exposed sensitive files and configuration"
            )
        if _d(modules.get("github")).get("total_findings", 0):
            critical.append("Rotate all credentials found in public GitHub repositories")

        high = [
            "Implement Web Application Firewall (WAF) if not already in place",
            "Review and harden all open ports and services",
            "Implement SPF, DMARC, and DKIM for email security",
        ]
        medium = [
            "Implement continuous subdomain monitoring",
            "Regular vulnerability scanning and patch management",
            "Implement rate limiting on all public APIs",
        ]

        for title, items in (("Critical", critical), ("High", high), ("Medium", medium)):
            if items:
                elements.append(Paragraph(title, self.styles["SubSection"]))
                for item in items:
                    elements.append(
                        Paragraph(f"• {safe(item)}", self.styles["BodyText2"])
                    )

        return KeepTogether(elements)

    def _metadata_table(self, results: Dict):
        results = _d(results)
        data = [
            ["Target", safe(results.get("target", ""))],
            ["Scan Date", safe(str(results.get("scan_date", "")))],
            ["Depth", safe(str(results.get("depth", "")))],
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
