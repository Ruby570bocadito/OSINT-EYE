"""OSINT EYE - Rich CLI Interface (Professional Edition)"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.layout import Layout
from rich.live import Live
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich import box
from rich.style import Style
from rich.padding import Padding
from rich.theme import Theme
import time
from datetime import datetime
from typing import Dict, List, Optional

# --- Custom Enterprise Theme ---
THEME = Theme({
    "primary":    "bold cyan",
    "secondary":  "bright_blue",
    "accent":     "bold magenta",
    "success":    "bold green",
    "warning":    "bold yellow",
    "danger":     "bold red",
    "dim_text":   "dim white",
    "ghost":      "bright_black",
    "header_bg":  "on #0d1117",
})

console = Console(theme=THEME, highlight=False)

# --- Severity Color Map ---
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim white",
}

SCORE_COLORS = {
    "CRITICAL": "red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

ASCII_BANNER = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ███████╗██╗   ██╗███████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔════╝╚██╗ ██╔╝██╔════╝
██║   ██║███████╗██║██╔██╗ ██║   ██║       █████╗   ╚████╔╝ █████╗  
██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══╝    ╚██╔╝  ██╔══╝  
╚██████╔╝███████║██║██║ ╚████║   ██║       ███████╗   ██║   ███████╗ 
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝   ╚═╝   ╚══════╝"""


class RichCLI:
    """Professional Rich CLI — enterprise terminal UI"""

    def __init__(self):
        self.console = Console(theme=THEME, highlight=False)

    # ─────────────────────────────────────────────────────────────────────
    # BANNER
    # ─────────────────────────────────────────────────────────────────────
    def print_banner(self):
        self.console.print()
        self.console.print(Align.center(
            Text(ASCII_BANNER, style="bold cyan")
        ))
        self.console.print()
        subtitle = Text.assemble(
            ("  AI-Powered Attack Surface Intelligence  ", "bold white on #0d1117"),
            ("  v2.0  ", "bold cyan on #0d1117"),
        )
        self.console.print(Align.center(subtitle))
        self.console.print(Align.center(
            Text("  100% Free · No API Keys · Local AI  ", style="dim white")
        ))
        self.console.print()
        self.console.print(Rule(style="bright_black"))
        self.console.print()

    # ─────────────────────────────────────────────────────────────────────
    # SCAN HEADER
    # ─────────────────────────────────────────────────────────────────────
    def print_scan_header(self, target: str, depth: str, stealth: bool = False):
        depth_colors = {
            "quick":  "green",
            "normal": "cyan",
            "deep":   "yellow",
            "full":   "red",
        }
        depth_color = depth_colors.get(depth, "white")
        stealth_tag = " [bold yellow]⚡ STEALTH[/bold yellow]" if stealth else ""

        info = (
            f"  [dim]TARGET[/dim]  [bold white]{target}[/bold white]\n"
            f"  [dim]DEPTH [/dim]  [{depth_color}]{depth.upper()}[/{depth_color}]{stealth_tag}\n"
            f"  [dim]TIME  [/dim]  [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]"
        )
        self.console.print(Panel(
            info,
            title="[bold cyan]◈  SCAN TARGET[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        ))
        self.console.print()

    # ─────────────────────────────────────────────────────────────────────
    # PHASE SEPARATOR
    # ─────────────────────────────────────────────────────────────────────
    def print_phase(self, number: int, name: str):
        self.console.print()
        self.console.print(Rule(
            f"[bold cyan]  PHASE {number}[/bold cyan]  [white]{name}[/white]",
            style="bright_black"
        ))

    def print_phase_done(self, number: int, elapsed: float = None):
        elapsed_str = f" [dim]({elapsed:.1f}s)[/dim]" if elapsed else ""
        self.console.print(
            f"  [bold green]✔[/bold green]  [dim]Phase {number} complete[/dim]{elapsed_str}"
        )

    # ─────────────────────────────────────────────────────────────────────
    # MODULE LOG (replaces [*] messages)
    # ─────────────────────────────────────────────────────────────────────
    def log_info(self, msg: str):
        self.console.print(f"  [cyan]›[/cyan]  [dim]{msg}[/dim]")

    def log_success(self, msg: str):
        self.console.print(f"  [green]✔[/green]  {msg}")

    def log_warning(self, msg: str):
        self.console.print(f"  [yellow]⚠[/yellow]  [yellow]{msg}[/yellow]")

    def log_error(self, msg: str):
        self.console.print(f"  [red]✖[/red]  [red]{msg}[/red]")

    # ─────────────────────────────────────────────────────────────────────
    # PROGRESS
    # ─────────────────────────────────────────────────────────────────────
    def create_progress(self):
        return Progress(
            SpinnerColumn(spinner_name="dots", style="cyan"),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(bar_width=30, style="cyan", complete_style="bold green"),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            console=self.console,
            transient=True,
        )

    # ─────────────────────────────────────────────────────────────────────
    # DNS RESULTS
    # ─────────────────────────────────────────────────────────────────────
    def print_dns_results(self, dns: Dict):
        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="bright_black",
            header_style="bold cyan",
            title="[bold cyan]DNS Reconnaissance[/bold cyan]",
            title_justify="left",
            padding=(0, 1),
        )
        table.add_column("TYPE", style="cyan", width=10, no_wrap=True)
        table.add_column("VALUE", style="white")

        records = dns.get("records", {})
        for rtype, values in records.items():
            if values:
                table.add_row(rtype, ", ".join(str(v) for v in values[:5]))

        subs = dns.get("subdomains", [])
        table.add_row("SUBDOMS", f"[bold green]{len(subs)}[/bold green] discovered" if subs else "[dim]0[/dim]")

        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        table.add_row("SPF", "[green]✔  Configured[/green]" if spf.get("exists") else "[red]✖  Missing[/red]")
        table.add_row("DMARC", "[green]✔  Configured[/green]" if dmarc.get("exists") else "[red]✖  Missing[/red]")

        self.console.print(Padding(table, (0, 2)))

    # ─────────────────────────────────────────────────────────────────────
    # NETWORK RESULTS
    # ─────────────────────────────────────────────────────────────────────
    def print_network_results(self, network: Dict):
        services = [s for s in network.get("services", []) if s.get("state") == "open"]
        if not services:
            return

        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="bright_black",
            header_style="bold cyan",
            title="[bold cyan]Open Ports & Services[/bold cyan]",
            title_justify="left",
            padding=(0, 1),
        )
        table.add_column("PORT",    style="bold yellow", width=8,  no_wrap=True)
        table.add_column("PROTO",   style="cyan",        width=7,  no_wrap=True)
        table.add_column("SERVICE", style="white",       width=14, no_wrap=True)
        table.add_column("VERSION", style="dim white")

        for svc in services:
            port_str = str(svc.get("port", ""))
            # Highlight common dangerous ports
            if svc.get("port") in [21, 23, 3389, 5900, 445]:
                port_str = f"[bold red]{port_str}[/bold red]"
            table.add_row(
                port_str,
                svc.get("protocol", "tcp"),
                svc.get("service", "unknown"),
                svc.get("version", ""),
            )

        self.console.print(Padding(table, (0, 2)))

    # ─────────────────────────────────────────────────────────────────────
    # WEB RESULTS
    # ─────────────────────────────────────────────────────────────────────
    def print_web_results(self, web: Dict):
        techs = web.get("technologies", {}).get("technologies", [])
        if not techs:
            return

        tech_text = Text()
        for i, tech in enumerate(techs):
            tech_text.append(f" {tech} ", style="bold white on #1e3a5f")
            if i < len(techs) - 1:
                tech_text.append("  ", style="")

        self.console.print(Padding(Panel(
            tech_text,
            title="[bold cyan]Technologies Detected[/bold cyan]",
            title_align="left",
            border_style="bright_black",
            padding=(0, 1),
        ), (0, 2)))

    # ─────────────────────────────────────────────────────────────────────
    # CDN/WAF
    # ─────────────────────────────────────────────────────────────────────
    def print_cdn_results(self, cdn: Dict):
        if not cdn:
            return
        cdn_val = cdn.get("cdn") or "None"
        waf_val = cdn.get("waf") or "None"
        cdn_c = "green" if cdn_val != "None" else "dim"
        waf_c = "red" if waf_val != "None" else "dim"
        self.console.print(Padding(
            f"  [dim]CDN[/dim]  [{cdn_c}]{cdn_val}[/{cdn_c}]   [dim]WAF[/dim]  [{waf_c}]{waf_val}[/{waf_c}]",
            (0, 2)
        ))

    # ─────────────────────────────────────────────────────────────────────
    # CVE RESULTS
    # ─────────────────────────────────────────────────────────────────────
    def print_cve_results(self, cves: Dict):
        cve_list = cves.get("cves", [])
        if not cve_list:
            return

        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="bright_black",
            header_style="bold cyan",
            title=f"[bold cyan]CVE Correlation[/bold cyan]  [dim]({len(cve_list)} total)[/dim]",
            title_justify="left",
            padding=(0, 1),
        )
        table.add_column("CVE ID",       style="yellow",    width=22, no_wrap=True)
        table.add_column("SCORE",        style="white",     width=7,  no_wrap=True)
        table.add_column("SEVERITY",     style="white",     width=12, no_wrap=True)
        table.add_column("DESCRIPTION",  style="dim white")

        for cve in cve_list[:12]:
            sev_list = cve.get("severity")
            sev = sev_list[0] if isinstance(sev_list, list) and sev_list else {}
            score    = sev.get("score", "N/A")
            severity = sev.get("severity", "N/A")
            color    = SEVERITY_COLORS.get(severity, "white")
            desc     = cve.get("description", "")[:65]
            table.add_row(
                cve.get("id", ""),
                str(score),
                f"[{color}]{severity}[/{color}]",
                desc,
            )

        self.console.print(Padding(table, (0, 2)))

    # ─────────────────────────────────────────────────────────────────────
    # MITRE ATT&CK
    # ─────────────────────────────────────────────────────────────────────
    def print_mitre(self, mitre: Dict):
        findings = mitre.get("findings", [])
        if not findings:
            return

        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="bright_black",
            header_style="bold cyan",
            title=f"[bold cyan]MITRE ATT&CK Mapping[/bold cyan]  [dim]({mitre.get('total_findings', 0)} findings)[/dim]",
            title_justify="left",
            padding=(0, 1),
        )
        table.add_column("TECHNIQUE",  style="bold yellow", width=14, no_wrap=True)
        table.add_column("NAME",       style="white",       width=45)
        table.add_column("TACTIC",     style="cyan",        width=18, no_wrap=True)
        table.add_column("SEVERITY",   style="white",       width=10, no_wrap=True)

        for f in findings:
            color = SEVERITY_COLORS.get(f.get("severity", ""), "white")
            table.add_row(
                f.get("technique_id", ""),
                f.get("technique_name", "")[:44],
                f.get("tactic", ""),
                f"[{color}]{f.get('severity', '')}[/{color}]",
            )

        self.console.print(Padding(table, (0, 2)))

    # ─────────────────────────────────────────────────────────────────────
    # ATTACK CHAINS
    # ─────────────────────────────────────────────────────────────────────
    def print_chains(self, chains: List):
        if not chains:
            return

        self.console.print()
        self.console.print(Padding("[bold cyan]Attack Chains Identified[/bold cyan]", (0, 2)))
        for i, chain in enumerate(chains[:5], 1):
            risk = chain.get("risk_score", 0)
            diff = chain.get("difficulty", "Unknown")
            if risk >= 80:
                risk_style = "bold red"
            elif risk >= 50:
                risk_style = "bold yellow"
            else:
                risk_style = "bold green"

            self.console.print(
                f"  [{risk_style}]▶[/{risk_style}] "
                f"[bold white]{chain['name']}[/bold white]  "
                f"[{risk_style}]RISK {risk}/100[/{risk_style}]  "
                f"[dim]{diff}[/dim]"
            )
            for step in chain.get("steps", [])[:3]:
                self.console.print(
                    f"    [dim]Step {step['step']}:[/dim]  {step['action'][:60]}"
                )

    # ─────────────────────────────────────────────────────────────────────
    # ERRORS
    # ─────────────────────────────────────────────────────────────────────
    def print_errors(self, errors: List):
        if not errors:
            return
        self.console.print()
        self.console.print(Padding(
            f"[dim]⚠  {len(errors)} module error(s) — graceful degradation active[/dim]",
            (0, 2)
        ))
        for err in errors[:5]:
            self.console.print(f"  [bright_black]└─[/bright_black] [dim red]{err}[/dim red]")

    # ─────────────────────────────────────────────────────────────────────
    # FINAL SUMMARY PANEL
    # ─────────────────────────────────────────────────────────────────────
    def print_summary(self, results: Dict):
        """Render full professional summary — always called after scan"""
        modules   = results.get("modules", {})
        corr      = results.get("correlation", {})
        mitre     = results.get("mitre", {})
        chains    = results.get("attack_chains", [])
        ai_data   = results.get("ai_analysis", {})
        errors    = results.get("errors", [])

        dns       = modules.get("dns", {})
        cert      = modules.get("certs", {})
        wayback   = modules.get("wayback", {})
        net       = modules.get("network", {})
        cdn       = modules.get("cdn_waf", {})
        cve_mod   = modules.get("cve", {})
        web       = modules.get("web", {})
        emails    = modules.get("emails", {})
        takeover  = modules.get("takeover", {})
        cloud     = modules.get("cloud_buckets", {})

        open_ports  = [s for s in net.get("services", []) if s.get("state") == "open"]
        score_data  = corr.get("attack_surface_score", {})
        score       = score_data.get("score", 0)
        severity    = score_data.get("severity", "LOW")
        score_c     = SCORE_COLORS.get(severity, "white")
        techs       = web.get("technologies", {}).get("technologies", [])
        mitre_total = mitre.get("total_findings", 0)
        mitre_crit  = mitre.get("critical_count", 0)
        ai_rs       = (ai_data or {}).get("risk_score", {})
        ai_score    = ai_rs.get("score", None)
        ai_sev      = ai_rs.get("severity", "")

        cdn_val = cdn.get("cdn") or "None"
        waf_val = cdn.get("waf") or "None"

        # ── Detailed tables first ──────────────────────────────────────
        self.console.print()
        self.console.print(Rule("[bold cyan]  Scan Results[/bold cyan]", style="bright_black"))

        # DNS table
        spf   = dns.get("spf",   {})
        dmarc = dns.get("dmarc", {})
        dns_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                          border_style="bright_black", title="[bold cyan]DNS / Email Security[/bold cyan]",
                          title_justify="left", padding=(0, 1))
        dns_table.add_column("CHECK",  style="dim",   width=14, no_wrap=True)
        dns_table.add_column("RESULT", style="white")
        subdns = dns.get("subdomains", [])
        dns_table.add_row("Subdomains",
            f"[bold green]{len(subdns)} found[/bold green]" if subdns else "[dim]0[/dim]")
        dns_table.add_row("CT Subdoms",
            f"[cyan]{len(cert.get('subdomains', []))}[/cyan] via crt.sh")
        dns_table.add_row("Wayback",
            f"[cyan]{wayback.get('total_snapshots', 0):,}[/cyan] snapshots")
        dns_table.add_row("SPF",
            "[green]✔  Configured[/green]" if spf.get("exists") else "[red]✖  Missing[/red]")
        dns_table.add_row("DMARC",
            "[green]✔  Configured[/green]" if dmarc.get("exists") else "[red]✖  Missing[/red]")
        self.console.print(Padding(dns_table, (0, 2)))

        # Network table
        if open_ports:
            net_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                              border_style="bright_black", title="[bold cyan]Open Ports[/bold cyan]",
                              title_justify="left", padding=(0, 1))
            net_table.add_column("PORT",    style="bold yellow", width=8,  no_wrap=True)
            net_table.add_column("PROTO",   style="cyan",        width=7,  no_wrap=True)
            net_table.add_column("SERVICE", style="white",       width=14, no_wrap=True)
            net_table.add_column("VERSION", style="dim white")
            for svc in open_ports:
                p = svc.get("port", "")
                port_str = f"[bold red]{p}[/bold red]" if p in [21,23,3389,5900,445] else str(p)
                net_table.add_row(port_str, svc.get("protocol","tcp"),
                                  svc.get("service",""), svc.get("version",""))
            self.console.print(Padding(net_table, (0, 2)))

        # CDN / WAF / Tech row
        cdn_c = "green" if cdn_val != "None" else "bright_black"
        waf_c = "red"   if waf_val != "None" else "bright_black"
        cdntxt = Text()
        cdntxt.append("  CDN  ", style="dim"); cdntxt.append(cdn_val + "   ", style=cdn_c)
        cdntxt.append("WAF  ",  style="dim"); cdntxt.append(waf_val, style=waf_c)
        if techs:
            cdntxt.append("\n  TECH  ", style="dim")
            cdntxt.append(", ".join(techs[:8]), style="bright_blue")
        self.console.print(Padding(cdntxt, (0, 2)))
        self.console.print()

        # CVE table — only show CVEs with actual scores, sorted by severity
        cve_list     = cve_mod.get("cves", [])
        scored_cves  = []
        for cve in cve_list:
            sev_list = cve.get("severity")
            sev = sev_list[0] if isinstance(sev_list, list) and sev_list else {}
            sc  = sev.get("score")
            if sc is not None:
                cve["_score"] = float(sc)
                cve["_sev"]   = sev.get("severity", "N/A")
                scored_cves.append(cve)
        scored_cves.sort(key=lambda x: x["_score"], reverse=True)

        if scored_cves:
            cve_table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                              border_style="bright_black",
                              title=f"[bold cyan]CVE Correlation[/bold cyan]  [dim]({len(cve_list)} total · {len(scored_cves)} scored)[/dim]",
                              title_justify="left", padding=(0, 1))
            cve_table.add_column("CVE ID",      style="yellow",   width=22, no_wrap=True)
            cve_table.add_column("CVSS",         style="white",    width=7,  no_wrap=True)
            cve_table.add_column("SEVERITY",     style="white",    width=12, no_wrap=True)
            cve_table.add_column("DESCRIPTION",  style="dim white")
            for cve in scored_cves[:10]:
                col  = SEVERITY_COLORS.get(cve["_sev"], "white")
                desc = cve.get("description", "")[:65]
                cve_table.add_row(cve.get("id", ""), str(cve["_score"]),
                                  f"[{col}]{cve['_sev']}[/{col}]", desc)
            self.console.print(Padding(cve_table, (0, 2)))
        elif cve_list:
            self.console.print(Padding(
                f"  [dim]CVEs: {len(cve_list)} matched (no CVSS scores available)[/dim]", (0, 2)))


        # MITRE table
        mitre_findings = mitre.get("findings", [])
        if mitre_findings:
            mt = Table(box=box.SIMPLE_HEAD, header_style="bold cyan",
                       border_style="bright_black",
                       title=f"[bold cyan]MITRE ATT&CK[/bold cyan]  [dim]({mitre_total})[/dim]",
                       title_justify="left", padding=(0, 1))
            mt.add_column("TECHNIQUE", style="bold yellow", width=14, no_wrap=True)
            mt.add_column("NAME",      style="white",       width=44)
            mt.add_column("TACTIC",    style="cyan",        width=18, no_wrap=True)
            mt.add_column("SEVERITY",  style="white",       width=10, no_wrap=True)
            for f in mitre_findings:
                col = SEVERITY_COLORS.get(f.get("severity",""), "white")
                mt.add_row(f.get("technique_id",""), f.get("technique_name","")[:43],
                           f.get("tactic",""), f"[{col}]{f.get('severity','')}[/{col}]")
            self.console.print(Padding(mt, (0, 2)))

        # Attack chains
        if chains:
            self.console.print(Padding("[bold cyan]Attack Chains[/bold cyan]", (0, 2)))
            for i, ch in enumerate(chains[:5], 1):
                risk = ch.get("risk_score", 0)
                rc   = "bold red" if risk >= 80 else "bold yellow" if risk >= 50 else "bold green"
                self.console.print(
                    f"  [{rc}]▶[/{rc}] [bold white]{ch['name']}[/bold white]  "
                    f"[{rc}]RISK {risk}/100[/{rc}]  [dim]{ch.get('difficulty','')}[/dim]"
                )

        if errors:
            self.console.print()
            self.console.print(Padding(
                f"[dim]⚠  {len(errors)} module error(s) — graceful degradation[/dim]", (0, 2)))
            for e in errors[:5]:
                self.console.print(f"  [bright_black]└─[/bright_black] [dim red]{e}[/dim red]")

        # ── Summary score panel ────────────────────────────────────────
        gauge_width = 30
        filled      = int((score / 100) * gauge_width)

        gauge = Text()
        gauge.append("  ", style="")
        gauge.append("█" * filled, style=score_c)
        gauge.append("░" * (gauge_width - filled), style="bright_black")
        gauge.append(f"  {score}/100", style=f"bold {score_c}")
        gauge.append(f"  [{severity}]", style=f"bold {score_c}")

        # Build summary grid
        sum_left  = Text()
        sum_left.append("TARGET\n",  style="dim"); sum_left.append(f"{results.get('target','')}\n\n", style="bold white")
        sum_left.append("DATE\n",    style="dim"); sum_left.append(f"{results.get('scan_date','')[:19]}\n\n", style="dim white")
        sum_left.append("DEPTH\n",   style="dim"); sum_left.append(f"{results.get('depth','normal').upper()}\n\n", style="cyan")
        sum_left.append("DNS\n",     style="dim"); sum_left.append(f"{len(dns.get('subdomains',[]))} subdomains\n", style="white")
        sum_left.append("NETWORK\n", style="dim"); sum_left.append(f"{len(open_ports)} open ports\n", style="white")
        sum_left.append("CVEs\n",    style="dim"); sum_left.append(f"{len(cve_list)}\n", style="white")

        sum_right = Text()
        sum_right.append("ATTACK SURFACE\n", style="dim")
        sum_right.append(gauge)
        sum_right.append("\n\n")
        sum_right.append("MITRE ATT&CK\n", style="dim")
        sum_right.append(f"{mitre_total} techniques", style="white")
        if mitre_crit:
            sum_right.append(f"  {mitre_crit} CRITICAL", style="bold red")
        sum_right.append("\n\n")
        sum_right.append("ATTACK CHAINS\n", style="dim")
        sum_right.append(f"{len(chains)} identified\n", style="yellow" if chains else "dim")
        if ai_score is not None:
            ai_c = SCORE_COLORS.get(ai_sev, "white")
            sum_right.append("\nAI RISK SCORE\n", style="dim")
            sum_right.append(f"{ai_score}/100", style=f"bold {ai_c}")
            sum_right.append(f"  [{ai_sev}]", style=f"bold {ai_c}")

        from rich.columns import Columns
        self.console.print()
        self.console.print(Rule(style="bright_black"))
        self.console.print(Panel(
            Columns([
                Padding(sum_left,  (1, 3)),
                Padding(sum_right, (1, 3)),
            ], equal=True),
            title="[bold cyan]◈  SCAN COMPLETE[/bold cyan]",
            border_style="cyan",
        ))
        self.console.print()

    # ─────────────────────────────────────────────────────────────────────
    # FULL RESULTS (--rich flag)
    # ─────────────────────────────────────────────────────────────────────
    def print_full_results(self, results: Dict):
        """Detailed per-module breakdown (same as summary now)"""
        self.print_summary(results)

    # ─────────────────────────────────────────────────────────────────────
    # EXPORT TABLE
    # ─────────────────────────────────────────────────────────────────────
    def print_exports(self, exports: Dict):
        table = Table(
            box=box.SIMPLE_HEAD,
            border_style="bright_black",
            header_style="bold cyan",
            title="[bold green]Exported Files[/bold green]",
            title_justify="left",
        )
        table.add_column("FORMAT", style="cyan",  width=12)
        table.add_column("PATH",   style="white")

        for fmt, path in exports.items():
            if isinstance(path, list):
                for p in path:
                    table.add_row(fmt.upper(), p)
            else:
                table.add_row(fmt.upper(), path)

        self.console.print(Padding(table, (0, 2)))
