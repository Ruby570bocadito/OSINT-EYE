"""OSINT EYE - Rich CLI Interface (Professional Edition)

Spectacular terminal presentation for scan output: gradient ASCII banner,
rounded panels, elegant tables, smooth attack-surface gauges and coherent
severity colours (critical=red, high=orange, medium=yellow, low=blue,
info=grey). Every renderer is defensive (``dict.get`` everywhere) so a
minimal or empty ``results`` dict never raises.
"""

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeRemainingColumn,
)
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich import box
from rich.style import Style
from rich.color import Color
from rich.padding import Padding
from rich.columns import Columns
from rich.markup import escape
from rich.theme import Theme
from datetime import datetime
from typing import Any, Dict, List, Optional

__all__ = [
    "RichCLI",
    "console",
    "THEME",
    "SEVERITY_COLORS",
    "ASCII_BANNER",
]

# ─────────────────────────────────────────────────────────────────────────────
# Theme & palette
# ─────────────────────────────────────────────────────────────────────────────
THEME = Theme(
    {
        "primary": "bold cyan",
        "secondary": "bright_blue",
        "accent": "bold magenta",
        "success": "bold green",
        "warning": "bold yellow",
        "danger": "bold red",
        "critical": "bold red",
        "high": "bold dark_orange",
        "medium": "bold yellow",
        "low": "bold blue",
        "info": "bright_black",
        "dim_text": "dim white",
        "ghost": "bright_black",
    }
)

console = Console(theme=THEME, highlight=False)

# Coherent severity palette: critical=red, high=orange, medium=yellow,
# low=blue, info=grey. Keys are matched case-insensitively via sev_style().
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "INFO": "bright_black",
}

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SCORE_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "INFO": "bright_black",
}

DEPTH_COLORS = {
    "quick": "green",
    "normal": "cyan",
    "deep": "dark_orange",
    "full": "red",
}

ASCII_BANNER = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ███████╗██╗   ██╗███████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔════╝╚██╗ ██╔╝██╔════╝
██║   ██║███████╗██║██╔██╗ ██║   ██║       █████╗   ╚████╔╝ █████╗
██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══╝    ╚██╔╝  ██╔══╝
╚██████╔╝███████║██║██║ ╚████║   ██║       ███████╗   ██║   ███████╗
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝   ╚═╝   ╚══════╝"""

# Eighth-block characters for smooth gauge edges (index = filled eighths).
_PARTIAL = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def sev_style(severity: Any) -> str:
    """Map a severity label to a coherent Rich style (case-insensitive)."""
    if not severity:
        return "white"
    return SEVERITY_COLORS.get(str(severity).upper(), "white")


def _d(value: Any) -> Dict:
    """Return ``value`` if it is a dict, else ``{}`` (defensive accessor)."""
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> List:
    """Return ``value`` if it is a list, else ``[]`` (defensive accessor)."""
    return value if isinstance(value, list) else {}


def _cve_sev(cve: Dict) -> Dict:
    """Normalise the many shapes a CVE 'severity' field can take."""
    sev = cve.get("severity")
    if isinstance(sev, list) and sev and isinstance(sev[0], dict):
        return sev[0]
    if isinstance(sev, dict):
        return sev
    return {}


def _gradient_banner(banner: str) -> Text:
    """Paint the ASCII banner with a stable vertical cyan→blue→magenta sweep."""
    stops = [(0, 229, 255), (64, 120, 255), (200, 60, 255)]
    lines = banner.strip("\n").split("\n")
    out = Text()
    last = max(len(lines) - 1, 1)
    for i, line in enumerate(lines):
        t = i / last * (len(stops) - 1)
        lo = int(t)
        hi = min(lo + 1, len(stops) - 1)
        u = t - lo
        rgb = tuple(
            int(stops[lo][j] + (stops[hi][j] - stops[lo][j]) * u) for j in range(3)
        )
        out.append(line, style=Style(color=Color.from_rgb(*rgb), bold=True))
        if i < len(lines) - 1:
            out.append("\n")
    return out


def _gauge(score: float, width: int = 32, color: str = "cyan") -> Text:
    """Smooth attack-surface gauge built from block characters."""
    try:
        score = max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        score = 0.0
    filled_eighths = int(round(score / 100 * width * 8))
    full, rem = divmod(filled_eighths, 8)
    bar = Text()
    if full:
        bar.append("█" * full, style=color)
    if rem and full < width:
        bar.append(_PARTIAL[rem], style=color)
        full += 1
    if width - full > 0:
        bar.append("░" * (width - full), style="bright_black")
    return bar


def _chip(label: str, color: str) -> Text:
    """Small coloured chip like [◆ HIGH] used across tables and lists."""
    chip = Text()
    chip.append("◆ ", style=color)
    chip.append(label, style=color)
    return chip


class RichCLI:
    """Professional Rich CLI — enterprise-grade terminal UI."""

    def __init__(self, console: Optional[Console] = None):
        # Optional console injection (used by tests to capture output).
        self.console = console or Console(theme=THEME, highlight=False)

    # ─────────────────────────────────────────────────────────────────────
    # BANNER
    # ─────────────────────────────────────────────────────────────────────
    def print_banner(self):
        """Spectacular gradient banner with tagline and feature chips."""
        self.console.print()
        self.console.print(Align.center(_gradient_banner(ASCII_BANNER)))
        self.console.print()

        tagline = Text(justify="center")
        tagline.append("◆ ", style="cyan")
        tagline.append("AI-POWERED ATTACK SURFACE INTELLIGENCE", style="bold white")
        tagline.append(" ◆", style="cyan")
        self.console.print(Align.center(tagline))
        self.console.print()

        chips = Text()
        specs = [
            (" v2.1 ", "bold white on #134e4a"),
            (" 100% FREE ", "bold white on #1e3a5f"),
            (" NO API KEYS ", "bold white on #3b2f63"),
            (" LOCAL AI ", "bold white on #4a2c2c"),
        ]
        for i, (text, style) in enumerate(specs):
            if i:
                chips.append(" ", style="")
            chips.append(text, style=style)
        self.console.print(Align.center(chips))
        self.console.print()
        self.console.print(Rule(style="bright_black"))
        self.console.print()

    # ─────────────────────────────────────────────────────────────────────
    # SCAN HEADER
    # ─────────────────────────────────────────────────────────────────────
    def print_scan_header(self, target: str, depth: str, stealth: bool = False):
        """Rounded scan-target panel with depth/stealth chips and timestamp."""
        depth_color = DEPTH_COLORS.get(str(depth).lower(), "white")

        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style="bright_black", no_wrap=True)
        grid.add_column(style="white")

        grid.add_row("TARGET", Text.assemble(("◆ ", "cyan"), (str(target or "—"), "bold white")))
        depth_line = Text(depth.upper(), style=f"bold {depth_color}")
        if stealth:
            depth_line.append("   ")
            depth_line.append(Text("◆ STEALTH MODE", style="bold yellow"))
        grid.add_row("DEPTH", depth_line)
        grid.add_row(
            "STARTED",
            Text(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="dim white"),
        )

        self.console.print(
            Panel(
                grid,
                title="[bold cyan]◆  SCAN TARGET[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )
        self.console.print()

    # ─────────────────────────────────────────────────────────────────────
    # PHASE SEPARATOR / LOGGING
    # ─────────────────────────────────────────────────────────────────────
    def print_phase(self, number: int, name: str):
        """Render a phase separator rule."""
        self.console.print()
        self.console.print(
            Rule(
                f"[bold cyan]  PHASE {number}[/bold cyan]  [white]{escape(str(name))}[/white]",
                style="bright_black",
            )
        )

    def print_phase_done(self, number: int, elapsed: float = None):
        """Confirm phase completion with a checkmark."""
        elapsed_str = f" [dim]({elapsed:.1f}s)[/dim]" if elapsed else ""
        self.console.print(
            f"  [bold green]✔[/bold green]  [dim]Phase {number} complete[/dim]{elapsed_str}"
        )

    def log_info(self, msg: str):
        self.console.print(f"  [cyan]▸[/cyan]  [dim]{escape(str(msg))}[/dim]")

    def log_success(self, msg: str):
        self.console.print(f"  [green]✔[/green]  {escape(str(msg))}")

    def log_warning(self, msg: str):
        self.console.print(f"  [yellow]⚠[/yellow]  [yellow]{escape(str(msg))}[/yellow]")

    def log_error(self, msg: str):
        self.console.print(f"  [red]✖[/red]  [red]{escape(str(msg))}[/red]")

    # ─────────────────────────────────────────────────────────────────────
    # PROGRESS
    # ─────────────────────────────────────────────────────────────────────
    def create_progress(self) -> Progress:
        """Consistent spinner + bar used across long-running phases."""
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
    # SHARED TABLE FACTORY
    # ─────────────────────────────────────────────────────────────────────
    def _table(self, title: Optional[str], *columns, caption: str = None) -> Table:
        """Elegant base table (clean head box, cyan headers, left title).

        ``title`` may be None for tables embedded inside titled panels.
        """
        t = Table(
            box=box.SIMPLE_HEAD,
            border_style="bright_black",
            header_style="bold cyan",
            title=f"[bold cyan]{title}[/bold cyan]" if title else None,
            title_justify="left",
            padding=(0, 1),
        )
        for col in columns:
            if isinstance(col, dict):
                t.add_column(**col)
            else:
                t.add_column(col)
        if caption:
            t.caption = caption
        return t

    # ─────────────────────────────────────────────────────────────────────
    # PER-MODULE RENDERERS (kept for programmatic use)
    # ─────────────────────────────────────────────────────────────────────
    def print_dns_results(self, dns: Dict):
        """DNS records + SPF/DMARC status table."""
        dns = _d(dns)
        table = self._table("DNS Reconnaissance", {"header": "TYPE", "style": "cyan", "width": 10, "no_wrap": True}, {"header": "VALUE", "style": "white"})

        for rtype, values in _d(dns.get("records")).items():
            if values:
                table.add_row(str(rtype), escape(", ".join(str(v) for v in list(values)[:5])))

        subs = _l(dns.get("subdomains"))
        table.add_row(
            "SUBDOMS",
            f"[bold green]{len(subs)}[/bold green] discovered" if subs else "[dim]0[/dim]",
        )

        spf = _d(dns.get("spf"))
        dmarc = _d(dns.get("dmarc"))
        table.add_row("SPF", "[green]✔  Configured[/green]" if spf.get("exists") else "[red]✖  Missing[/red]")
        table.add_row("DMARC", "[green]✔  Configured[/green]" if dmarc.get("exists") else "[red]✖  Missing[/red]")

        self.console.print(Padding(table, (0, 2)))

    def print_network_results(self, network: Dict):
        """Open ports & services table."""
        network = _d(network)
        services = [s for s in _l(network.get("services")) if _d(s).get("state") == "open"]
        if not services:
            return

        table = self._table(
            "Open Ports & Services",
            {"header": "PORT", "style": "bold yellow", "width": 8, "no_wrap": True},
            {"header": "PROTO", "style": "cyan", "width": 7, "no_wrap": True},
            {"header": "SERVICE", "style": "white", "width": 14, "no_wrap": True},
            {"header": "VERSION", "style": "dim white"},
        )
        for svc in services:
            svc = _d(svc)
            port = svc.get("port", "")
            port_str = str(port)
            if port in [21, 23, 3389, 5900, 445]:
                port_str = f"[bold red]{port_str}[/bold red]"
            table.add_row(
                port_str,
                str(svc.get("protocol", "tcp")),
                str(svc.get("service", "unknown")),
                escape(str(svc.get("version", ""))),
            )
        self.console.print(Padding(table, (0, 2)))

    def print_web_results(self, web: Dict):
        """Detected technologies as chips."""
        techs = _l(_d(_d(web).get("technologies")).get("technologies"))
        if not techs:
            return
        tech_text = Text()
        for i, tech in enumerate(techs):
            tech_text.append(f" {tech} ", style="bold white on #1e3a5f")
            if i < len(techs) - 1:
                tech_text.append(" ", style="")
        self.console.print(
            Padding(
                Panel(
                    tech_text,
                    title="[bold cyan]Technologies Detected[/bold cyan]",
                    title_align="left",
                    border_style="bright_black",
                    box=box.ROUNDED,
                    padding=(0, 1),
                ),
                (0, 2),
            )
        )

    def print_cdn_results(self, cdn: Dict):
        """One-line CDN / WAF fingerprint row."""
        cdn = _d(cdn)
        if not cdn:
            return
        cdn_val = cdn.get("cdn") or "None"
        waf_val = cdn.get("waf") or "None"
        cdn_c = "green" if cdn_val != "None" else "dim"
        waf_c = "red" if waf_val != "None" else "dim"
        self.console.print(
            Padding(
                f"  [dim]CDN[/dim]  [{cdn_c}]{escape(str(cdn_val))}[/{cdn_c}]"
                f"   [dim]WAF[/dim]  [{waf_c}]{escape(str(waf_val))}[/{waf_c}]",
                (0, 2),
            )
        )

    def print_cve_results(self, cves: Dict):
        """CVE correlation table sorted by CVSS score."""
        cve_list = _l(_d(cves).get("cves"))
        if not cve_list:
            return
        table = self._table(
            f"CVE Correlation  [dim]({len(cve_list)} total)[/dim]",
            {"header": "CVE ID", "style": "yellow", "width": 22, "no_wrap": True},
            {"header": "SCORE", "style": "white", "width": 7, "no_wrap": True},
            {"header": "SEVERITY", "style": "white", "width": 12, "no_wrap": True},
            {"header": "DESCRIPTION", "style": "dim white"},
        )
        for cve in cve_list[:12]:
            cve = _d(cve)
            sev = _cve_sev(cve)
            severity = str(sev.get("severity", "N/A"))
            table.add_row(
                str(cve.get("id", "")),
                str(sev.get("score", "N/A")),
                Text(severity, style=sev_style(severity)),
                escape(str(cve.get("description", ""))[:65]),
            )
        self.console.print(Padding(table, (0, 2)))

    def print_mitre(self, mitre: Dict):
        """MITRE ATT&CK mapping table."""
        findings = _l(_d(mitre).get("findings"))
        if not findings:
            return
        table = self._table(
            f"MITRE ATT&CK Mapping  [dim]({_d(mitre).get('total_findings', len(findings))} findings)[/dim]",
            {"header": "TECHNIQUE", "style": "bold yellow", "width": 14, "no_wrap": True},
            {"header": "NAME", "style": "white", "width": 45},
            {"header": "TACTIC", "style": "cyan", "width": 18, "no_wrap": True},
            {"header": "SEVERITY", "style": "white", "width": 12, "no_wrap": True},
        )
        for f in findings:
            f = _d(f)
            severity = str(f.get("severity", ""))
            table.add_row(
                str(f.get("technique_id", "")),
                escape(str(f.get("technique_name", ""))[:44]),
                str(f.get("tactic", "")),
                Text(severity, style=sev_style(severity)),
            )
        self.console.print(Padding(table, (0, 2)))

    def print_chains(self, chains: List):
        """Attack chains with risk colouring and step previews."""
        if not chains:
            return
        self.console.print()
        self.console.print(Padding("[bold cyan]◆ Attack Chains Identified[/bold cyan]", (0, 2)))
        for i, chain in enumerate(chains[:5], 1):
            chain = _d(chain)
            risk = chain.get("risk_score", 0) or 0
            if risk >= 80:
                risk_style = "bold red"
            elif risk >= 50:
                risk_style = "bold dark_orange"
            else:
                risk_style = "bold green"
            self.console.print(
                f"  [{risk_style}]▸[/{risk_style}] "
                f"[bold white]{escape(str(chain.get('name', 'chain')))}[/bold white]  "
                f"[{risk_style}]RISK {risk}/100[/{risk_style}]  "
                f"[dim]{escape(str(chain.get('difficulty', 'Unknown')))}[/dim]"
            )
            for step in _l(chain.get("steps"))[:3]:
                step = _d(step)
                self.console.print(
                    f"    [dim]Step {step.get('step', '?')}:[/dim]  "
                    f"{escape(str(step.get('action', ''))[:60])}"
                )

    def print_errors(self, errors: List):
        """Graceful-degradation error footer."""
        errors = _l(errors)
        if not errors:
            return
        self.console.print()
        self.console.print(
            Padding(
                f"[yellow]⚠[/yellow] [dim] {len(errors)} module error(s) — graceful degradation active[/dim]",
                (0, 2),
            )
        )
        for err in errors[:5]:
            self.console.print(f"  [bright_black]└─[/bright_black] [dim red]{escape(str(err))}[/dim red]")

    # ─────────────────────────────────────────────────────────────────────
    # SUMMARY DASHBOARD
    # ─────────────────────────────────────────────────────────────────────
    def _module_counts(self, results: Dict) -> List[tuple]:
        """(label, count, style) rows for the coverage panel."""
        modules = _d(results.get("modules"))
        dns = _d(modules.get("dns"))
        certs = _d(modules.get("certs"))
        wayback = _d(modules.get("wayback"))
        net = _d(modules.get("network"))
        web = _d(modules.get("web"))
        endpoints = _d(modules.get("endpoints"))
        emails = _d(modules.get("emails"))
        cloud = _d(modules.get("cloud_buckets"))
        github = _d(modules.get("github"))
        permutation = _d(modules.get("permutation"))
        takeover = _d(modules.get("takeover"))

        open_ports = [s for s in _l(net.get("services")) if _d(s).get("state") == "open"]
        techs = _l(_d(web.get("technologies")).get("technologies"))

        return [
            ("DNS subdomains", len(_l(dns.get("subdomains"))), "cyan"),
            ("CT subdomains", len(_l(certs.get("subdomains"))), "cyan"),
            ("Wayback snapshots", wayback.get("total_snapshots", 0) or 0, "blue"),
            ("Open ports", len(open_ports), "yellow"),
            ("Technologies", len(techs), "magenta"),
            ("Endpoints", endpoints.get("total_found", len(_l(endpoints.get("found")))) or 0, "green"),
            ("Emails", len(_l(emails.get("emails_found"))), "green"),
            ("Cloud buckets", len(_l(cloud.get("found"))), "blue"),
            ("Permutations", permutation.get("total_found", 0) or 0, "cyan"),
            ("GitHub findings", github.get("total_findings", 0) or 0, "red"),
            ("Takeover vulns", len(_l(takeover.get("vulnerable"))), "red"),
        ]

    def _top_findings(self, results: Dict) -> List[tuple]:
        """Ranked (severity, description) list of the most relevant findings."""
        modules = _d(results.get("modules"))
        items: List[tuple] = []

        takeover = _l(_d(modules.get("takeover")).get("vulnerable"))
        if takeover:
            items.append(("CRITICAL", f"{len(takeover)} subdomain takeover candidate(s)"))

        github = _d(modules.get("github"))
        if github.get("total_findings", 0):
            items.append(("CRITICAL", f"{github.get('total_findings')} potential GitHub leak(s)"))

        cve_list = _l(_d(modules.get("cve")).get("cves"))
        scored = []
        for cve in cve_list:
            sev = _cve_sev(cve)
            try:
                score = float(sev.get("score"))
            except (TypeError, ValueError):
                continue
            scored.append((score, cve.get("id", ""), sev.get("severity", "")))
        for score, cid, severity in sorted(scored, key=lambda x: -x[0])[:3]:
            items.append((severity or "HIGH", f"{cid} (CVSS {score:g})"))

        buckets = _l(_d(modules.get("cloud_buckets")).get("public"))
        if buckets:
            items.append(("HIGH", f"{len(buckets)} public cloud bucket(s)"))

        sensitive = _l(_d(modules.get("endpoints")).get("sensitive"))
        if not sensitive:
            sensitive = _l(_d(_d(modules.get("web")).get("endpoints")).get("sensitive"))
        if sensitive:
            items.append(("HIGH", f"{len(sensitive)} sensitive file(s) exposed"))

        mitre_items = _l(results.get("mitre", {}).get("findings") if isinstance(results.get("mitre"), dict) else [])
        critical_mitre = [m for m in mitre_items if str(_d(m).get("severity", "")).upper() == "CRITICAL"]
        if critical_mitre:
            items.append(("CRITICAL", f"{len(critical_mitre)} critical ATT&CK mapping(s)"))

        items.sort(key=lambda x: SEVERITY_RANK.get(str(x[0]).upper(), -1), reverse=True)
        return items[:6]

    def print_summary(self, results: Dict):
        """Executive dashboard: score gauge, module coverage and top findings.

        Tolerates minimal/empty ``results`` — every key is read defensively.
        """
        results = _d(results)
        modules = _d(results.get("modules"))
        corr = _d(results.get("correlation"))
        mitre = _d(results.get("mitre"))
        chains = _l(results.get("attack_chains"))
        ai_data = _d(results.get("ai_analysis"))
        errors = _l(results.get("errors"))

        score_data = _d(corr.get("attack_surface_score"))
        score = score_data.get("score", 0) or 0
        severity = str(score_data.get("severity", "LOW") or "LOW")
        score_c = SCORE_COLORS.get(severity.upper(), "white")
        factors = _l(score_data.get("factors"))

        mitre_total = mitre.get("total_findings", len(_l(mitre.get("findings")))) or 0
        mitre_crit = mitre.get("critical_count", 0) or 0
        ai_rs = _d(ai_data.get("risk_score"))
        ai_score = ai_rs.get("score")
        ai_sev = str(ai_rs.get("severity", "") or "")

        # ── Header ───────────────────────────────────────────────────────
        self.console.print()
        target = results.get("target") or "—"
        self.console.print(
            Rule(
                f"[bold cyan]  ◈ SCAN SUMMARY[/bold cyan]  [bold white]{escape(str(target))}[/bold white]",
                style="bright_black",
            )
        )

        # ── Left: attack surface score panel ────────────────────────────
        left = Table.grid(padding=(0, 0))
        left.add_column()
        left.add_row(Text("ATTACK SURFACE SCORE", style="dim"))
        gauge_row = Text()
        gauge_row.append(Text("  ", style=""))
        gauge_row.append(_gauge(score, width=28, color=SCORE_COLORS.get(severity.upper(), "cyan")))
        left.add_row(gauge_row)
        score_row = Text()
        score_row.append(f"  {score}", style=f"bold {score_c}")
        score_row.append("/100", style="dim")
        score_row.append(f"  {severity}", style=f"bold {score_c}")
        left.add_row(score_row)
        if factors:
            left.add_row(Text())
            left.add_row(Text("Contributing factors", style="dim"))
            for factor in factors[:3]:
                left.add_row(Text.assemble(("  ▸ ", "bright_black"), (str(factor)[:64], "dim white")))
        score_panel = Panel(
            left,
            title="[bold cyan]◆ RISK POSTURE[/bold cyan]",
            border_style="bright_black",
            box=box.ROUNDED,
            padding=(1, 2),
        )

        # ── Right: module coverage with mini bars ───────────────────────
        counts = self._module_counts(results)
        max_count = max([c for _, c, _ in counts] + [1])
        coverage = Table.grid(padding=(0, 1))
        coverage.add_column(justify="left", no_wrap=True)
        coverage.add_column(justify="right", width=6)
        coverage.add_column(no_wrap=True)
        for label, count, color in counts:
            count = int(count or 0)
            bar = Text()
            if count:
                fill = max(1, int(round(count / max_count * 8)))
                bar.append("▰" * fill, style=color)
            else:
                bar.append("·", style="bright_black")
            value = Text(str(count), style="bold white" if count else "bright_black")
            coverage.add_row(Text(label, style="dim"), value, bar)

        extra = Text()
        extra.append("MITRE ATT&CK   ", style="dim")
        extra.append(f"{mitre_total} techniques", style="white")
        if mitre_crit:
            extra.append(f"   {mitre_crit} CRITICAL", style="bold red")
        extra.append("\n")
        extra.append("ATTACK CHAINS  ", style="dim")
        extra.append(f"{len(chains)} identified", style="yellow" if chains else "bright_black")
        if ai_score is not None:
            ai_c = SCORE_COLORS.get(ai_sev.upper(), "white")
            extra.append("\n")
            extra.append("AI RISK SCORE  ", style="dim")
            extra.append(f"{ai_score}/100", style=f"bold {ai_c}")
            if ai_sev:
                extra.append(f"  [{ai_sev}]", style=f"bold {ai_c}")
        coverage_grid = Table.grid(padding=(0, 0))
        coverage_grid.add_column()
        coverage_grid.add_row(coverage)
        coverage_grid.add_row(Text())
        coverage_grid.add_row(extra)
        coverage_panel = Panel(
            coverage_grid,
            title="[bold cyan]◆ MODULE COVERAGE[/bold cyan]",
            border_style="bright_black",
            box=box.ROUNDED,
            padding=(1, 2),
        )

        self.console.print(Padding(Columns([score_panel, coverage_panel], equal=True), (1, 1)))

        # ── Top findings ─────────────────────────────────────────────────
        top = self._top_findings(results)
        if top:
            self.console.print()
            self.console.print(Padding("[bold cyan]◆ TOP FINDINGS[/bold cyan]", (0, 1)))
            for severity, text in top:
                chip = _chip(str(severity).upper(), sev_style(severity))
                self.console.print(Padding(Text.assemble(("  ", ""), chip, ("  ", ""), (text, "white")), (0, 1)))
        else:
            self.console.print()
            self.console.print(
                Padding("[dim]  ○ No high-impact findings recorded for this scan.[/dim]", (0, 1))
            )

        # ── Errors ───────────────────────────────────────────────────────
        if errors:
            self.print_errors(errors)

        self.console.print()
        self.console.print(
            Padding(
                f"  [bright_black]Completed {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · OSINT EYE v2.1[/bright_black]",
                (0, 0),
            )
        )
        self.console.print()

    # ─────────────────────────────────────────────────────────────────────
    # FULL RESULTS (--rich): one panel per module
    # ─────────────────────────────────────────────────────────────────────
    def _panel(self, title: str, body, count: Optional[int] = None):
        """Rounded section panel with an optional count badge in the title."""
        if count is not None:
            title = f"{title}  [dim]· {count}[/dim]"
        return Panel(
            body,
            title=f"[bold cyan]◆ {title}[/bold cyan]",
            title_align="left",
            border_style="bright_black",
            box=box.ROUNDED,
            padding=(0, 2),
        )

    def _kv_grid(self, rows: List[tuple]) -> Table.grid:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", justify="right", no_wrap=True)
        grid.add_column(style="white")
        for k, v in rows:
            grid.add_row(str(k), v if isinstance(v, (Text,)) else Text(str(v)))
        return grid

    def _section_dns(self, dns: Dict):
        dns = _d(dns)
        rows = []
        for rtype, values in _d(dns.get("records")).items():
            if values:
                rows.append((str(rtype), Text(", ".join(str(v) for v in list(values)[:5]))))
        subs = _l(dns.get("subdomains"))
        spf = _d(dns.get("spf"))
        dmarc = _d(dns.get("dmarc"))
        if spf:
            rows.append(("SPF", Text("✔ Configured" if spf.get("exists") else "✖ Missing", style="green" if spf.get("exists") else "red")))
        if dmarc:
            rows.append(("DMARC", Text("✔ Configured" if dmarc.get("exists") else "✖ Missing", style="green" if dmarc.get("exists") else "red")))
        if subs:
            sample = Table.grid(padding=(0, 2))
            sample.add_column(style="white")
            for sub in subs[:12]:
                sample.add_row(Text(f"  ▸ {sub}", style="white"))
            if len(subs) > 12:
                sample.add_row(Text(f"  … and {len(subs) - 12} more", style="dim"))
            body = Group(self._kv_grid(rows) if rows else Text("", style=""), Text(), sample)
        else:
            body = self._kv_grid(rows) if rows else Text("No DNS data collected.", style="dim")
        return self._panel("DNS RECONNAISSANCE", body, len(subs) or None)

    def _section_list(self, title: str, items: List, count: int = None):
        """Generic vertical list section."""
        body = Table.grid(padding=(0, 2))
        body.add_column(style="white")
        for item in items[:15]:
            body.add_row(Text(f"  ▸ {item}", style="white"))
        if len(items) > 15:
            body.add_row(Text(f"  … and {len(items) - 15} more", style="dim"))
        return self._panel(title, body, count if count is not None else len(items))

    def _section_network(self, net: Dict):
        net = _d(net)
        services = [s for s in _l(net.get("services")) if _d(s).get("state") == "open"]
        table = self._table(
            "Open Ports",
            {"header": "PORT", "style": "bold yellow", "no_wrap": True},
            {"header": "PROTO", "style": "cyan", "no_wrap": True},
            {"header": "SERVICE", "style": "white", "no_wrap": True},
            {"header": "VERSION", "style": "dim white"},
        )
        for svc in services:
            svc = _d(svc)
            port = svc.get("port", "")
            port_str = f"[bold red]{port}[/bold red]" if port in [21, 23, 3389, 5900, 445] else str(port)
            table.add_row(
                port_str,
                str(svc.get("protocol", "tcp")),
                str(svc.get("service", "")),
                escape(str(svc.get("version", ""))),
            )
        return self._panel("NETWORK", table, len(services) or None)

    def _section_cve(self, cve_mod: Dict):
        cve_list = _l(_d(cve_mod).get("cves"))
        if not cve_list:
            return None
        scored = []
        for cve in cve_list:
            sev = _cve_sev(cve)
            scored.append((sev.get("score"), sev.get("severity", "N/A"), cve))
        scored.sort(key=lambda x: (-(x[0] if isinstance(x[0], (int, float)) else 0)))
        table = self._table(
            None, "CVE ID", "CVSS", "SEVERITY", "DESCRIPTION"
        )
        for score, severity, cve in scored[:12]:
            cve = _d(cve)
            table.add_row(
                str(cve.get("id", "")),
                str(score) if score is not None else "N/A",
                Text(str(severity), style=sev_style(severity)),
                escape(str(cve.get("description", ""))[:65]),
            )
        return self._panel("CVE CORRELATION", table, len(cve_list))

    def _section_mitre(self, mitre: Dict):
        mitre = _d(mitre)
        findings = _l(mitre.get("findings"))
        if not findings:
            return None
        table = self._table(None, "TECHNIQUE", "NAME", "TACTIC", "SEVERITY")
        for f in findings:
            f = _d(f)
            severity = str(f.get("severity", ""))
            table.add_row(
                str(f.get("technique_id", "")),
                escape(str(f.get("technique_name", ""))[:44]),
                str(f.get("tactic", "")),
                Text(severity, style=sev_style(severity)),
            )
        return self._panel("MITRE ATT&CK", table, mitre.get("total_findings", len(findings)))

    def _section_chains(self, chains: List):
        chains = _l(chains)
        if not chains:
            return None
        body = Table.grid(padding=(0, 1))
        body.add_column()
        for chain in chains[:5]:
            chain = _d(chain)
            risk = chain.get("risk_score", 0) or 0
            rc = "bold red" if risk >= 80 else "bold dark_orange" if risk >= 50 else "bold green"
            line = Text()
            line.append("▸ ", style=rc)
            line.append(str(chain.get("name", "chain")), style="bold white")
            line.append(f"  RISK {risk}/100", style=rc)
            line.append(f"  {chain.get('difficulty', '')}", style="dim")
            body.add_row(line)
            for step in _l(chain.get("steps"))[:4]:
                step = _d(step)
                body.add_row(
                    Text.assemble(
                        ("    └─ ", "bright_black"),
                        (f"Step {step.get('step', '?')}: ", "dim"),
                        (str(step.get("action", ""))[:66], "white"),
                    )
                )
        return self._panel("ATTACK CHAINS", body, len(chains))

    def _section_ai(self, ai: Dict):
        ai = _d(ai)
        if not ai:
            return None
        body = Table.grid(padding=(0, 1))
        body.add_column()
        rs = _d(ai.get("risk_score"))
        if rs:
            score = rs.get("score", 0) or 0
            severity = str(rs.get("severity", "INFO") or "INFO")
            line = Text()
            line.append(_gauge(score, width=24, color=SCORE_COLORS.get(severity.upper(), "cyan")))
            line.append(f"  {score}/100", style=f"bold {SCORE_COLORS.get(severity.upper(), 'white')}")
            line.append(f"  [{severity}]", style=f"bold {SCORE_COLORS.get(severity.upper(), 'white')}")
            body.add_row(line)
        for key in ("summary", "analysis", "recommendation"):
            if ai.get(key):
                body.add_row(Text())
                body.add_row(Text(str(ai.get(key))[:400], style="white"))
                break
        extra_keys = [k for k in ai.keys() if k not in ("risk_score", "summary", "analysis", "recommendation")]
        if extra_keys:
            body.add_row(Text())
            for k in extra_keys[:6]:
                body.add_row(Text.assemble(("  ▸ ", "bright_black"), (f"{k}: ", "dim"), (str(ai.get(k))[:80], "white")))
        return self._panel("AI ANALYSIS", body)

    def _generic_section(self, name: str, data: Dict):
        """Fallback renderer for modules without a bespoke layout."""
        rows = []
        for key, value in _d(data).items():
            if isinstance(value, (str, int, float, bool)) and value not in ("", None):
                rows.append((key, Text(str(value)[:100])))
            elif isinstance(value, list) and value and all(isinstance(v, (str, int, float)) for v in value[:3]):
                rows.append((key, Text(", ".join(str(v) for v in value[:5])[:100])))
        if not rows:
            return None
        return self._panel(name.upper(), self._kv_grid(rows))

    def print_full_results(self, results: Dict):
        """Detailed per-module breakdown — one rounded panel per module."""
        results = _d(results)
        modules = _d(results.get("modules"))

        self.print_summary(results)

        self.console.print()
        self.console.print(
            Rule("[bold cyan]  ◈ FULL RESULTS BY MODULE[/bold cyan]", style="bright_black")
        )
        self.console.print()

        # DNS
        dns = _d(modules.get("dns"))
        if dns:
            self.console.print(self._section_dns(dns))
            self.console.print()

        # Certificates (CT)
        certs = _d(modules.get("certs"))
        cert_subs = _l(certs.get("subdomains"))
        if certs:
            if cert_subs:
                self.console.print(self._section_list("CERT TRANSPARENCY", cert_subs, len(cert_subs)))
            else:
                self.console.print(
                    self._panel("CERT TRANSPARENCY", Text("No CT data collected.", style="dim"))
                )
            self.console.print()

        # Wayback
        wayback = _d(modules.get("wayback"))
        if wayback:
            rows = [("Total snapshots", Text(str(wayback.get("total_snapshots", 0) or 0)))]
            by_year = _d(wayback.get("by_year"))
            if by_year:
                top_years = sorted(by_year.items(), key=lambda kv: -int(kv[1] or 0))[:5]
                rows.append(("Most active years", Text(", ".join(f"{y} ({c})" for y, c in top_years))))
            urls = _l(wayback.get("interesting_urls"))
            if urls:
                sample = Table.grid(padding=(0, 2))
                sample.add_column()
                for u in urls[:5]:
                    u = _d(u) if isinstance(u, dict) else {"url": u}
                    sample.add_row(Text.assemble(("  ▸ ", "bright_black"), (str(u.get("url", "")), "white")))
                body = Group(self._kv_grid(rows), Text(), sample)
            else:
                body = self._kv_grid(rows)
            self.console.print(
                self._panel("WAYBACK MACHINE", body, wayback.get("total_snapshots", 0) or None)
            )
            self.console.print()

        # Network
        net = _d(modules.get("network"))
        if net:
            section = self._section_network(net)
            if section:
                self.console.print(section)
            else:
                self.console.print(
                    self._panel("NETWORK", Text("No open ports discovered.", style="dim"))
                )
            self.console.print()

        # Web technologies
        web = _d(modules.get("web"))
        if web:
            techs = _l(_d(web.get("technologies")).get("technologies"))
            body_rows = []
            if techs:
                chips = Text()
                for i, tech in enumerate(techs):
                    chips.append(f" {tech} ", style="bold white on #1e3a5f")
                    if i < len(techs) - 1:
                        chips.append(" ", style="")
                body_rows.append(("Detected", chips))
            server = _d(web.get("technologies")).get("server")
            if server:
                body_rows.append(("Server", Text(str(server))))
            if body_rows:
                self.console.print(self._panel("WEB STACK", self._kv_grid(body_rows)))
            else:
                self.console.print(
                    self._panel("WEB STACK", Text("No technologies fingerprinted.", style="dim"))
                )
            self.console.print()

        # Endpoints
        endpoints = _d(modules.get("endpoints"))
        if endpoints:
            found = _l(endpoints.get("found"))
            sensitive = _l(endpoints.get("sensitive"))
            if found or sensitive:
                table = self._table(None, "STATUS", "PATH", "SIZE")
                for ep in found[:15]:
                    ep = _d(ep)
                    table.add_row(
                        str(ep.get("status", "")),
                        escape(str(ep.get("path", ""))),
                        str(ep.get("size", "")),
                    )
                for ep in sensitive[:10]:
                    ep = _d(ep)
                    table.add_row(
                        Text(f"⚠ {ep.get('status', '')}", style="bold red"),
                        Text(f"{ep.get('path', '')}", style="bold red"),
                        str(ep.get("size", "")),
                    )
                self.console.print(
                    self._panel("ENDPOINT DISCOVERY", table, endpoints.get("total_found", len(found)))
                )
            else:
                self.console.print(
                    self._panel("ENDPOINT DISCOVERY", Text("No endpoints discovered.", style="dim"))
                )
            self.console.print()

        # Cloud buckets
        cloud = _d(modules.get("cloud_buckets"))
        if cloud:
            found = _l(cloud.get("found"))
            if found:
                table = self._table(None, "URL", "PROVIDER", "STATE")
                for b in found:
                    b = _d(b)
                    state = (
                        Text("PUBLIC", style="bold red")
                        if b.get("public")
                        else Text("private", style="bright_black")
                    )
                    table.add_row(escape(str(b.get("url", ""))), str(b.get("provider", "")), state)
                self.console.print(self._panel("CLOUD STORAGE", table, len(found)))
            else:
                self.console.print(
                    self._panel("CLOUD STORAGE", Text("No cloud buckets discovered.", style="dim"))
                )
            self.console.print()

        # Emails
        emails = _d(modules.get("emails"))
        email_list = _l(emails.get("emails_found"))
        if emails:
            if email_list:
                self.console.print(self._section_list("EMAIL ADDRESSES", email_list, len(email_list)))
            else:
                self.console.print(
                    self._panel("EMAIL ADDRESSES", Text("No email addresses enumerated.", style="dim"))
                )
            self.console.print()

        # GitHub
        github = _d(modules.get("github"))
        if github:
            findings = _l(github.get("findings"))
            if findings:
                table = self._table(None, "TYPE", "MATCH", "URL")
                for f in findings[:10]:
                    f = _d(f) if isinstance(f, dict) else {"match": f}
                    table.add_row(
                        str(f.get("type", f.get("kind", ""))),
                        escape(str(f.get("match", f.get("text", "")))[:50]),
                        escape(str(f.get("url", ""))[:60]),
                    )
                self.console.print(
                    self._panel("GITHUB LEAKS", table, github.get("total_findings", len(findings)))
                )
            elif github.get("total_findings"):
                self.console.print(
                    self._panel(
                        "GITHUB LEAKS",
                        Text(f"{github.get('total_findings')} potential leaks detected.", style="bold red"),
                    )
                )
            else:
                self.console.print(
                    self._panel("GITHUB LEAKS", Text("No leaks found in public repositories.", style="dim"))
                )
            self.console.print()

        # Google dorking
        google = _d(modules.get("google"))
        if google:
            results_list = _l(google.get("results"))
            if results_list:
                self.console.print(self._section_list("GOOGLE DORKING", results_list, len(results_list)))
            else:
                self.console.print(
                    self._panel("GOOGLE DORKING", Text("No indexed results found.", style="dim"))
                )
            self.console.print()

        # CVE
        cve_section = self._section_cve(modules.get("cve"))
        if cve_section:
            self.console.print(cve_section)
            self.console.print()

        # Permutation
        permutation = _d(modules.get("permutation"))
        if permutation:
            perms = _l(permutation.get("subdomains"))
            total = permutation.get("total_found", len(perms)) or 0
            if perms:
                self.console.print(self._section_list("SUBDOMAIN PERMUTATION", perms, total))
            else:
                self.console.print(
                    self._panel("SUBDOMAIN PERMUTATION", Text("No new permutations resolved.", style="dim"))
                )
            self.console.print()

        # Takeover
        takeover = _d(modules.get("takeover"))
        if takeover:
            vulns = _l(takeover.get("vulnerable"))
            if vulns:
                table = self._table(None, "SUBDOMAIN", "SERVICE", "SIGNATURE")
                for v in vulns[:10]:
                    v = _d(v)
                    table.add_row(
                        Text(str(v.get("subdomain", "")), style="bold red"),
                        str(v.get("service", "")),
                        escape(str(v.get("signature", ""))[:40]),
                    )
                self.console.print(self._panel("SUBDOMAIN TAKEOVER", table, len(vulns)))
            else:
                self.console.print(
                    self._panel("SUBDOMAIN TAKEOVER", Text("✔ No takeover vulnerabilities detected.", style="green"))
                )
            self.console.print()

        # CDN/WAF
        cdn = _d(modules.get("cdn_waf"))
        if cdn:
            rows = [
                ("CDN", Text(str(cdn.get("cdn") or "None detected"), style="green" if cdn.get("cdn") else "dim")),
                ("WAF", Text(str(cdn.get("waf") or "None detected"), style="red" if cdn.get("waf") else "dim")),
            ]
            self.console.print(self._panel("CDN / WAF DETECTION", self._kv_grid(rows)))
            self.console.print()

        # MITRE
        mitre_section = self._section_mitre(results.get("mitre"))
        if mitre_section:
            self.console.print(mitre_section)
            self.console.print()

        # Attack chains
        chains_section = self._section_chains(results.get("attack_chains"))
        if chains_section:
            self.console.print(chains_section)
            self.console.print()

        # AI analysis
        ai_section = self._section_ai(results.get("ai_analysis"))
        if ai_section:
            self.console.print(ai_section)
            self.console.print()

        # Fallback for any module without a bespoke renderer (e.g. whois)
        handled = {
            "dns", "certs", "wayback", "network", "web", "endpoints",
            "cloud_buckets", "emails", "github", "google", "cve",
            "permutation", "takeover", "cdn_waf",
        }
        for name, data in modules.items():
            if name in handled or not isinstance(data, dict):
                continue
            section = self._generic_section(name, data)
            if section:
                self.console.print(section)
                self.console.print()

        # Errors
        errors = _l(results.get("errors"))
        if errors:
            self.print_errors(errors)
            self.console.print()

    # ─────────────────────────────────────────────────────────────────────
    # EXPORT TABLE
    # ─────────────────────────────────────────────────────────────────────
    def print_exports(self, exports: Dict):
        """Render the exported-files manifest."""
        table = self._table(
            "Exported Files",
            {"header": "FORMAT", "style": "cyan", "width": 16},
            {"header": "PATH", "style": "white"},
        )
        for fmt, path in _d(exports).items():
            if isinstance(path, list):
                for p in path:
                    table.add_row(str(fmt).upper(), escape(str(p)))
            else:
                table.add_row(str(fmt).upper(), escape(str(path)))
        self.console.print(Padding(table, (0, 2)))
