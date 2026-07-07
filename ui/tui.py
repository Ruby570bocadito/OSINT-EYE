"""OSINT EYE - Terminal UI (Rich)"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
import json
from datetime import datetime


console = Console()


def print_banner():
    """Print OSINT EYE banner"""
    console.print(
        Panel.fit(
            """
[bold cyan]OSINT EYE[/bold cyan] - AI-Powered Attack Surface Intelligence
        
[dim]Version 1.0 | 100% Free - No API Keys Required[/dim]
        """,
            border_style="cyan",
            padding=(1, 2),
        )
    )


def print_module_result(name: str, data: dict):
    """Print module result in a nice table"""
    if name == "dns":
        table = Table(title="[cyan]DNS Records[/cyan]", box=box.ROUNDED)
        table.add_column("Record Type", style="yellow")
        table.add_column("Value", style="white")

        for rtype, values in data.get("records", {}).items():
            if values:
                table.add_row(rtype, ", ".join(values[:3]))

        if data.get("subdomains"):
            table.add_row("Subdomains", f"{len(data['subdomains'])} found")

        console.print(table)

    elif name == "certs":
        table = Table(title="[cyan]Certificate Transparency[/cyan]", box=box.ROUNDED)
        table.add_column("Subdomain", style="white")
        table.add_column("Issuer", style="yellow")

        for sub in data.get("subdomains", [])[:10]:
            table.add_row(sub, "")

        console.print(table)

    elif name == "wayback":
        if data.get("total_snapshots", 0) > 0:
            table = Table(title="[cyan]Wayback Machine[/cyan]", box=box.ROUNDED)
            table.add_column("Year", style="yellow")
            table.add_column("Snapshots", style="white")

            for year, count in data.get("by_year", {}).items():
                table.add_row(year, str(count))

            console.print(table)

            if data.get("interesting_urls"):
                console.print("\n[yellow]Interesting URLs:[/yellow]")
                for url in data["interesting_urls"][:5]:
                    console.print(f"  [{url['pattern']}] {url['url']}")

    elif name == "network":
        table = Table(title="[cyan]Network Services[/cyan]", box=box.ROUNDED)
        table.add_column("Port", style="yellow")
        table.add_column("Protocol", style="cyan")
        table.add_column("Service", style="white")
        table.add_column("Version", style="dim")

        for svc in data.get("services", []):
            if svc.get("state") == "open":
                table.add_row(
                    str(svc.get("port", "")),
                    svc.get("protocol", ""),
                    svc.get("service", ""),
                    svc.get("version", ""),
                )

        console.print(table)

    elif name == "whois":
        if data.get("domain"):
            table = Table(title="[cyan]WHOIS Info[/cyan]", box=box.ROUNDED)
            table.add_column("Field", style="yellow")
            table.add_column("Value", style="white")

            fields = [
                "domain",
                "registrar",
                "creation_date",
                "expiration_date",
                "name_servers",
            ]
            for field in fields:
                if data.get(field):
                    value = data[field]
                    if isinstance(value, list):
                        value = ", ".join(value[:3])
                    table.add_row(field.replace("_", " ").title(), str(value))

            console.print(table)

    elif name == "cve":
        cves = data.get("cves", [])
        if cves:
            table = Table(
                title=f"[cyan]CVEs Found: {len(cves)}[/cyan]", box=box.ROUNDED
            )
            table.add_column("CVE ID", style="yellow")
            table.add_column("Score", style="red")
            table.add_column("Severity", style="white")
            table.add_column("Description", style="dim")

            for cve in cves[:10]:
                severity_data = (
                    cve.get("severity", [{}])[0] if cve.get("severity") else {}
                )
                score = severity_data.get("score", "N/A")
                sev = severity_data.get("severity", "N/A")
                desc = cve.get("description", "")[:50]

                table.add_row(cve.get("id", ""), str(score), sev, desc)

            console.print(table)


def print_summary(results: dict):
    """Print final summary"""
    console.print("\n")

    summary_table = Table(title="[bold green]Scan Summary[/bold green]", box=box.DOUBLE)
    summary_table.add_column("Module", style="cyan")
    summary_table.add_column("Results", style="white")

    modules_data = [
        ("DNS", len(results.get("modules", {}).get("dns", {}).get("subdomains", []))),
        (
            "Certs",
            len(results.get("modules", {}).get("certs", {}).get("subdomains", [])),
        ),
        (
            "Wayback",
            results.get("modules", {}).get("wayback", {}).get("total_snapshots", 0),
        ),
        (
            "Network",
            len(
                [
                    s
                    for s in results.get("modules", {})
                    .get("network", {})
                    .get("services", [])
                    if s.get("state") == "open"
                ]
            ),
        ),
        ("CVE", len(results.get("modules", {}).get("cve", {}).get("cves", []))),
    ]

    for module, count in modules_data:
        summary_table.add_row(module, str(count))

    console.print(summary_table)

    if results.get("ai_analysis", {}).get("risk_score"):
        risk = results["ai_analysis"]["risk_score"]
        color = "red" if risk["severity"] in ["CRITICAL", "HIGH"] else "yellow"
        console.print(
            f"\n[bold {color}]Risk Score: {risk['score']}/100 - {risk['severity']}[/bold {color}]"
        )


def print_progress(message: str):
    """Print progress message"""
    console.print(f"[dim][*] {message}[/dim]")


def print_error(message: str):
    """Print error message"""
    console.print(f"[red][!] {message}[/red]")


def print_success(message: str):
    """Print success message"""
    console.print(f"[green][+] {message}[/green]")


def print_json(data: dict):
    """Print data as formatted JSON"""
    console.print(
        Panel.fit(
            json.dumps(data, indent=2, default=str)[:2000],
            title="JSON Output",
            border_style="green",
        )
    )


class OSINTTUI:
    """Interactive TUI for OSINT EYE"""

    def __init__(self):
        self.console = Console()

    def run_interactive(self, target: str):
        """Run interactive scan"""
        print_banner()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            progress.add_task(f"Scanning {target}...", total=None)

    def display_results(self, results: dict):
        """Display scan results"""
        print_banner()

        for module_name, data in results.get("modules", {}).items():
            print_module_result(module_name, data)

        print_summary(results)


if __name__ == "__main__":
    print_banner()
    console.print("\n[yellow]TUI Module Ready[/yellow]")
    console.print("[dim]Import this module in osint_eye.py to use[/dim]")
