"""OSINT EYE - Interactive TUI with Textual"""

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Label, Static, Button
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.screen import Screen
from rich.text import Text
from rich.table import Table as RichTable
import json
from datetime import datetime


class ScanScreen(Screen):
    """Main scan screen"""

    def __init__(self, results: dict = None):
        super().__init__()
        self.results = results or {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

        with Container(id="main-container"):
            yield Label(f"OSINT EYE - Scan Results", id="title")
            yield Label(
                f"Target: {self.results.get('target', 'N/A')}", id="target-info"
            )

            with Vertical(id="panels"):
                yield DataTable(id="dns-table")
                yield DataTable(id="network-table")
                yield DataTable(id="findings-table")

    def on_mount(self):
        self._populate_dns()
        self._populate_network()
        self._populate_findings()

    def _populate_dns(self):
        table = self.query_one("#dns-table", DataTable)
        table.add_columns("Type", "Value")

        dns = self.results.get("modules", {}).get("dns", {})
        records = dns.get("records", {})

        for rtype, values in records.items():
            if values:
                table.add_row(rtype, ", ".join(values[:5]))

        subs = dns.get("subdomains", [])
        if subs:
            table.add_row("Subdomains", f"{len(subs)} found")

    def _populate_network(self):
        table = self.query_one("#network-table", DataTable)
        table.add_columns("Port", "Protocol", "Service", "Version")

        net = self.results.get("modules", {}).get("network", {})
        for svc in net.get("services", []):
            if svc.get("state") == "open":
                table.add_row(
                    str(svc.get("port", "")),
                    svc.get("protocol", ""),
                    svc.get("service", ""),
                    svc.get("version", ""),
                )

    def _populate_findings(self):
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Category", "Finding", "Severity")

        web = self.results.get("modules", {}).get("web", {})
        techs = web.get("technologies", {}).get("technologies", [])
        for tech in techs:
            table.add_row("Technology", tech, "INFO")

        buckets = (
            self.results.get("modules", {}).get("cloud_buckets", {}).get("public", [])
        )
        for b in buckets:
            table.add_row("Cloud Bucket", b.get("url", ""), "HIGH")


class DashboardScreen(Screen):
    """Dashboard overview screen"""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

        with Container(id="dashboard"):
            yield Label("OSINT EYE Dashboard", id="dash-title")

            with Horizontal(id="stats-row"):
                yield Static("0", id="stat-subdomains")
                yield Static("0", id="stat-ports")
                yield Static("0", id="stat-cves")
                yield Static("0", id="stat-emails")

            yield DataTable(id="recent-scans")


class OSINTEyeTUI(App):
    """Main TUI Application"""

    CSS = """
    Screen {
        background: $surface;
    }

    #main-container {
        padding: 1 2;
    }

    #title {
        text-style: bold;
        color: $primary;
        padding: 1 0;
    }

    #target-info {
        color: $text-muted;
        padding-bottom: 1;
    }

    DataTable {
        height: 10;
        margin: 1 0;
    }

    #panels {
        layout: vertical;
    }

    #dashboard {
        padding: 1 2;
    }

    #dash-title {
        text-style: bold;
        color: $primary;
        padding: 1 0;
    }

    #stats-row {
        layout: horizontal;
        height: 5;
    }

    #stat-subdomains, #stat-ports, #stat-cves, #stat-emails {
        width: 1fr;
        background: $panel;
        border: solid $primary;
        padding: 1;
        margin: 0 1;
    }
    """

    def __init__(self, results: dict = None):
        super().__init__()
        self.results = results or {}

    def on_mount(self):
        self.push_screen(ScanScreen(self.results))

    def action_quit(self):
        self.exit()


def launch_tui(results: dict = None):
    """Launch the TUI"""
    app = OSINTEyeTUI(results)
    app.run()


if __name__ == "__main__":
    test_results = {
        "target": "example.com",
        "modules": {
            "dns": {
                "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
                "subdomains": ["www.example.com", "api.example.com"],
            },
            "network": {
                "services": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "state": "open",
                        "version": "Apache",
                    },
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service": "https",
                        "state": "open",
                    },
                ]
            },
        },
    }
    launch_tui(test_results)
