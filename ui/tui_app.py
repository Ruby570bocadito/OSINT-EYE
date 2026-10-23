"""OSINT EYE - Interactive TUI with Textual (navegable, offline).

Estructura:
- ``ScanScreen``: TabbedContent con pestañas Overview / Assets / DNS /
  Network / Findings. La pestaña Assets muestra la vista canónica de
  activos (``ui.dashboard._collect_assets``) con filtro de texto y abre la
  ficha de detalle de cada activo con Enter.
- ``AssetDetailScreen``: ficha modal del activo — módulos que lo reportan,
  severidad por módulo y evidencia agregada.
- Atajos: 1-5 salta de pestaña, ``ctrl+f`` enfoca el filtro, ``q`` sale.

Todo es 100 % offline: solo lee el dict ``results`` en memoria.
"""

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen, ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static
from textual.widgets import TabbedContent, TabPane

# Estado / severidad con el mismo vocabulario que el resto de la UI.
_SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_TABS = ("Overview", "Assets", "DNS", "Network", "Findings")


def _sev_markup(severity: str) -> str:
    sev = (severity or "info").lower()
    style = _SEV_STYLE.get(sev, "dim")
    return f"[{style}]{sev.upper()}[/]"


class ScanScreen(Screen):
    """Pantalla principal: resultados navegable por pestañas."""

    BINDINGS = [
        Binding("ctrl+f,slash", "focus_filter", "Find"),
    ]

    def __init__(self, results: dict = None):
        super().__init__()
        self.results = results or {}
        self._row_map: dict = {}

    # -- layout ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()
        with TabbedContent(id="tabs"):
            with TabPane("Overview", id="tab-overview"):
                yield VerticalScroll(id="overview")
            with TabPane("Assets", id="tab-assets"):
                yield Input(
                    placeholder="Filter by type / asset / module / detail… "
                                "(ctrl+f)",
                    id="asset-filter",
                )
                yield DataTable(id="assets-table", cursor_type="row")
            with TabPane("DNS", id="tab-dns"):
                yield VerticalScroll(id="dns-pane")
            with TabPane("Network", id="tab-network"):
                yield VerticalScroll(id="network-pane")
            with TabPane("Findings", id="tab-findings"):
                yield VerticalScroll(id="findings-pane")

    def on_mount(self):
        self._build_overview()
        self._populate_assets(self._all_assets())
        self._populate_dns()
        self._populate_network()
        self._populate_findings()

    # -- datos (pura memoria, degradación grácil) ---------------------------------
    @staticmethod
    def _coerce_record_values(values) -> list:
        """Normalise a record value payload to a list of strings.

        A bare string ("A": "1.2.3.4") used to be joined character by
        character ("1, ., 2, ., 3"); non-iterable junk is dropped.
        """
        if isinstance(values, str):
            return [values]
        if isinstance(values, (list, tuple, set)):
            return [str(v) for v in values]
        return []

    def _all_assets(self) -> list:
        """Canonical asset view — reuse of the dashboard flattener.

        Imported lazily so ``import ui.tui_app`` never drags Flask in; if
        the ui extra is missing the TUI degrades to an honest empty table
        instead of crashing.
        """
        try:
            from ui.dashboard import _collect_assets
        except Exception:
            return []
        try:
            return _collect_assets(self.results)
        except Exception:
            return []

    @staticmethod
    def _filter_assets(assets: list, query: str) -> list:
        """Case-insensitive substring filter over type/name/module/detail."""
        needle = (query or "").strip().lower()
        if not needle:
            return list(assets)
        return [
            a for a in assets
            if needle in str(a.get("type", "")).lower()
            or needle in str(a.get("name", "")).lower()
            or needle in str(a.get("module", "")).lower()
            or needle in str(a.get("detail", "")).lower()
        ]

    @staticmethod
    def _severity_counts(assets: list) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for a in assets:
            sev = str(a.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _modules_reporting(assets: list, name: str) -> list:
        """All (module, severity, detail) rows that report ``name``."""
        key = str(name or "").strip().lower()
        rows = []
        for a in assets:
            if str(a.get("name", "")).strip().lower() == key and key:
                rows.append((a.get("module", "?"),
                             str(a.get("severity", "info")).lower(),
                             a.get("detail", "")))
        return rows

    @staticmethod
    def _type_counts(assets: list) -> dict:
        counts: dict = {}
        for a in assets:
            counts[a.get("type", "?")] = counts.get(a.get("type", "?"), 0) + 1
        return counts

    # -- pestañas ------------------------------------------------------------------
    def _build_overview(self):
        pane = self.query_one("#overview", VerticalScroll)
        results = self.results if isinstance(self.results, dict) else {}
        assets = self._all_assets()
        by_type = self._type_counts(assets)
        sevs = self._severity_counts(assets)

        meta = results.get("meta") or {}
        target = results.get("target") or "unknown"
        date = results.get("scan_date") or "—"
        depth = str(results.get("depth") or "—").upper()
        pane.mount(Label(f"[bold]Target:[/] {target}    "
                         f"[bold]Date:[/] {date}    [bold]Depth:[/] {depth}",
                         id="ov-meta"))

        score_info = results.get("correlation", {}).get("attack_surface_score") \
            if isinstance(results.get("correlation"), dict) else {}
        score_info = score_info if isinstance(score_info, dict) else {}
        score = score_info.get("score", "–")
        severity = str(score_info.get("severity", "")).lower() or "unknown"
        pane.mount(Label(
            f"[bold]Attack surface score:[/] {score} "
            f"({_sev_markup(severity)})", id="ov-score"))

        order = ["subdomain", "port", "tech", "email", "cve", "bucket",
                 "technique"]
        chips = "    ".join(
            f"[bold]{by_type.get(t, 0)}[/] {t}" for t in order if by_type.get(t)
        )
        pane.mount(Label(chips or "No assets collected", id="ov-types"))

        sev_line = "    ".join(
            f"{_sev_markup(s)}: {n}" for s, n in sevs.items() if n
        )
        pane.mount(Label(sev_line or "No findings", id="ov-sevs"))

        if not assets:
            try:
                from ui.dashboard import _collect_assets  # noqa: F401
            except Exception:
                pane.mount(Label(
                    "[yellow]Asset view unavailable: the ui extra is not "
                    "installed (pip install -e '.[ui]').[/yellow]",
                    id="ov-warning"))

    def _populate_assets(self, assets: list):
        table = self.query_one("#assets-table", DataTable)
        self._row_map = {}
        table.clear(columns=True)
        table.add_columns("Severity", "Type", "Asset", "Module", "Detail")
        for a in assets:
            key = f"{a.get('type')}|{a.get('name')}|{a.get('module')}"
            self._row_map[key] = a
            table.add_row(
                _sev_markup(str(a.get("severity", "info")).lower()),
                str(a.get("type", "")),
                str(a.get("name", "")),
                str(a.get("module", "")),
                str(a.get("detail", ""))[:80],
                key=key,
            )

    def _populate_dns(self):
        pane = self.query_one("#dns-pane", VerticalScroll)
        dns = self.results.get("modules", {}).get("dns", {}) \
            if isinstance(self.results.get("modules"), dict) else {}
        if not isinstance(dns, dict):
            dns = {}

        records_table = DataTable(id="dns-records")
        records_table.add_columns("Type", "Value")
        records = dns.get("records", {})
        if not isinstance(records, dict):
            records = {}
        for rtype, values in records.items():
            values = self._coerce_record_values(values)
            if values:
                records_table.add_row(str(rtype), ", ".join(values[:8]))
        pane.mount(records_table)

        subs = dns.get("subdomains", [])
        pane.mount(Label(f"[bold]{len(subs)}[/] subdomains found",
                         id="dns-subs"))
        if subs:
            sub_table = DataTable(id="dns-subdomains")
            sub_table.add_columns("Subdomain")
            for sub in subs[:200]:
                sub_table.add_row(str(sub))
            pane.mount(sub_table)

    def _populate_network(self):
        pane = self.query_one("#network-pane", VerticalScroll)
        modules = self.results.get("modules", {}) \
            if isinstance(self.results.get("modules"), dict) else {}
        net = modules.get("network", {}) if isinstance(modules.get("network"),
                                                       dict) else {}
        table = DataTable(id="network-table")
        table.add_columns("Port", "Protocol", "Service", "Version")
        for svc in net.get("services", []) or []:
            if not isinstance(svc, dict) or svc.get("state") != "open":
                continue
            table.add_row(
                str(svc.get("port", "")),
                str(svc.get("protocol", "")),
                str(svc.get("service", "")),
                str(svc.get("version", "")),
            )
        pane.mount(table)

    def _populate_findings(self):
        pane = self.query_one("#findings-pane", VerticalScroll)
        modules = self.results.get("modules", {}) \
            if isinstance(self.results.get("modules"), dict) else {}

        table = DataTable(id="findings-table")
        table.add_columns("Severity", "Category", "Finding", "Detail")

        cves = modules.get("cve", {}).get("cves", []) \
            if isinstance(modules.get("cve"), dict) else []
        for cve in cves or []:
            if not isinstance(cve, dict):
                continue
            sev_list = cve.get("severity") or []
            sev = sev_list[0].get("severity", "info") \
                if sev_list and isinstance(sev_list[0], dict) else "info"
            desc = str(cve.get("description") or "")[:80]
            table.add_row(_sev_markup(str(sev).lower()), "CVE",
                          str(cve.get("id", "")), desc)

        buckets = modules.get("cloud_buckets", {}).get("found", []) \
            if isinstance(modules.get("cloud_buckets"), dict) else []
        for b in buckets or []:
            if not isinstance(b, dict):
                continue
            sev = "high" if b.get("public") else "info"
            table.add_row(_sev_markup(sev), "Cloud bucket",
                          str(b.get("url", b.get("bucket", ""))),
                          str(b.get("provider", "")))

        for name, module in (("Emails", "emails"), ("Technologies", "web")):
            data = modules.get(module, {})
            if not isinstance(data, dict):
                continue
            items = data.get("emails_found", []) if module == "emails" \
                else (data.get("technologies", {}).get("technologies", [])
                      if isinstance(data.get("technologies"), dict) else [])
            for item in items or []:
                if isinstance(item, str):
                    table.add_row(_sev_markup("info"), name, item, "")

        mitre = self.results.get("mitre", {}) \
            if isinstance(self.results.get("mitre"), dict) else {}
        for f in mitre.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            table.add_row(
                _sev_markup(str(f.get("severity", "info")).lower()),
                "MITRE",
                f"{f.get('technique_id', '')} {f.get('technique_name', '')}"
                .strip(),
                str(f.get("tactic", "")),
            )
        pane.mount(table)

    # -- interacción ---------------------------------------------------------------
    def on_key(self, event) -> None:
        """Atajos 1-5 para saltar de pestaña (los Input consumen los dígitos
        cuando tienen el foco, así que escribir en el filtro nunca salta)."""
        if event.key in {"1", "2", "3", "4", "5"}:
            index = int(event.key) - 1
            if 0 <= index < len(_TABS):
                self.query_one("#tabs", TabbedContent).active = (
                    f"tab-{_TABS[index].lower()}"
                )

    def action_focus_filter(self) -> None:
        self.query_one("#asset-filter", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "asset-filter":
            return
        self._populate_assets(self._filter_assets(self._all_assets(),
                                                  event.value))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "assets-table":
            return
        asset = self._row_map.get(str(event.row_key.value or ""))
        if asset is not None:
            self.app.push_screen(AssetDetailScreen(asset,
                                                   self._all_assets()))


class AssetDetailScreen(ModalScreen):
    """Ficha del activo: módulos que lo reportan, severidad y evidencia."""

    BINDINGS = [
        Binding("escape,enter,q", "dismiss_detail", "Close"),
    ]

    def __init__(self, asset: dict, all_assets: list):
        super().__init__()
        self.asset = asset or {}
        self.all_assets = all_assets or []

    def compose(self) -> ComposeResult:
        name = str(self.asset.get("name", ""))
        related = ScanScreen._modules_reporting(self.all_assets, name)
        lines = [
            f"[bold]{name}[/bold]",
            f"Type: {self.asset.get('type', '—')}    "
            f"Severity: {_sev_markup(str(self.asset.get('severity', 'info')).lower())}",
            "",
            "[bold]Reported by[/bold]",
        ]
        for module, sev, detail in related:
            line = f"  • {module} — {_sev_markup(sev)}"
            if detail:
                line += f" — {detail}"
            lines.append(line)
        if not related:
            lines.append("  • (no modules reported this asset)")
        lines.append("")
        lines.append("[dim]esc/enter/q to close[/dim]")

        yield VerticalScroll(
            Static("\n".join(lines), id="detail-card"),
            id="detail-wrap",
        )

    def action_dismiss_detail(self) -> None:
        self.app.pop_screen()


class OSINTEyeTUI(App):
    """Main TUI Application — navegable, offline."""

    CSS = """
    Screen { background: $surface; }
    #tabs { height: 1fr; }
    DataTable { height: auto; max-height: 1fr; margin: 0 0 1 0; }
    #asset-filter { margin-bottom: 1; }
    #overview, #dns-pane, #network-pane, #findings-pane { padding: 1 2; }
    #overview Label, #dns-pane Label { margin-bottom: 1; }
    #detail-wrap { align: center middle; padding: 2 6; }
    #detail-card {
        background: $panel; border: solid $primary; padding: 1 3;
        width: 90%; max-height: 80%;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, results: dict = None):
        super().__init__()
        self.results = results or {}

    def on_mount(self):
        self.push_screen(ScanScreen(self.results))


def launch_tui(results: dict = None):
    """Launch the TUI"""
    app = OSINTEyeTUI(results)
    app.run()


if __name__ == "__main__":
    from ui.tui_app import launch_tui as _lt  # pragma: no cover

    _lt({
        "target": "example.com",
        "scan_date": "2026-10-23T00:00:00",
        "depth": "normal",
        "correlation": {"attack_surface_score": {"score": 42,
                                                 "severity": "MEDIUM"}},
        "modules": {
            "dns": {
                "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
                "subdomains": ["www.example.com", "api.example.com"],
            },
            "network": {"services": [
                {"port": 80, "protocol": "tcp", "service": "http",
                 "state": "open", "version": "nginx"},
                {"port": 443, "protocol": "tcp", "service": "https",
                 "state": "open"},
            ]},
            "cve": {"cves": [{"id": "CVE-2024-0001",
                              "severity": [{"severity": "high", "score": 7.5}],
                              "description": "example"}]},
        },
        "mitre": {"findings": [{"technique_id": "T1595",
                                "technique_name": "Active Scanning",
                                "severity": "medium",
                                "tactic": "Reconnaissance"}]},
    })
