"""OSINT EYE - Main Entry Point with Async, Cache & Multi-Target"""

import argparse
import sys
import json
import asyncio
import re
from typing import Optional
from datetime import datetime
from pathlib import Path

from modules.dns import DNSScanner
from modules.dns.subdomain_permutator import (
    SubdomainPermutator,
    SubdomainTakeoverDetector,
)
from modules.certs import CertScanner
from modules.certs.tls_audit import TLSAuditor
from modules.web import WaybackScanner
from modules.web.web_scanner import WebScanner, EndpointDiscovery
from modules.network import NetworkScanner
from modules.osint import WhoisScanner, GitHubScanner, GoogleScanner
from modules.osint.cloud_email import CloudBucketDetector, EmailEnumerator, CDNDetector
from modules.cve import CVEScanner
from core import __version__
from core.correlator import AssetCorrelator
from core.config import (
    VALID_EXPORT_FORMATS as _EXPORT_FORMATS,
)
from core.config import Config, ConfigError
from core.logging_config import parse_level, setup_logging
from core.schema import SCHEMA_VERSION, new_results, validate_results
from core.scope import Scope, ScopeError
from core.session_cache import ScanCache, SessionManager
from core.scan_diff import ScanDiff, AttackChainBuilder, BountyReporter
from core.monitor import SubdomainMonitor, AlertManager
from core.plugins import PluginManager
from graph.builder import GraphBuilder, GraphAnalyzer
from reporting.markdown_reporter import MarkdownReporter
from reporting.mitre_mapper import MitreMapper
from reporting.export import CSVExporter, HTMLReporter
from reporting.export_tools import BurpExporter, MetasploitExporter
from reporting.sarif import SarifExporter
from ui.rich_cli import RichCLI, instrument_engine
from ai import AIEngine


def _sanitize_filename(value: str) -> str:
    """Turn an arbitrary target into a safe filename fragment.

    Targets can be URLs (``https://acme.com:8443``) whose ``/`` and ``:``
    would otherwise create/escape path components when composing output
    filenames, causing FileNotFoundError or files landing in stray
    directories.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(value))
    return safe.strip("._") or "unknown"


class OutputPathError(ValueError):
    """A user-supplied output path resolves outside the current directory."""


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _neutralize_console_text(value) -> str:
    """Strip ANSI/control bytes from user-controlled text (H-004, TEST).

    Targets and external data reach the terminal through prints and Rich
    panels; raw ESC/OSC sequences (e.g. ``\\x1b]0;pwned\\x07``) could
    rewrite the terminal title or fake operator-facing output. Control
    bytes carry no meaning in domains/IPs/paths, so they are removed at
    the entry points and render boundaries. Results files keep whatever
    the collectors captured untouched.
    """
    return _CONTROL_CHARS_RE.sub("", str(value))


def _validate_output_path(value: str, flag: str = "--output") -> str:
    """Ensure a user-supplied output path stays inside the current directory.

    H-003 (TEST): ``-o ../../foo`` used to silently write two levels above
    the repo. The base is resolved against the CWD and anything landing
    outside it is refused with an actionable message instead of writing to
    a stray location. Paths that resolve inside the CWD (relative or
    absolute) pass through unchanged.
    """
    resolved = Path(str(value)).expanduser().resolve()
    cwd = Path.cwd().resolve()
    if resolved != cwd and cwd not in resolved.parents:
        raise OutputPathError(
            f"{flag} resolves outside the current working directory: "
            f"{value!r} -> {resolved} (cwd: {cwd}). Use a path inside it, "
            f"e.g. {flag} output/report"
        )
    return str(value)


def _split_modules_token(value: str) -> list:
    """Split one --modules argv token on commas (H-010, TEST).

    ``--modules dns,web`` is the natural way to write a list; the type
    hook splits it per token so both ``dns web`` and ``dns,web`` work.
    Empty fragments (trailing/double commas) are dropped.
    """
    return [m for m in (part.strip() for part in str(value).split(",")) if m]


def _pdf_output_name(target: str) -> str:
    """Default PDF filename for a target (sanitized, CWD-relative)."""
    return (
        f"osint_eye_{_sanitize_filename(target)}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )


def _print_monitor_panel(console, targets: list, interval: int, webhook_url):
    """Render the daemon-monitor startup panel (markup-safe).

    Targets/webhooks are user input; a value containing a closing Rich tag
    (e.g. ``x[/bold]y.com``) used to abort startup with ``MarkupError``
    because it was interpolated into the panel markup unescaped.
    """
    from rich.markup import escape
    from rich.panel import Panel

    console.print()
    console.print(
        Panel(
            f"  [dim]TARGETS[/dim]   [bold white]{escape(', '.join(map(str, targets)))}[/bold white]\n"
            f"  [dim]INTERVAL[/dim]  [cyan]{interval}s ({interval // 60} min)[/cyan]\n"
            f"  [dim]WEBHOOK [/dim]  {'[green]' + escape(str(webhook_url)) + '[/green]' if webhook_url else '[dim]Disabled[/dim]'}",
            title="[bold cyan]◈  DAEMON MONITOR[/bold cyan]",
            border_style="cyan",
        )
    )


class ScanInterrupted(Exception):
    """The operator aborted the scan (Ctrl+C, H-007).

    Carries the results collected so far (completed targets plus the
    in-flight one, whose partial data lives in ``engine.results``) so
    ``main()`` can report what was gathered and exit with the dedicated
    interrupt code instead of a raw traceback.
    """

    def __init__(self, partial_results: dict):
        super().__init__("scan interrupted by user")
        self.partial_results = partial_results or {}


class OSINTEye:
    """Main OSINT EYE orchestrator v2"""

    def __init__(
        self,
        target: str,
        stealth: bool = False,
        ai: bool = True,
        depth: str = "normal",
        cache: bool = True,
        scope: Scope = None,
    ):
        # H-004: one neutralization up front — self.target, new_results()
        # and every downstream consumer (exports, graph, dashboard keys)
        # inherit the clean form; raw bytes never enter the results.
        target = _neutralize_console_text(target)
        self.target = target
        self.stealth = stealth
        self.use_ai = ai
        self.depth = depth
        self.use_cache = cache
        self.scope = scope
        self.results = new_results(target, depth)
        # Defensive: new_results() must always emit a schema-versioned dict;
        # if the contract drifts, fail loudly here instead of shipping
        # unversioned scans.
        if self.results.get("schema_version") != SCHEMA_VERSION:
            raise RuntimeError("results factory diverged from SCHEMA_VERSION")

        self.dns_scanner = DNSScanner()
        self.permutator = SubdomainPermutator(threads=100)
        self.takeover_detector = SubdomainTakeoverDetector()
        self.cert_scanner = CertScanner()
        self.tls_auditor = TLSAuditor()
        self.wayback_scanner = WaybackScanner()
        self.web_scanner = WebScanner()
        self.endpoint_discovery = EndpointDiscovery()
        self.network_scanner = NetworkScanner()
        self.whois_scanner = WhoisScanner()
        self.github_scanner = GitHubScanner()
        self.google_scanner = GoogleScanner()
        self.cloud_detector = CloudBucketDetector()
        self.email_enumerator = EmailEnumerator()
        self.cdn_detector = CDNDetector()
        self.cve_scanner = CVEScanner()
        self.correlator = AssetCorrelator()
        self.graph_builder = GraphBuilder()
        self.graph_analyzer = None
        self.reporter = MarkdownReporter()
        self.mitre_mapper = MitreMapper()
        self.csv_exporter = CSVExporter()
        self.html_reporter = HTMLReporter()
        self.burp_exporter = BurpExporter()
        self.msf_exporter = MetasploitExporter()
        self.sarif_exporter = SarifExporter()
        self._pdf_reporter = None  # lazy: reportlab is the [pdf] extra
        self.chain_builder = AttackChainBuilder()
        self.bounty_reporter = BountyReporter()
        self.cli = RichCLI()
        self.scan_cache = ScanCache() if cache else None
        self.session_manager = (
            SessionManager(self.scan_cache) if self.scan_cache else None
        )
        self.plugin_manager = PluginManager()
        self.plugin_manager.load_builtin()

        if ai:
            self.ai_engine = AIEngine()

        self._module_errors = 0

    def _safe_run(self, name: str, func, *args, **kwargs):
        """Run a module with graceful degradation"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self._module_errors += 1
            error_msg = f"[{name}] {str(e)}"
            self.results["errors"].append(error_msg)
            print(f"[!] {error_msg}")
            return {}

    @property
    def pdf_reporter(self):
        """Deferred PDFReporter so `import osint_eye` never pulls reportlab."""
        if self._pdf_reporter is None:
            from reporting.pdf_reporter import PDFReporter

            self._pdf_reporter = PDFReporter()
        return self._pdf_reporter

    def _print(self, msg):
        # Choke point for every engine/module message: external data
        # interpolated here (targets, banners, records) is neutralized so
        # control bytes never reach the terminal (H-004).
        print(f"[*] {_neutralize_console_text(msg)}")

    def _refresh_scope_summary(self):
        """Embed the live scope summary (incl. discard log) into results."""
        if self.scope is not None:
            self.results["scope"] = self.scope.to_dict()

    def _validate_schema(self):
        """Check self.results against the contract; warn, never fail.

        A schema violation here is a bug in a collector, not a reason to
        lose the whole scan: problems are surfaced so the JSON stays
        debuggable by consumers (dashboard, diff, CI exports).
        """
        problems = validate_results(self.results)
        for problem in problems[:5]:
            print(f"[!] schema: {problem}")
        if len(problems) > 5:
            print(f"[!] schema: {len(problems) - 5} more problems suppressed")
        return problems

    def _drain_executor_errors(self, futures, phase: str):
        """Surface exceptions raised inside phase worker threads.

        ``concurrent.futures.wait()`` discards the futures, so without this
        a crashed worker (e.g. a bug in one run_* method) used to disappear
        silently: no message, no error entry, missing module data.
        """
        for future in futures:
            exc = future.exception()
            if exc is not None:
                self._module_errors += 1
                error_msg = f"[{phase}] worker crashed: {exc}"
                self.results["errors"].append(error_msg)
                print(f"[!] {error_msg}")

    def run_dns(self):
        self._print("Running DNS enumeration...")
        result = self._safe_run("dns", self.dns_scanner.scan, self.target, "basic")
        self.results["modules"]["dns"] = result
        self.correlator.ingest_dns(result)
        if self.scan_cache:
            for sub in result.get("subdomains", []):
                self.scan_cache.add_subdomain(self.target, sub, "dns")
        self._print(f"  Found {len(result.get('subdomains', []))} subdomains")

    def run_certs(self):
        self._print("Running Certificate Transparency...")
        result = self._safe_run("certs", self.cert_scanner.scan, self.target)
        self.results["modules"]["certs"] = result
        self.correlator.ingest_certs(result)
        self._print(f"  Found {len(result.get('subdomains', []))} subdomains via CT")

    def run_tls_audit(self):
        self._print("Running TLS audit...")
        result = self._safe_run(
            "tls_audit", self.tls_auditor.audit, self.target, scope=self.scope
        )
        self.results["modules"]["tls_audit"] = result
        grade = result.get("grade") or "n/a"
        self._print(f"  TLS grade {grade} (score {result.get('score')})")

    def run_wayback(self):
        self._print("Running Wayback Machine...")
        result = self._safe_run("wayback", self.wayback_scanner.scan, self.target)
        self.results["modules"]["wayback"] = result
        self.correlator.ingest_wayback(result)
        self._print(f"  Found {result.get('total_snapshots', 0)} snapshots")

    def run_network(self):
        self._print("Running network scan...")
        result = self._safe_run("network", self.network_scanner.scan, self.target)
        self.results["modules"]["network"] = result
        self.correlator.ingest_network(result)
        if self.scan_cache:
            for svc in result.get("services", []):
                if svc.get("state") == "open":
                    self.scan_cache.add_port(
                        self.target,
                        result.get("host", ""),
                        svc.get("port"),
                        svc.get("service"),
                        svc.get("version"),
                    )
        open_ports = [s for s in result.get("services", []) if s.get("state") == "open"]
        self._print(f"  Found {len(open_ports)} open ports")

    def run_whois(self):
        self._print("Running WHOIS...")
        result = self._safe_run("whois", self.whois_scanner.scan, self.target)
        self.results["modules"]["whois"] = result
        self.correlator.ingest_whois(result)

    def run_web(self):
        self._print(f"Detecting technologies on {self.target}...")
        result = self._safe_run("web", self.web_scanner.scan, self.target)
        self.results["modules"]["web"] = result
        self.correlator.ingest_web(result)
        techs = result.get("technologies")
        if isinstance(techs, dict):
            techs = techs.get("technologies") or []
        elif not isinstance(techs, list):
            techs = []
        self._print(f"  Detected: {', '.join(map(str, techs[:5])) if techs else 'none'}")

    def run_endpoints(self):
        self._print("Discovering endpoints...")
        target_url = (
            f"https://{self.target}"
            if not self.target.startswith("http")
            else self.target
        )
        endpoints = self._safe_run(
            "endpoints", self.endpoint_discovery.discover, target_url
        )
        sensitive = self._safe_run(
            "endpoints_sensitive",
            self.endpoint_discovery.discover_sensitive,
            target_url,
        )
        self.results["modules"]["endpoints"] = {
            "target": target_url,
            "found": endpoints.get("found", []),
            "sensitive": sensitive.get("found", []),
            "total_found": len(endpoints.get("found", [])),
        }
        self.correlator.ingest_endpoints(self.results["modules"]["endpoints"])
        self._print(f"  Found {len(endpoints.get('found', []))} endpoints")

    def run_cdn_waf(self):
        self._print("Detecting CDN/WAF...")
        target_url = (
            f"https://{self.target}"
            if not self.target.startswith("http")
            else self.target
        )
        result = self._safe_run("cdn_waf", self.cdn_detector.detect, target_url)
        self.results["modules"]["cdn_waf"] = result
        self.correlator.ingest_cdn_waf(result)
        self._print(
            f"  CDN: {result.get('cdn', 'None')} | WAF: {result.get('waf', 'None')}"
        )

    def run_cve(self):
        services = (
            self.results.get("modules", {}).get("network", {}).get("services", [])
        )
        # Tolerate hand-loaded/corrupt shapes: services entries must be dicts
        # (a bare string used to raise AttributeError inside the set build).
        unique_services = {
            s.get("service") for s in services if isinstance(s, dict) and s.get("service")
        }
        if unique_services:
            self._print("Running CVE lookup...")
            all_cves = []
            for service in list(unique_services)[:5]:
                cves = self._safe_run(
                    f"cve_{service}", self.cve_scanner.scan, service, "keyword"
                )
                # ".get('cves', [])" still returns None when the key exists
                # with a null value; extend(None) would raise TypeError.
                all_cves.extend(cves.get("cves") or [])
            self.results["modules"]["cve"] = {"cves": all_cves}
            self.correlator.ingest_cve(self.results["modules"]["cve"])
            self._print(f"  Found {len(all_cves)} potential CVEs")

    def run_permutation(self):
        self._print("Running subdomain permutation...")
        discovered = (
            self.results.get("modules", {}).get("dns", {}).get("subdomains", [])
        )
        found = self._safe_run(
            "permutation", self.permutator.enumerate, self.target, discovered
        )
        if self.scope is not None:
            # Resolution is an active touch: drop candidates outside scope.
            found = self.scope.filter_targets(found, "permutation")
        self.results["modules"]["permutation"] = {
            "subdomains": found,
            "total_found": len(found),
            "domain": self.target,
        }
        self.correlator.ingest_permutation(self.results["modules"]["permutation"])
        if self.scan_cache:
            for sub in found:
                self.scan_cache.add_subdomain(self.target, sub, "permutation")
        self._print(f"  Found {len(found)} subdomains via permutation")

    def run_takeover_check(self):
        self._print("Checking subdomain takeover...")
        subs = self.results.get("modules", {}).get("permutation", {}).get(
            "subdomains", []
        ) or self.results.get("modules", {}).get("dns", {}).get("subdomains", [])
        # A JSON "subdomains": null used to reach the slice below and raise
        # "TypeError: 'NoneType' object is not subscriptable".
        if not isinstance(subs, list):
            subs = []
        if self.scope is not None:
            # Takeover probing actively touches every candidate; never let
            # a discovered asset pull the scan outside the authorized scope.
            subs = self.scope.filter_targets(subs, "takeover")
        vulnerable = self._safe_run(
            "takeover", self.takeover_detector.scan_list, subs[:50]
        )
        self.results["modules"]["takeover"] = {
            "checked": len(subs[:50]),
            "vulnerable": vulnerable,
        }
        self.correlator.ingest_takeover({"vulnerable": vulnerable})
        self._print(f"  Found {len(vulnerable)} potential takeovers")

    def run_cloud_buckets(self):
        self._print("Scanning cloud buckets...")
        result = self._safe_run("cloud", self.cloud_detector.scan, self.target)
        self.results["modules"]["cloud_buckets"] = result
        self.correlator.ingest_cloud(result)
        self._print(
            f"  Found {len(result.get('found', []))} buckets, {len(result.get('public', []))} public"
        )

    def run_emails(self):
        self._print("Enumerating emails...")
        whois_data = self.results.get("modules", {}).get("whois", {})
        result = self._safe_run(
            "emails", self.email_enumerator.scan, self.target, whois_data
        )
        self.results["modules"]["emails"] = result
        self.correlator.ingest_emails(result)
        self._print(f"  Found {len(result.get('emails_found', []))} emails")

    def run_github(self):
        self._print("Running GitHub dorks...")
        result = self._safe_run("github", self.github_scanner.scan, self.target)
        self.results["modules"]["github"] = result
        self.correlator.ingest_github(result)
        self._print(f"  Found {result.get('total_findings', 0)} potential leaks")

    def run_google(self):
        self._print("Running Google dorks...")
        result = self._safe_run("google", self.google_scanner.scan, self.target, "full")
        self.results["modules"]["google"] = result
        self.correlator.ingest_google(result)

    def run_correlation(self):
        self._print("Correlating assets...")
        correlation = self.correlator.export_report()
        self.results["correlation"] = correlation
        score = correlation.get("attack_surface_score", {})
        self._print(
            f"  Attack Surface Score: {score.get('score')}/100 ({score.get('severity')})"
        )

    def run_graph(self):
        self._print("Building attack surface graph...")
        self.graph_builder.ingest_all(self.results)
        self.graph_analyzer = GraphAnalyzer(self.graph_builder)
        self.results["graph"] = self.graph_builder.export_json()
        summary = self.graph_analyzer.get_attack_surface_summary()
        self._print(
            f"  Graph: {summary['total_nodes']} nodes, {summary['total_edges']} edges"
        )

    def run_mitre(self):
        self._print("Mapping to MITRE ATT&CK...")
        findings = self.mitre_mapper.map_findings(self.results)
        self.results["mitre"] = self.mitre_mapper.export_json()
        self._print(f"  Mapped {len(findings)} findings to MITRE ATT&CK")

    def run_attack_chains(self):
        self._print("Building attack chains...")
        chains = self.chain_builder.build(self.results)
        self.results["attack_chains"] = chains
        self._print(f"  Identified {len(chains)} potential attack chains")

    def run_ai(self):
        if self.use_ai:
            self._print("Running AI analysis...")
            result = self._safe_run(
                "ai", self.ai_engine.analyze, self.results["modules"]
            )
            self.results["ai_analysis"] = result
            if result.get("risk_score"):
                rs = result["risk_score"]
                self._print(
                    f"  AI Risk Score: {rs.get('score')}/100 ({rs.get('severity')})"
                )

    def run_plugins(self, plugin_dir: str):
        self._print(f"Loading custom plugins from {plugin_dir}...")
        self.plugin_manager.load_from_directory(plugin_dir)

        # Filter only custom loaded plugins that are not builtin
        custom_plugins = [
            p
            for p in self.plugin_manager.plugins.values()
            if getattr(p, "author", "built-in") != "built-in"
            and p.__class__.__name__ not in ("PluginTemplate", "BaseModule")
            and hasattr(p, "run")
        ]

        if not custom_plugins:
            self._print("  No custom plugins found or loaded.")
            return

        self._print(f"Executing {len(custom_plugins)} custom plugins...")

        async def _run_all_plugins():
            results = {}
            for plugin in custom_plugins:
                try:
                    self._print(f"  Running plugin: {plugin.name}")
                    res = await plugin.run(self.target)
                    results[plugin.name] = res
                except Exception as e:
                    self._print(f"  Plugin {plugin.name} failed: {e}")
                    self.results["errors"].append(f"[plugin_{plugin.name}] {e}")
            return results

        plugin_results = asyncio.run(_run_all_plugins())
        self.results["plugins"] = plugin_results

    def run_all(self):
        import concurrent.futures
        from rich.console import Console

        # Plain phase rules instead of console.status(): worker threads
        # print() progress directly, which garbles a Live/Status display.
        console = Console()
        deep_enough = self.depth in ("deep", "full")

        # Live per-module progress (ui/rich_cli.py owns all the logic).
        tracker = instrument_engine(self)
        tracker.start_live()

        def phase(title: str):
            console.print()
            console.rule(f"[bold cyan]{title}[/bold cyan]", style="dim cyan")

        phase("Phase 1 · Concurrent OSINT Collection")
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            p1 = [
                executor.submit(self.run_dns),
                executor.submit(self.run_certs),
                executor.submit(self.run_wayback),
                executor.submit(self.run_whois),
            ]
            concurrent.futures.wait(p1)
        self._drain_executor_errors(p1, "phase1")
        self._print("[+] Phase 1 complete.")

        phase("Phase 2 · Network & Web Discovery")
        if self.depth != "quick":
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                p2 = [
                    executor.submit(self.run_network),
                    executor.submit(self.run_cdn_waf),
                ]
                if deep_enough:
                    p2.append(executor.submit(self.run_permutation))
                if not self.stealth:
                    p2.append(executor.submit(self.run_github))
                    p2.append(executor.submit(self.run_google))
                concurrent.futures.wait(p2)
            self._drain_executor_errors(p2, "phase2")
        self._print("[+] Phase 2 complete.")

        phase("Phase 3 · Web Vulnerability Scanning & Deep Recon")
        self.run_web()
        if self.depth != "quick":
            if deep_enough:
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                    p3 = [
                        executor.submit(self.run_takeover_check),
                        executor.submit(self.run_endpoints),
                        executor.submit(self.run_cloud_buckets),
                        executor.submit(self.run_emails),
                    ]
                    concurrent.futures.wait(p3)
                self._drain_executor_errors(p3, "phase3")
            self.run_cve()
        self._print("[+] Phase 3 complete.")

        phase("Phase 4 · Correlation, Graph & AI")
        self.run_correlation()
        self.run_graph()
        self.run_mitre()
        if deep_enough:
            self.run_attack_chains()
        self.run_ai()
        self._print("[+] Phase 4 complete.")

        self._refresh_scope_summary()
        self._validate_schema()

        if self.scan_cache:
            self.scan_cache.save_scan(self.target, "full", self.results, self.depth)

        tracker.stop_live()

        return self.results

    def export_all(self, output_base=None, formats=None):
        """Export results in all (or the selected) formats.

        ``formats`` selects a subset of the export catalogue
        (json, markdown, html, csv, mitre_json, mitre_navigator,
        bounty_report, graph, pdf, burp, metasploit, sarif). None = all.
        """
        self._refresh_scope_summary()
        self._validate_schema()

        if not output_base:
            output_base = (
                f"osint_eye_{_sanitize_filename(self.target)}_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
        else:
            # H-003 (TEST): every caller-supplied base must stay inside the
            # CWD; the CLI validates earlier, this guard covers the rest.
            try:
                output_base = _validate_output_path(output_base, flag="--output")
            except OutputPathError as exc:
                raise OutputPathError(f"export_all: {exc}") from None

        if formats is None:
            formats = list(_EXPORT_FORMATS)
        unknown = [f for f in formats if f not in _EXPORT_FORMATS]
        if unknown:
            raise ValueError(
                f"formatos de exportación desconocidos: {sorted(unknown)}; "
                f"válidos: {sorted(_EXPORT_FORMATS)}"
            )
        wanted = set(formats)

        exports = {}

        if not output_base.endswith(".json"):
            json_path = output_base + ".json"
        else:
            json_path = output_base

        # --output may point into a not-yet-existing directory
        # (e.g. "out/report"); create it instead of crashing after the scan.
        Path(json_path).parent.mkdir(parents=True, exist_ok=True)

        if "json" in wanted:
            with open(json_path, "w") as f:
                json.dump(self.results, f, indent=2, default=str)
            exports["json"] = json_path

        if "markdown" in wanted:
            md_path = (
                json_path.replace(".json", ".md")
                if json_path.endswith(".json")
                else output_base + ".md"
            )
            self.reporter.load_results(self.results)
            self.reporter.generate(md_path)
            exports["markdown"] = md_path

        if "html" in wanted:
            html_path = (
                json_path.replace(".json", ".html")
                if json_path.endswith(".json")
                else output_base + ".html"
            )
            self.html_reporter.generate(self.results, html_path)
            exports["html"] = html_path

        if "csv" in wanted:
            csv_files = self.csv_exporter.export_all(self.results, output_base)
            exports["csv"] = csv_files

        if "mitre_json" in wanted:
            mitre_json = output_base + "_mitre.json"
            with open(mitre_json, "w") as f:
                json.dump(self.results.get("mitre", {}), f, indent=2)
            exports["mitre_json"] = mitre_json

        if "mitre_navigator" in wanted:
            mitre_navigator = output_base + "_navigator.json"
            with open(mitre_navigator, "w") as f:
                json.dump(self.mitre_mapper.export_navigator_layer(), f, indent=2)
            exports["mitre_navigator"] = mitre_navigator

        if "bounty_report" in wanted:
            bounty_path = self.bounty_reporter.generate(self.results)
            exports["bounty_report"] = bounty_path

        if "graph" in wanted:
            graph_path = output_base + "_graph.html"
            self.graph_builder.export_html(graph_path)
            exports["graph"] = graph_path

        if "pdf" in wanted:
            pdf_path = (
                output_base + ".pdf" if not output_base.endswith(".pdf") else output_base
            )
            self.pdf_reporter.generate(self.results, pdf_path)
            exports["pdf"] = pdf_path

        if "burp" in wanted:
            burp_path = self.burp_exporter.export(self.results, output_base + "_burp.xml")
            exports["burp"] = burp_path

        if "metasploit" in wanted:
            msf_path = self.msf_exporter.export(self.results, output_base + "_msf.json")
            exports["metasploit"] = msf_path

        if "sarif" in wanted:
            sarif_path = self.sarif_exporter.export(
                self.results, output_base + ".sarif"
            )
            exports["sarif"] = sarif_path

        return exports

    def print_summary(self):
        """Delegate summary rendering to RichCLI"""
        self.cli.print_summary(self.results)


def scan_targets(targets: list, args):
    """Scan one or multiple targets"""
    # H-004: hostile ESC/OSC sequences in a target must never reach the
    # monitor panel, the scan header or any print downstream.
    targets = [_neutralize_console_text(t) for t in targets]
    all_results = {}

    if getattr(args, "monitor", False):
        from rich.console import Console

        console = Console(highlight=False)
        interval = getattr(args, "monitor_interval", 3600)
        webhook_url = getattr(args, "webhook", None)
        _print_monitor_panel(console, targets, interval, webhook_url)

        # Wiring mínimo (OWNERSHIP — excepción IMP-2): --dashboard en modo
        # monitor lanza el dashboard con auto-refresco en un hilo daemon, así
        # la página hace polling de la API cada --monitor-interval mientras
        # el daemon corre. No se toca nada más del flujo del monitor.
        if getattr(args, "dashboard", False):
            try:
                import threading as _threading

                from ui.dashboard import start_dashboard as _start_dash

                dash_thread = _threading.Thread(
                    target=_start_dash,
                    kwargs={"monitor": True, "interval": interval},
                    daemon=True,
                    name="oe-dashboard",
                )
                dash_thread.start()
                console.print(
                    "  [green]✔[/green] Dashboard en vivo en http://127.0.0.1:5000 "
                    "(auto-refresco cada %ss)" % interval
                )
            except Exception as exc:
                console.print(f"  [yellow]⚠ Dashboard no disponible: {exc}[/yellow]")

        monitor = SubdomainMonitor(
            targets, check_interval=args.monitor_interval, cache=not args.no_cache
        )
        if getattr(args, "webhook", None):
            monitor.alert_manager.add_handler(
                AlertManager.webhook_handler(args.webhook)
            )
            from rich.markup import escape as _escape

            console.print(
                f"  [green]✔[/green] Webhook alerts enabled for {_escape(str(args.webhook))}"
            )

        try:
            asyncio.run(monitor.run_daemon())
        except KeyboardInterrupt:
            monitor.stop()
            console.print("\n  [bold green]✔  Monitor stopped gracefully.[/bold green]")
        return {}

    # H-007 (TEST): Ctrl+C used to end the scan as a raw
    # KeyboardInterrupt traceback (e.g. inside sock.connect). The loop
    # below folds whatever was collected (completed targets plus the
    # in-flight one) into ScanInterrupted for main() to report cleanly.
    target = None
    engine = None
    try:
        for target in targets:
            engine = None  # reset per iteration: no stale engine misattribution
            scope = getattr(args, "scope_obj", None)
            if scope is not None and not scope.allows(target):
                scope.discard(target, "cli")
                print(
                    f"[!] {target} fuera de scope ({scope.reason(target)}) - target omitido"
                )
                continue

            # Rich header for each target
            from ui.rich_cli import RichCLI as _RCli

            _cli = _RCli()
            _cli.print_scan_header(target, args.depth, getattr(args, "stealth", False))

            engine = OSINTEye(
                target,
                stealth=args.stealth,
                ai=not args.no_ai,
                depth=args.depth,
                cache=not args.no_cache,
                scope=getattr(args, "scope_obj", None),
            )

            if args.modules:
                # Instrument FIRST, then build the dispatch map: module_map
                # captures bound methods, so mapping before instrument_engine()
                # would call the unwrapped originals and the live "Module
                # Progress" table would stay "pending" for the whole scan.
                tracker = instrument_engine(engine)
                tracker.start_live()
                module_map = {
                    "dns": engine.run_dns,
                    "certs": engine.run_certs,
                    "tls_audit": engine.run_tls_audit,
                    "wayback": engine.run_wayback,
                    "network": engine.run_network,
                    "whois": engine.run_whois,
                    "github": engine.run_github,
                    "google": engine.run_google,
                    "cve": engine.run_cve,
                    "web": engine.run_web,
                    "endpoints": engine.run_endpoints,
                    "cloud": engine.run_cloud_buckets,
                    "emails": engine.run_emails,
                    "permutation": engine.run_permutation,
                    "takeover": engine.run_takeover_check,
                    "cdn_waf": engine.run_cdn_waf,
                    "correlation": engine.run_correlation,
                    "graph": engine.run_graph,
                    "mitre": engine.run_mitre,
                    "chains": engine.run_attack_chains,
                }
                for module in args.modules:
                    if module in module_map:
                        module_map[module]()
                if not args.no_ai:
                    engine.run_ai()
                tracker.stop_live()
            else:
                engine.run_all()

            if getattr(args, "plugin_dir", None):
                engine.run_plugins(args.plugin_dir)

            if getattr(args, "agent", False) and getattr(engine, "ai_engine", None):
                engine._print("[*] Generating AI Red Team Playbook...")
                playbook_res = engine.ai_engine.generate_redteam_playbook(engine.results)
                playbook_md = playbook_res.get("playbook", "")
                engine.results["agent_playbook"] = playbook_md
                print("\n" + "=" * 60 + "\nAI AGENT PLAYBOOK\n" + "=" * 60)
                print(playbook_md)
                print("=" * 60 + "\n")

            engine.print_summary()

            if args.rich:
                from ui.rich_cli import RichCLI

                cli = RichCLI()
                cli.print_full_results(engine.results)

            if getattr(args, "pdf", False):
                # H-008 (TEST): with -o, the default-named PDF in the CWD was
                # an unexpected duplicate. When 'pdf' is among the export
                # formats, export_all() renders <base>.pdf and this branch
                # stays out of the way; otherwise the path derives from the
                # -o base (suffixed per target on multi-target runs).
                formats = getattr(args, "export_formats", None)
                pdf_in_exports = bool(args.output) and (
                    formats is None or "pdf" in (formats or [])
                )
                if not pdf_in_exports:
                    try:
                        # Sanitized: a URL-like target used to produce a filename
                        # containing "/" and crash PDF generation (FileNotFoundError).
                        if args.output:
                            base = (
                                args.output
                                if len(targets) == 1
                                else f"{args.output}_{_sanitize_filename(target)}"
                            )
                            pdf_path = base if base.endswith(".pdf") else base + ".pdf"
                        else:
                            pdf_path = _pdf_output_name(target)
                        engine._print(
                            f"[*] Generating Executive PDF Report -> {pdf_path}..."
                        )
                        engine.pdf_reporter.generate(engine.results, pdf_path)
                        print(f"[+] PDF Report saved: {pdf_path}")
                    except Exception as e:
                        print(f"[!] PDF generation failed: {e}")

            auto_saved_json = None
            if args.output:
                output = (
                    args.output
                    if len(targets) == 1
                    else f"{args.output}_{_sanitize_filename(target)}"
                )
                exports = engine.export_all(
                    output, formats=getattr(args, "export_formats", None)
                )
                print(f"\n[+] Exports: {json.dumps(exports, indent=2)}")
            else:
                # H-001 (TEST): the README quickstart left the user with no
                # reusable file at all. Persist a default JSON (same CWD
                # convention as the default PDF) and say where things live.
                default_json = (
                    f"osint_eye_{_sanitize_filename(target)}_"
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                try:
                    with open(default_json, "w") as f:
                        json.dump(engine.results, f, indent=2, default=str)
                except OSError as exc:
                    print(f"[!] Could not auto-save results: {exc}")
                else:
                    auto_saved_json = default_json
                    cache_hint = (
                        "cached in ~/.osint_eye/cache"
                        if engine.use_cache
                        else "cache disabled"
                    )
                    print(
                        f"[+] Results saved to {default_json} ({cache_hint}; "
                        f"export more formats with -o)"
                    )

            if getattr(args, "export_cypher", None):
                from graph.neo4j_exporter import Neo4jExporter

                cypher_file = (
                    args.export_cypher
                    if len(targets) == 1
                    else f"{args.export_cypher}_{_sanitize_filename(target)}"
                )
                print(f"[*] Exporting Neo4j Cypher to {cypher_file}...")
                exporter = Neo4jExporter(
                    engine.results.get("graph", {"nodes": [], "edges": []})
                )
                exporter.export_file(cypher_file)
                print(f"[*] Cypher export complete: {cypher_file}")

            if args.dashboard and len(targets) == 1:
                from ui.dashboard import load_scan_results, start_dashboard

                # Persist the scan JSON first so the dashboard always has real
                # data to load, then hand the exact path over. The auto-saved
                # default from H-001 is reused when present (no duplicate).
                if args.output:
                    dash_json = (
                        args.output
                        if args.output.endswith(".json")
                        else args.output + ".json"
                    )
                elif auto_saved_json:
                    dash_json = auto_saved_json
                else:
                    dash_json = (
                        f"osint_eye_{_sanitize_filename(target)}_"
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    )
                if not Path(dash_json).exists():
                    Path(dash_json).parent.mkdir(parents=True, exist_ok=True)
                    with open(dash_json, "w") as f:
                        json.dump(engine.results, f, indent=2, default=str)
                load_scan_results(dash_json)
                start_dashboard()

            if getattr(args, "tui", False) and len(targets) == 1:
                from ui.tui_app import launch_tui

                launch_tui(engine.results)

            if args.diff and len(targets) > 1:
                prev_target = targets[targets.index(target) - 1]
                if prev_target in all_results:
                    diff = ScanDiff()
                    diff.compare(all_results[prev_target], engine.results)
                    print(f"\n[Diff vs {prev_target}]")
                    print(diff.get_summary())

            all_results[target] = engine.results

    except KeyboardInterrupt:
        # The in-flight target's partial results live in engine.results;
        # completed ones are already in all_results. engine is reset to
        # None at the top of every iteration, so a hit during the scan
        # header of target N+1 never misattributes target N's engine.
        if target is not None and engine is not None and target not in all_results:
            all_results[target] = engine.results
        raise ScanInterrupted(all_results)
    return all_results


MODULE_CATALOG = {
    "dns": "DNS record enumeration (A/AAAA/MX/NS/TXT/CNAME/SOA) + subdomain brute-force",
    "certs": "Certificate transparency (crt.sh) subdomain discovery",
    "tls_audit": "TLS protocol versions, weak ciphers, certificate expiry and chain (stdlib ssl)",
    "wayback": "Wayback Machine URL history and snapshot timeline",
    "network": "Port & service discovery via nmap (graceful skip if nmap missing)",
    "whois": "Domain registration and ownership data",
    "github": "GitHub code-search dorking for leaked secrets and configs",
    "google": "Google dorking for exposed panels, files and backups",
    "cve": "NVD/CVE lookup for services discovered by the network module",
    "web": "HTTP technology fingerprinting of the target",
    "endpoints": "JS/HTML endpoint discovery + sensitive file probing",
    "cloud": "Cloud bucket (S3/GCP/Azure) discovery and public exposure",
    "emails": "Email enumeration from WHOIS and public sources",
    "permutation": "Subdomain permutation generation and resolution",
    "takeover": "Subdomain takeover detection (dangling CNAME fingerprints)",
    "cdn_waf": "CDN and WAF fingerprinting",
    "correlation": "Cross-module asset correlation + attack surface score",
    "graph": "Entity relationship graph (interactive HTML export)",
    "mitre": "MITRE ATT&CK technique mapping + Navigator layer export",
    "chains": "Attack chain builder (multi-step kill-chain hypotheses)",
}


def _positive_int(value: str) -> int:
    """argparse type: strictly positive integer."""
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer")
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be a positive integer")
    return ivalue


# ─────────────────────────────────────────────────────────────────────────────
# CI exit codes (--fail-on)
#
#   0   scan finished under the requested threshold (or no --fail-on given)
#   1   --fail-on threshold reached or exceeded by the worst finding severity
#   2   usage error (argparse convention)
#   3   nothing was scanned (all targets outside the authorized scope)
#   130 scan interrupted by the operator (Ctrl+C, POSIX 128+SIGINT)
# ─────────────────────────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_FAIL_ON = 1
EXIT_USAGE = 2
EXIT_NOTHING_SCANNED = 3
EXIT_INTERRUPTED = 130

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
FAIL_ON_CHOICES = ("low", "medium", "high")


def max_severity(results_by_target: dict) -> str:
    """Worst attack-surface severity across all scanned targets.

    Reads ``results["correlation"]["attack_surface_score"]["severity"]``
    per target; targets without correlation (e.g. partial ``--modules``
    runs) count as LOW and malformed shapes are tolerated.
    """
    worst = "LOW"
    if not isinstance(results_by_target, dict):
        return worst
    for result in results_by_target.values():
        if not isinstance(result, dict):
            continue
        correlation = result.get("correlation")
        score = (
            correlation.get("attack_surface_score")
            if isinstance(correlation, dict)
            else None
        )
        severity = (
            str(score.get("severity", "")).upper()
            if isinstance(score, dict)
            else ""
        )
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK[worst]:
            worst = severity
    return worst


def decide_exit_code(all_results: dict, args) -> int:
    """Turn a finished scan into a pipeline-friendly exit code."""
    if getattr(args, "monitor", False):
        # A daemon run has no finite result set to grade.
        return EXIT_OK
    if not all_results:
        print(
            "[x] no target scanned: every target was outside the authorized "
            "scope (exit code 3)"
        )
        return EXIT_NOTHING_SCANNED

    threshold = getattr(args, "fail_on", None)
    if not threshold:
        return EXIT_OK

    worst = max_severity(all_results)
    if SEVERITY_RANK.get(worst, 0) >= SEVERITY_RANK[threshold.upper()]:
        print(
            f"[x] fail-on {threshold}: worst severity {worst} reaches the "
            f"threshold (exit code {EXIT_FAIL_ON})"
        )
        return EXIT_FAIL_ON
    print(f"[+] fail-on {threshold}: worst severity {worst} under the threshold")
    return EXIT_OK


def _apply_config_to_args(args, config: Config, parser) -> None:
    """Fill args from the config file where the user left CLI defaults.

    Precedence: explicit CLI flags win; anything the user did not pass
    gets the config value. A flag equal to its argparse default is treated
    as "not passed" (documented edge: passing --depth normal with a config
    that sets deep lets the config win).
    """
    option_map = {
        "depth": config.depth,
        "stealth": config.stealth,
        "no_ai": config.no_ai,
        "no_cache": config.no_cache,
        "monitor_interval": config.monitor_interval,
    }
    for attr, value in option_map.items():
        if value is None or value == parser.get_default(attr):
            continue
        if getattr(args, attr, None) == parser.get_default(attr):
            setattr(args, attr, value)

    if config.modules and getattr(args, "modules", None) is None:
        args.modules = list(config.modules)

    # Export formats have no CLI flag yet (export-cli-flags, Banco):
    # config is the only source, applied directly.
    if config.export_formats:
        args.export_formats = list(config.export_formats)


def build_scope_from_config(config: Config) -> Optional[Scope]:
    """Scope from [scope].includes/excludes (None when unconfigured)."""
    includes = config.scope_includes
    excludes = config.scope_excludes
    if not includes and not excludes:
        return None
    return Scope(includes=includes, excludes=excludes)


def _print_module_catalog():
    """Print the available scan modules as a Rich table."""
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    table = Table(
        title="[bold cyan]◈  OSINT EYE · Module Catalog[/bold cyan]",
        box=box.ROUNDED,
        header_style="bold cyan",
        border_style="cyan",
    )
    table.add_column("MODULE", style="bold", min_width=12)
    table.add_column("DESCRIPTION")
    for name, description in MODULE_CATALOG.items():
        table.add_row(name, description)
    console.print()
    console.print(table)
    console.print(
        "\n[dim]Usage:[/dim] python osint_eye.py <target> "
        "--modules dns certs wayback graph mitre\n"
        "[dim]Docs:[/dim]  https://github.com/Ruby570bocadito/OSINT-EYE\n"
    )


def main():
    parser = argparse.ArgumentParser(
        description=f"OSINT EYE v{__version__} - AI-Powered Attack Surface Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_eye.py example.com
  python osint_eye.py example.com --depth full --output results
  python osint_eye.py target1.com target2.com target3.com --depth deep
  python osint_eye.py example.com --stealth --no-ai --no-cache
  python osint_eye.py example.com --modules dns network web cloud emails graph mitre chains
  python osint_eye.py example.com --scope scope.txt --exclude sub.example.com --exclude 10.0.0.0/8

Exit codes (CI):
  0 scan finished under threshold · 1 --fail-on threshold exceeded ·
  2 usage error · 3 no target scanned (all outside scope)
        """,
    )

    parser.add_argument(
        "targets",
        nargs="*",
        help="Target domain(s) or IP(s) (omit for the interactive wizard)",
    )
    parser.add_argument("--stealth", action="store_true", help="Stealth mode")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    parser.add_argument(
        "--output",
        "-o",
        help="Output base filename (must resolve inside the current "
        "working directory; escaping paths are refused before scanning)",
    )
    parser.add_argument(
        "--depth", choices=["quick", "normal", "deep", "full"], default="normal"
    )
    parser.add_argument("--diff", action="store_true", help="Show diff between targets")
    parser.add_argument("--rich", action="store_true", help="Use Rich CLI output")
    parser.add_argument(
        "--dashboard", action="store_true", help="Launch web dashboard after scan"
    )
    parser.add_argument(
        "--tui", action="store_true",
        help="Explore the results in the interactive Textual TUI after scan",
    )
    parser.add_argument(
        "--profile", help="Use a named [profiles.<name>] section from the "
        "config file (requires --config or an osint_eye.toml)"
    )
    parser.add_argument(
        "--config", metavar="FILE", help="TOML configuration file "
        "(default: osint_eye.toml in the current directory, if present)"
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Run in continuous monitoring daemon mode",
    )
    parser.add_argument(
        "--monitor-interval",
        type=_positive_int,
        default=3600,
        help="Seconds between monitor checks (default: 3600)",
    )
    parser.add_argument(
        "--webhook", help="Webhook URL (Discord/Slack) for monitor alerts"
    )
    parser.add_argument(
        "--plugin-dir", help="Directory containing custom plugins to load and run"
    )
    parser.add_argument(
        "--agent",
        action="store_true",
        help="Run the AI Agent to generate actionable Red Team Playbook",
    )
    parser.add_argument(
        "--export-cypher",
        help="Export Graph to a Neo4j compatible .cypher data dump "
        "(must resolve inside the current working directory)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Log level of core/graph/reporting: DEBUG, INFO, WARNING, ERROR, "
        "CRITICAL (default: INFO). Console output of the UI stays on Rich.",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Append library logs to this file (console keeps receiving "
        "them; must resolve inside the current working directory)",
    )
    parser.add_argument(
        "--scope",
        metavar="FILE",
        help="Authorization scope: one domain, wildcard domain, IP or CIDR per "
        "line (# comments). Targets outside it are skipped and recorded",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        metavar="ITEM",
        help="Exclude domain/IP/CIDR from the scan (repeatable; always wins "
        "over --scope)",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        type=str.lower,
        default=None,
        help="CI mode: exit with code 1 when the worst attack-surface severity "
        "is low/medium/high or above (high also fails on critical)",
    )
    parser.add_argument(
        "--pdf", action="store_true", help="Generate an executive PDF report after scan"
    )
    parser.add_argument(
        "--modules",
        nargs="*",
        type=_split_modules_token,
        help="Modules to run, comma or space separated (e.g. dns,web). "
        "Without values, prints the module catalog",
    )

    if len(sys.argv) == 1:
        try:
            from ui.wizard import InteractiveWizard

            wizard = InteractiveWizard()
            wizard_args = wizard.start()
            args = parser.parse_args(wizard_args)
            interactive_mode = True
        except ImportError:
            parser.print_help()
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[!] Setup cancelled by user.")
            sys.exit(0)
    else:
        args = parser.parse_args()
        interactive_mode = False

    # H-003 (TEST): user-supplied output paths must never escape the CWD.
    # Checked before any side effect (log file creation, scans, exports) so
    # a bad path is a clean usage error (argparse exits with code 2).
    for flag, attr in (
        ("--output", "output"),
        ("--export-cypher", "export_cypher"),
        ("--log-file", "log_file"),
    ):
        value = getattr(args, attr, None)
        if value:
            # H-004 first: strip control bytes, then validate the exact
            # string that will be used and echoed back, so the cleaned
            # path can never escape where the raw one did not.
            value = _neutralize_console_text(value)
            try:
                _validate_output_path(value, flag=flag)
            except OutputPathError as exc:
                parser.error(str(exc))
            setattr(args, attr, value)

    # H-010 (TEST): --modules dns,web is the natural list form; the type
    # hook splits commas per token, here the per-token lists are flattened
    # and unknown names rejected with a short, actionable error (the old
    # choices=[...] dumped ~40 lines of usage instead).
    if getattr(args, "modules", None):
        flat = [m for part in args.modules for m in part]
        args.modules = list(dict.fromkeys(flat))
        unknown = [m for m in args.modules if m not in MODULE_CATALOG]
        if unknown:
            parser.error(
                f"unknown module(s): {', '.join(unknown)}; valid modules: "
                f"{', '.join(MODULE_CATALOG)} (separate them with commas or "
                f"spaces: --modules dns,web)"
            )

    # Configure the library logger before any scan/monitor work runs, so
    # every core/graph/reporting message honours --log-level/--log-file.
    try:
        log_level = parse_level(args.log_level)
    except ValueError as exc:
        parser.error(str(exc))
    setup_logging(log_level, args.log_file)

    args.scope_obj = None
    config_obj = None
    try:
        config_obj = Config.load(args.config)
    except ConfigError as exc:
        parser.error(f"config: {exc}")

    if getattr(args, "profile", None):
        if config_obj is None:
            parser.error(
                "--profile requiere un fichero de configuración (--config u "
                "osint_eye.toml en el directorio actual)"
            )
        try:
            config_obj = config_obj.apply_profile(args.profile)
        except ConfigError as exc:
            parser.error(f"config: {exc}")

    if config_obj is not None:
        try:
            config_obj.validate_modules(MODULE_CATALOG).validate_export_formats()
        except ConfigError as exc:
            parser.error(f"config: {exc}")
        _apply_config_to_args(args, config_obj, parser)
        args.config_obj = config_obj

    # Scope control: --scope FILE defines what may be touched, --exclude
    # always wins; [scope] del fichero de configuración se usa sólo si el
    # usuario no dio nada por CLI. Built (and validated) before anything
    # runs so a broken scope is a clean usage error, never a mid-scan crash.
    if getattr(args, "scope", None) or getattr(args, "exclude", None):
        try:
            if args.scope:
                args.scope_obj = Scope.from_file(args.scope, excludes=args.exclude)
            else:
                args.scope_obj = Scope(excludes=args.exclude)
        except (ScopeError, OSError) as exc:
            parser.error(f"scope: {exc}")
    elif config_obj is not None:
        args.scope_obj = build_scope_from_config(config_obj)

    # `--modules` without a value prints the module catalog and exits.
    if getattr(args, "modules", None) is not None and len(args.modules) == 0:
        _print_module_catalog()
        return 0

    # --webhook: outbound fetch of the operator's machine (monitor alerts).
    # Fail fast like scope/config: https-only, public host (no loopback,
    # RFC1918 or cloud metadata), so a typo never leaks scan data inwards.
    if getattr(args, "webhook", None):
        from modules.web.ssrf_guard import is_safe_webhook_url

        if not is_safe_webhook_url(args.webhook):
            parser.error(
                "webhook: URL rechazada - exige https y un host público "
                "(loopback, IPs privadas y metadatos cloud están bloqueados)"
            )

    if not getattr(args, "targets", None):
        parser.error(
            "no targets given - pass one or more domains/IPs, or run without "
            "arguments for the interactive wizard"
        )

    # Print the banner once for every non-interactive run (scan or monitor).
    # Monitor mode's daemon loop lives entirely inside scan_targets().
    if not interactive_mode:
        from ui.rich_cli import RichCLI as _RCli

        _RCli().print_banner()
        try:
            all_results = scan_targets(args.targets, args)
        except ScanInterrupted as interrupted:
            # H-007 (TEST): clean abort — report what was collected, render
            # the per-target summary of the partials and exit with the
            # dedicated interrupt code instead of a raw traceback.
            partials = interrupted.partial_results
            names = ", ".join(partials.keys()) or "none"
            print(f"\n[x] Scan interrupted by user (Ctrl+C); partial results for: {names}")
            summary_cli = _RCli()
            for result in partials.values():
                if isinstance(result, dict):
                    try:
                        summary_cli.print_summary(result)
                    except Exception as exc:
                        print(f"[!] Partial summary unavailable: {exc}")
            print(
                f"[i] Interrupted scans exit with code {EXIT_INTERRUPTED} "
                f"(128+SIGINT). Re-run with -o to export results as they "
                f"are collected."
            )
            return EXIT_INTERRUPTED
        return decide_exit_code(all_results, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
