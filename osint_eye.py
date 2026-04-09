"""OSINT EYE v2 - Main Entry Point with Async, Cache & Multi-Target"""

import argparse
import sys
import json
import asyncio
import traceback
from datetime import datetime
from pathlib import Path

from modules.dns import DNSScanner
from modules.dns.subdomain_permutator import (
    SubdomainPermutator,
    SubdomainTakeoverDetector,
)
from modules.certs import CertScanner
from modules.web import WaybackScanner
from modules.web.web_scanner import WebScanner, EndpointDiscovery
from modules.network import NetworkScanner
from modules.osint import WhoisScanner, GitHubScanner, GoogleScanner
from modules.osint.cloud_email import CloudBucketDetector, EmailEnumerator, CDNDetector
from modules.cve import CVEScanner
from core.correlator import AssetCorrelator
from core.session_cache import ScanCache, SessionManager
from core.async_engine import AsyncConfig
from core.scan_diff import ScanDiff, AttackChainBuilder, BountyReporter
from core.monitor import SubdomainMonitor, AlertManager
from core.plugins import PluginManager
from graph.builder import GraphBuilder, GraphAnalyzer
from reporting.markdown_reporter import MarkdownReporter
from reporting.mitre_mapper import MitreMapper
from reporting.export import CSVExporter, HTMLReporter
from reporting.pdf_reporter import PDFReporter
from reporting.export_tools import BurpExporter, MetasploitExporter, ConfigProfiles
from ui.rich_cli import RichCLI
from ai import AIEngine


class OSINTEye:
    """Main OSINT EYE orchestrator v2"""

    def __init__(
        self,
        target: str,
        stealth: bool = False,
        ai: bool = True,
        depth: str = "normal",
        cache: bool = True,
    ):
        self.target = target
        self.stealth = stealth
        self.use_ai = ai
        self.depth = depth
        self.use_cache = cache
        self.results = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "depth": depth,
            "modules": {},
            "errors": [],
        }

        self.dns_scanner = DNSScanner()
        self.permutator = SubdomainPermutator(threads=100)
        self.takeover_detector = SubdomainTakeoverDetector()
        self.cert_scanner = CertScanner()
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
        self.pdf_reporter = PDFReporter()
        self.burp_exporter = BurpExporter()
        self.msf_exporter = MetasploitExporter()
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

    def _print(self, msg):
        print(f"[*] {msg}")

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
        techs = result.get("technologies", {}).get("technologies", [])
        self._print(f"  Detected: {', '.join(techs[:5]) if techs else 'none'}")

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
            "found": endpoints.get("found", []),
            "sensitive": sensitive.get("found", []),
            "total_found": len(endpoints.get("found", [])),
        }
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
        self._print(
            f"  CDN: {result.get('cdn', 'None')} | WAF: {result.get('waf', 'None')}"
        )

    def run_cve(self):
        services = (
            self.results.get("modules", {}).get("network", {}).get("services", [])
        )
        unique_services = {s.get("service") for s in services if s.get("service")}
        if unique_services:
            self._print("Running CVE lookup...")
            all_cves = []
            for service in list(unique_services)[:5]:
                cves = self._safe_run(
                    f"cve_{service}", self.cve_scanner.scan, service, "keyword"
                )
                all_cves.extend(cves.get("cves", []))
            self.results["modules"]["cve"] = {"cves": all_cves}
            self._print(f"  Found {len(all_cves)} potential CVEs")

    def run_permutation(self):
        self._print("Running subdomain permutation...")
        discovered = (
            self.results.get("modules", {}).get("dns", {}).get("subdomains", [])
        )
        found = self._safe_run(
            "permutation", self.permutator.enumerate, self.target, discovered
        )
        self.results["modules"]["permutation"] = {
            "subdomains": found,
            "total_found": len(found),
        }
        if self.scan_cache:
            for sub in found:
                self.scan_cache.add_subdomain(self.target, sub, "permutation")
        self._print(f"  Found {len(found)} subdomains via permutation")

    def run_takeover_check(self):
        self._print("Checking subdomain takeover...")
        subs = self.results.get("modules", {}).get("permutation", {}).get(
            "subdomains", []
        ) or self.results.get("modules", {}).get("dns", {}).get("subdomains", [])
        vulnerable = self._safe_run(
            "takeover", self.takeover_detector.scan_list, subs[:50]
        )
        self.results["modules"]["takeover"] = {
            "checked": len(subs[:50]),
            "vulnerable": vulnerable,
        }
        self._print(f"  Found {len(vulnerable)} potential takeovers")

    def run_cloud_buckets(self):
        self._print("Scanning cloud buckets...")
        result = self._safe_run("cloud", self.cloud_detector.scan, self.target)
        self.results["modules"]["cloud_buckets"] = result
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
        self._print(f"  Found {len(result.get('emails_found', []))} emails")

    def run_github(self):
        self._print("Running GitHub dorks...")
        result = self._safe_run("github", self.github_scanner.scan, self.target)
        self.results["modules"]["github"] = result
        self._print(f"  Found {result.get('total_findings', 0)} potential leaks")

    def run_google(self):
        self._print("Running Google dorks...")
        result = self._safe_run("google", self.google_scanner.scan, self.target, "full")
        self.results["modules"]["google"] = result

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

        console = Console()

        with console.status(
            "[bold green]Phase 1: Concurrent OSINT Collection...[/bold green]",
            spinner="dots",
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                p1 = [
                    executor.submit(self.run_dns),
                    executor.submit(self.run_certs),
                    executor.submit(self.run_wayback),
                    executor.submit(self.run_whois),
                ]
                concurrent.futures.wait(p1)
        self._print("[+] Phase 1 Complete.")

        with console.status(
            "[bold green]Phase 2: Network & Web Discovery...[/bold green]",
            spinner="dots",
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                p2 = [
                    executor.submit(self.run_network),
                    executor.submit(self.run_cdn_waf),
                ]
                if self.depth in ["deep", "full"]:
                    p2.append(executor.submit(self.run_permutation))
                if not self.stealth:
                    p2.append(executor.submit(self.run_github))
                    p2.append(executor.submit(self.run_google))
                concurrent.futures.wait(p2)

        with console.status(
            "[bold green]Running Web Vulnerability Scanner...[/bold green]",
            spinner="dots",
        ):
            self.run_web()
        self._print("[+] Phase 2 Complete.")

        with console.status(
            "[bold green]Phase 3: Vulnerability Scanning & Deep Recon...[/bold green]",
            spinner="bouncingBar",
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                p3 = [executor.submit(self.run_cve)]
                if self.depth in ["deep", "full"]:
                    p3.append(executor.submit(self.run_takeover_check))
                    p3.append(executor.submit(self.run_endpoints))
                    p3.append(executor.submit(self.run_cloud_buckets))
                    p3.append(executor.submit(self.run_emails))
                concurrent.futures.wait(p3)
        self._print("[+] Phase 3 Complete.")

        with console.status(
            "[bold green]Phase 4: Correlation & AI...[/bold green]", spinner="dots"
        ):
            self.run_correlation()
            self.run_graph()
            self.run_mitre()
            self.run_attack_chains()
            self.run_ai()
        self._print("[+] Phase 4 Complete.")

        if self.scan_cache:
            self.scan_cache.save_scan(self.target, "full", self.results, self.depth)

        return self.results

    def export_all(self, output_base=None):
        """Export results in all formats"""
        if not output_base:
            output_base = (
                f"osint_eye_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )

        exports = {}

        if not output_base.endswith(".json"):
            json_path = output_base + ".json"
        else:
            json_path = output_base

        with open(json_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        exports["json"] = json_path

        md_path = (
            json_path.replace(".json", ".md")
            if json_path.endswith(".json")
            else output_base + ".md"
        )
        self.reporter.load_results(self.results)
        self.reporter.generate(md_path)
        exports["markdown"] = md_path

        html_path = (
            json_path.replace(".json", ".html")
            if json_path.endswith(".json")
            else output_base + ".html"
        )
        self.html_reporter.generate(self.results, html_path)
        exports["html"] = html_path

        csv_files = self.csv_exporter.export_all(self.results, output_base)
        exports["csv"] = csv_files

        mitre_json = output_base + "_mitre.json"
        with open(mitre_json, "w") as f:
            json.dump(self.results.get("mitre", {}), f, indent=2)
        exports["mitre_json"] = mitre_json

        mitre_navigator = output_base + "_navigator.json"
        with open(mitre_navigator, "w") as f:
            json.dump(self.mitre_mapper.export_navigator_layer(), f, indent=2)
        exports["mitre_navigator"] = mitre_navigator

        bounty_path = self.bounty_reporter.generate(self.results)
        exports["bounty_report"] = bounty_path

        graph_path = output_base + "_graph.html"
        self.graph_builder.export_html(graph_path)
        exports["graph"] = graph_path

        pdf_path = (
            output_base + ".pdf" if not output_base.endswith(".pdf") else output_base
        )
        self.pdf_reporter.generate(self.results, pdf_path)
        exports["pdf"] = pdf_path

        burp_path = self.burp_exporter.export(self.results, output_base + "_burp.xml")
        exports["burp"] = burp_path

        msf_path = self.msf_exporter.export(self.results, output_base + "_msf.json")
        exports["metasploit"] = msf_path

        return exports

    def print_summary(self):
        """Delegate summary rendering to RichCLI"""
        self.cli.print_summary(self.results)


def scan_targets(targets: list, args):
    """Scan one or multiple targets"""
    all_results = {}

    if getattr(args, "monitor", False):
        print(f"\n{'#' * 60}")
        print(f"# Continuous Monitoring Mode")
        print(f"# Targets: {', '.join(targets)}")
        print(f"{'#' * 60}\n")

        monitor = SubdomainMonitor(
            targets, check_interval=args.monitor_interval, cache=not args.no_cache
        )
        if getattr(args, "webhook", None):
            monitor.alert_manager.add_handler(
                AlertManager.webhook_handler(args.webhook)
            )
            print(f"[*] Webhook alerts enabled for {args.webhook}")

        try:
            asyncio.run(monitor.run_daemon())
        except KeyboardInterrupt:
            monitor.stop()
            print("\n[*] Monitor stopped gracefully")
        return {}

    for target in targets:
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
        )

        if args.modules:
            module_map = {
                "dns": engine.run_dns,
                "certs": engine.run_certs,
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
            try:
                pdf_path = (
                    f"osint_eye_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )
                engine._print(f"[*] Generating Executive PDF Report -> {pdf_path}...")
                engine.pdf_reporter.generate(engine.results, pdf_path)
                print(f"[+] PDF Report saved: {pdf_path}")
            except Exception as e:
                print(f"[!] PDF generation failed: {e}")

        if args.output:
            output = args.output if len(targets) == 1 else f"{args.output}_{target}"
            exports = engine.export_all(output)
            print(f"\n[+] Exports: {json.dumps(exports, indent=2)}")

        if getattr(args, "export_cypher", None):
            from graph.neo4j_exporter import Neo4jExporter

            cypher_file = (
                args.export_cypher
                if len(targets) == 1
                else f"{args.export_cypher}_{target}"
            )
            print(f"[*] Exporting Neo4j Cypher to {cypher_file}...")
            exporter = Neo4jExporter(
                engine.results.get("graph", {"nodes": [], "edges": []})
            )
            exporter.export_file(cypher_file)
            print(f"[*] Cypher export complete: {cypher_file}")

        if args.dashboard and len(targets) == 1:
            from ui.dashboard import load_scan_results, start_dashboard

            load_scan_results(
                args.output
                if args.output
                else f"osint_eye_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            start_dashboard()

        if args.diff and len(targets) > 1:
            prev_target = targets[targets.index(target) - 1]
            if prev_target in all_results:
                diff = ScanDiff()
                result = diff.compare(all_results[prev_target], engine.results)
                print(f"\n[Diff vs {prev_target}]")
                print(diff.get_summary())

        all_results[target] = engine.results

    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="OSINT EYE v2 - AI-Powered Attack Surface Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python osint_eye.py example.com
  python osint_eye.py example.com --depth full --output results
  python osint_eye.py target1.com target2.com target3.com --depth deep
  python osint_eye.py example.com --stealth --no-ai --no-cache
  python osint_eye.py example.com --modules dns network web cloud emails graph mitre chains
        """,
    )

    parser.add_argument("targets", nargs="+", help="Target domain(s) or IP(s)")
    parser.add_argument("--stealth", action="store_true", help="Stealth mode")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    parser.add_argument("--output", "-o", help="Output base filename")
    parser.add_argument(
        "--depth", choices=["quick", "normal", "deep", "full"], default="normal"
    )
    parser.add_argument("--diff", action="store_true", help="Show diff between targets")
    parser.add_argument("--rich", action="store_true", help="Use Rich CLI output")
    parser.add_argument(
        "--dashboard", action="store_true", help="Launch web dashboard after scan"
    )
    parser.add_argument(
        "--profile", choices=["default", "deep", "stealth"], help="Use a config profile"
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Run in continuous monitoring daemon mode",
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
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
        "--export-cypher", help="Export Graph to a Neo4j compatible .cypher data dump"
    )
    parser.add_argument(
        "--pdf", action="store_true", help="Generate an executive PDF report after scan"
    )
    parser.add_argument(
        "--modules",
        nargs="*",
        choices=[
            "dns",
            "certs",
            "wayback",
            "network",
            "whois",
            "github",
            "google",
            "cve",
            "web",
            "endpoints",
            "cloud",
            "emails",
            "permutation",
            "takeover",
            "cdn_waf",
            "correlation",
            "graph",
            "mitre",
            "chains",
        ],
        help="Specific modules",
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

    if getattr(args, "monitor", False):
        import time
        from core.scan_diff import ScanDiff
        from ui.rich_cli import RichCLI as _RCli

        _cli = _RCli()
        _cli.print_banner()
        from rich.console import Console as _C
        from rich.panel import Panel as _P

        _c = _C(highlight=False)
        interval = getattr(args, "monitor_interval", 3600)
        webhook_url = getattr(args, "webhook", None)
        _c.print(
            _P(
                f"  [dim]TARGETS[/dim]   [bold white]{', '.join(args.targets)}[/bold white]\n"
                f"  [dim]INTERVAL[/dim]  [cyan]{interval}s ({interval // 60} min)[/cyan]\n"
                f"  [dim]WEBHOOK [/dim]  {'[green]' + webhook_url + '[/green]' if webhook_url else '[dim]Disabled[/dim]'}",
                title="[bold cyan]◈  DAEMON MONITOR[/bold cyan]",
                border_style="cyan",
            )
        )
        previous_results = {}
        loop = 1
        try:
            while True:
                from rich.rule import Rule as _Rule

                _c.print(
                    _Rule(
                        f"[bold cyan]  Cycle #{loop}[/bold cyan]  [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
                        style="bright_black",
                    )
                )
                current = scan_targets(args.targets, args)
                for tgt, res in current.items():
                    if tgt in previous_results:
                        diff = ScanDiff()
                        diff.compare(previous_results[tgt], res)
                        summary = diff.get_summary()
                        changes = [
                            diff.diff.get("new_subdomains", []),
                            diff.diff.get("new_ports", []),
                            diff.diff.get("new_cves", []),
                        ]
                        if any(changes):
                            _c.print(
                                f"  [bold red]⚠  NEW SURFACE DETECTED on {tgt}![/bold red]"
                            )
                            _c.print(summary)
                            if webhook_url:
                                try:
                                    import requests as _requests

                                    _requests.post(
                                        webhook_url,
                                        json={
                                            "text": f"*OSINT EYE ALERT* - New surface on `{tgt}`:\n```{summary[:1800]}```"
                                        },
                                        timeout=10,
                                    )
                                except Exception:
                                    pass
                        else:
                            _c.print(
                                f"  [green]✔[/green]  [dim]No changes detected on {tgt}.[/dim]"
                            )
                    previous_results[tgt] = res
                loop += 1
                _c.print(f"\n  [dim]Sleeping {interval}s... (Ctrl+C to stop)[/dim]")
                time.sleep(interval)
        except KeyboardInterrupt:
            _c.print("\n  [bold green]✔  Daemon stopped gracefully.[/bold green]")
            return 0
    else:
        if not interactive_mode:
            from ui.rich_cli import RichCLI as _RCli

            _RCli().print_banner()
        scan_targets(args.targets, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
