"""OSINT EYE - DNS Resolution Module

Provides DNS record resolution, subdomain bruteforce enumeration and
zone-transfer (AXFR) checks, orchestrated by :class:`DNSScanner`.

Contract consumed by osint_eye.py:
    DNSScanner().scan(target, "basic") -> dict with keys "domain",
    "subdomains" (list), "records" (dict per record type) and
    "spf"/"dmarc" dicts (always present, even on partial failures).
    In "full" mode "subdomains" additionally merges the passive sources
    from modules/dns/passive_sources.py (deduplicated) and the per-source
    detail is exposed under "passive_subdomains".
"""

import socket
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Optional, Set

import dns.resolver
import dns.query
import dns.zone

from modules.dns.passive_sources import PassiveSubdomainEnumerator


class DNSResolver:
    """DNS resolver with multiple record types support"""

    def __init__(self, timeout: int = 5, retries: int = 3):
        self.timeout = timeout
        self.retries = retries
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * retries

        self.nameservers = [
            "8.8.8.8",  # Google
            "8.8.4.4",  # Google
            "1.1.1.1",  # Cloudflare
            "1.0.0.1",  # Cloudflare
            "9.9.9.9",  # Quad9
        ]

    def resolve(self, domain: str, record_type: str = "A") -> List[str]:
        """Resolve a domain for a specific record type"""
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return []
        except Exception:
            return []

    def resolve_with_fallback(self, domain: str, record_type: str = "A") -> List[str]:
        """Try multiple nameservers as fallback (restores defaults after)."""
        original_nameservers = list(self.resolver.nameservers)
        try:
            for ns in self.nameservers:
                try:
                    self.resolver.nameservers = [ns]
                    results = self.resolve(domain, record_type)
                    if results:
                        return results
                except Exception:
                    continue
        finally:
            # Restore the system resolver so later lookups are not pinned
            # to the last public nameserver we tried.
            self.resolver.nameservers = original_nameservers
        return []

    def get_all_records(self, domain: str) -> Dict[str, List[str]]:
        """Get all common DNS record types"""
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        results = {}

        for rtype in record_types:
            results[rtype] = self.resolve_with_fallback(domain, rtype)

        return results

    def check_dmarc(self, domain: str) -> Dict:
        """Check DMARC record"""
        dmarc_domain = f"_dmarc.{domain}"
        result = {"exists": False, "record": "", "policy": None}

        try:
            answers = self.resolver.resolve(dmarc_domain, "TXT")
            for answer in answers:
                record = str(answer).strip('"')
                # RFC 7489 tags are case-insensitive; real records are seen
                # as "v=DMARC1" but also lowercase "v=dmarc1".
                lowered = record.lower()
                if "v=dmarc1" in lowered:
                    result["exists"] = True
                    result["record"] = record
                    if "p=none" in lowered:
                        result["policy"] = "none"
                    elif "p=quarantine" in lowered:
                        result["policy"] = "quarantine"
                    elif "p=reject" in lowered:
                        result["policy"] = "reject"
        except Exception:
            pass

        return result

    def check_spf(self, domain: str) -> Dict:
        """Check SPF record"""
        result = {"exists": False, "record": "", "policy": None}

        try:
            answers = self.resolver.resolve(domain, "TXT")
            for answer in answers:
                record = str(answer).strip('"')
                # RFC 7208 tags are case-insensitive and virtually all real
                # records use lowercase "v=spf1"; the old case-sensitive
                # check ("v=SPF1" in record) never matched real DNS data.
                lowered = record.lower()
                if "v=spf1" in lowered:
                    result["exists"] = True
                    result["record"] = record
                    if "-all" in lowered:
                        result["policy"] = "hardfail"
                    elif "~all" in lowered:
                        result["policy"] = "softfail"
                    elif "+all" in lowered:
                        result["policy"] = "pass-all"
        except Exception:
            pass

        return result


class SubdomainEnumerator:
    """Subdomain enumeration using DNS bruteforce.

    The wordlist is resolved relative to this module file (not the CWD)
    and falls back to a small built-in list if it is missing.
    """

    #: Fallback wordlist location relative to the repository root.
    DEFAULT_WORDLIST = Path(__file__).resolve().parents[2] / "data" / "wordlists" / "common.txt"

    def __init__(self, wordlist_path: Optional[str] = None, threads: int = 50, timeout: int = 3):
        self.wordlist_path = str(wordlist_path) if wordlist_path else str(self.DEFAULT_WORDLIST)
        # Keep the thread count bounded; DNS lookups are socket-bound but
        # hundreds of threads only add overhead and fd pressure.
        self.threads = max(1, min(threads, 200))
        self.timeout = timeout
        self.resolver = DNSResolver(timeout=timeout)
        self.found_subdomains: Set[str] = set()

    def load_wordlist(self) -> List[str]:
        """Load wordlist from file (module-relative); never fails hard.

        Tolerates both one-word-per-line files and single-line
        comma-separated lists (the bundled data/wordlists/*.txt mix both
        formats). Whitespace is stripped and duplicates removed.
        """
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
        except OSError:
            raw = None

        words: List[str] = []
        if raw:
            # Split on newlines and commas, then normalise each entry.
            for token in raw.replace(",", "\n").split("\n"):
                token = token.strip()
                if token:
                    words.append(token)
            # Deduplicate preserving order.
            words = list(dict.fromkeys(words))

        if not words:
            print(f"[!] Wordlist not readable at {self.wordlist_path}, using built-in defaults")
            return self._get_default_wordlist()
        return words

    def _get_default_wordlist(self) -> List[str]:
        """Default common subdomains (deduplicated)"""
        return [
            "www",
            "mail",
            "ftp",
            "localhost",
            "webmail",
            "smtp",
            "pop",
            "ns1",
            "webdisk",
            "ns2",
            "cpanel",
            "whm",
            "autodiscover",
            "autoconfig",
            "m",
            "imap",
            "test",
            "ns",
            "blog",
            "pop3",
            "dev",
            "www2",
            "admin",
            "forum",
            "news",
            "vpn",
            "cvs",
            "git",
            "staging",
            "beta",
            "arc",
            "secure",
            "v2",
            "staging2",
            "moodle",
            "cdn",
            "static",
            "docs",
            "media",
            "static1",
            "static2",
            "store",
            "api",
            "app",
            "live",
            "office",
            "owa",
            "lyncdiscover",
            "i",
            "remote",
            "s3",
            "backup",
            "mx",
            "direct",
            "cloud",
            "jira",
            "crm",
            "erp",
            "portal",
            "intranet",
            "gitlab",
            "jenkins",
            "monitor",
            "myshop",
            "shop",
            "v2.api",
            "demo",
            "db",
            "mysql",
            "sql",
            "phpmyadmin",
            "support",
            "platform",
            "ads",
            "ads1",
            "ads2",
            "assets",
            "assets1",
            "assets2",
            "b2b",
            "b2c",
            "cart",
            "client",
            "clients",
            "cluster",
            "chat",
            "connect",
            "content",
            "core",
            "dashboard",
            "data",
            "data1",
            "dev1",
            "dev2",
            "devel",
            "devs",
            "download",
            "download1",
            "download2",
            "dms",
            "downloads",
            "edit",
            "email",
            "forms",
            "forums",
            "gallery",
            "gate",
            "gateway",
            "host",
            "hosting",
            "http",
            "https",
            "info",
            "internal",
            "ip",
            "ipv4",
            "lb",
            "ldap",
            "legacy",
            "link",
            "links",
            "lists",
            "login",
            "logout",
            "m1",
            "manage",
            "manager",
            "marketing",
            "max",
            "media1",
            "mobile",
            "mx1",
            "mx2",
            "new",
            "newsletter",
            "ns0",
            "ns3",
            "old",
            "online",
            "orders",
            "panel",
            "partners",
            "pc",
            "phplist",
            "picasa",
            "photo",
            "photos",
            "pma",
            "podcasts",
            "preview",
            "private",
            "projects",
            "proxy",
            "redirect",
            "root",
            "search",
            "servers",
            "service",
            "services",
            "sites",
            "smtp2",
            "social",
            "source",
            "sql1",
            "ssh",
            "sso",
            "stats",
            "status",
            "storage",
            "storefront",
            "streaming",
            "subscribe",
            "test1",
            "tickets",
            "tools",
            "trac",
            "trading",
            "traffic",
            "traffic1",
            "upload",
            "uploads",
            "v",
            "v1",
            "v3",
            "video",
            "videos",
            "web",
            "web1",
            "web2",
            "web3",
            "webcam",
            "webmail1",
            "webtrader",
            "worker",
            "ws",
            "www3",
            "wwwold",
            "zone",
        ]

    def _check_subdomain(self, subdomain: str, domain: str) -> Optional[str]:
        """Check if a subdomain exists"""
        try:
            socket.gethostbyname(f"{subdomain}.{domain}")
            return f"{subdomain}.{domain}"
        except (socket.gaierror, socket.herror):
            return None

    def enumerate(self, domain: str, progress_callback=None) -> List[str]:
        """Enumerate subdomains using bruteforce (bounded thread pool)."""
        wordlist = self.load_wordlist()
        self.found_subdomains = set()

        total = len(wordlist)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            futures = {
                executor.submit(self._check_subdomain, sub, domain): sub
                for sub in wordlist
            }

            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

                result = future.result()
                if result:
                    self.found_subdomains.add(result)

        return sorted(list(self.found_subdomains))

    def enumerate_with_resolve(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate and resolve IPs for each subdomain"""
        subdomains = self.enumerate(domain)
        results = {}

        for sub in subdomains:
            ips = self.resolver.resolve_with_fallback(sub, "A")
            if ips:
                results[sub] = ips

        return results


class ZoneTransfer:
    """Detect and attempt zone transfers"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout

    def attempt_zone_transfer(self, domain: str, nameserver: str = None) -> List[str]:
        """Attempt AXFR zone transfer"""
        if not nameserver:
            try:
                answers = self.resolver.resolve(domain, "NS")
                nameservers = [str(ns) for ns in answers]
            except Exception:
                return []
        else:
            nameservers = [nameserver]

        for ns in nameservers:
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns, domain, timeout=self.timeout)
                )
                records = []
                for name, node in zone.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name}.{domain} {rdata}")
                if records:
                    return records
            except Exception:
                continue

        return []

    def check_axfr_enabled(self, domain: str) -> Dict:
        """Check if zone transfer is enabled"""
        result = {"vulnerable": False, "nameservers": [], "records": []}

        try:
            answers = self.resolver.resolve(domain, "NS")
            result["nameservers"] = [str(ns) for ns in answers]
        except Exception:
            return result

        if result["nameservers"]:
            records = self.attempt_zone_transfer(domain, result["nameservers"][0])
            if records:
                result["vulnerable"] = True
                result["records"] = records[:100]

        return result


class DNSScanner:
    """Main DNS scanning orchestrator.

    ``scan()`` always returns a dict with the full result shape
    ("domain", "records", "subdomains", "spf", "dmarc",
    "zone_transfer") even if an individual step fails, so the CLI and
    report generation never break on partial results.
    """

    def __init__(self, wordlist_path: str = None, passive: bool = True):
        self.resolver = DNSResolver()
        # Default wordlist is module-relative (works from any CWD).
        self.subenum = SubdomainEnumerator(wordlist_path)
        self.zonetransfer = ZoneTransfer()
        # Passive sources (no API keys) merged in "full" mode; each source
        # degrades independently, so a dead source never breaks the scan.
        self.passive_enumerator = PassiveSubdomainEnumerator() if passive else None

    def scan(self, domain: str, scan_type: str = "basic") -> Dict:
        """Perform a DNS scan; each step degrades independently on error."""
        results = {
            "domain": domain,
            "records": {},
            "subdomains": [],
            "zone_transfer": {},
            "dmarc": {},
            "spf": {},
        }

        print(f"[*] Getting DNS records for {domain}...")
        try:
            results["records"] = self.resolver.get_all_records(domain)
        except Exception as e:
            print(f"[!] DNS record lookup failed for {domain}: {e}")

        print(f"[*] Checking SPF for {domain}...")
        try:
            results["spf"] = self.resolver.check_spf(domain)
        except Exception as e:
            print(f"[!] SPF check failed for {domain}: {e}")

        print(f"[*] Checking DMARC for {domain}...")
        try:
            results["dmarc"] = self.resolver.check_dmarc(domain)
        except Exception as e:
            print(f"[!] DMARC check failed for {domain}: {e}")

        if scan_type in ("full", "subdomains"):
            print(f"[*] Enumerating subdomains for {domain}...")
            try:
                results["subdomains"] = self.subenum.enumerate(domain)
            except Exception as e:
                print(f"[!] Subdomain enumeration failed for {domain}: {e}")

        if scan_type == "full":
            print(f"[*] Checking zone transfer for {domain}...")
            try:
                results["zone_transfer"] = self.zonetransfer.check_axfr_enabled(domain)
            except Exception as e:
                print(f"[!] Zone transfer check failed for {domain}: {e}")

            if self.passive_enumerator is not None:
                print(f"[*] Querying passive subdomain sources for {domain}...")
                try:
                    passive = self.passive_enumerator.enumerate(domain)
                    results["passive_subdomains"] = passive
                    # Merge + dedupe with the brute-force/CT findings.
                    merged = set(results.get("subdomains", []))
                    merged.update(passive.get("subdomains", []))
                    results["subdomains"] = sorted(merged)
                except Exception as e:
                    results["passive_subdomains"] = {
                        "domain": domain,
                        "subdomains": [],
                        "per_source": {},
                        "total": 0,
                        "error": str(e),
                    }
                    print(f"[!] Passive enumeration failed for {domain}: {e}")

        return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dns_scanner.py <domain>")
        sys.exit(1)

    scanner = DNSScanner()
    results = scanner.scan(sys.argv[1], "full")

    print("\n=== DNS Scan Results ===")
    print("\n[Records]")
    for rtype, values in results["records"].items():
        if values:
            print(f"  {rtype}: {', '.join(values)}")

    print(f"\n[Subdomains Found: {len(results['subdomains'])}]")
    for sub in results["subdomains"][:20]:
        print(f"  - {sub}")
    if len(results["subdomains"]) > 20:
        print(f"  ... and {len(results['subdomains']) - 20} more")

    print(f"\n[SPF] {'Exists' if results['spf']['exists'] else 'Not found'}")
    print(f"[DMARC] {'Exists' if results['dmarc']['exists'] else 'Not found'}")
    print(
        f"[Zone Transfer] {'Vulnerable' if results['zone_transfer'].get('vulnerable') else 'Not vulnerable'}"
    )
