"""OSINT EYE - DNS Resolution Module"""

import socket
import dns.resolver
import dns.query
import dns.zone
import dns.name
import concurrent.futures
from typing import List, Dict, Optional, Set
import time


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
        """Try multiple nameservers as fallback"""
        for ns in self.nameservers:
            try:
                self.resolver.nameservers = [ns]
                results = self.resolve(domain, record_type)
                if results:
                    return results
            except Exception:
                continue
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
                if "v=DMARC1" in record:
                    result["exists"] = True
                    result["record"] = record
                    if "p=none" in record:
                        result["policy"] = "none"
                    elif "p=quarantine" in record:
                        result["policy"] = "quarantine"
                    elif "p=reject" in record:
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
                if "v=SPF1" in record:
                    result["exists"] = True
                    result["record"] = record
                    if "-all" in record:
                        result["policy"] = "hardfail"
                    elif "~all" in record:
                        result["policy"] = "softfail"
                    elif "+all" in record:
                        result["policy"] = "pass-all"
        except Exception:
            pass

        return result


class SubdomainEnumerator:
    """Subdomain enumeration using bruteforce"""

    def __init__(self, wordlist_path: str, threads: int = 50, timeout: int = 3):
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        self.resolver = DNSResolver(timeout=timeout)
        self.found_subdomains: Set[str] = set()

    def load_wordlist(self) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(self.wordlist_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return self._get_default_wordlist()

    def _get_default_wordlist(self) -> List[str]:
        """Default common subdomains"""
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
            " lyncdiscover",
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
            "admin",
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
            "shop",
            "support",
            "intranet",
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
            "support",
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
            full_domain = f"{subdomain}.{domain}"
            ip = socket.gethostbyname(full_domain)
            return full_domain
        except (socket.gaierror, socket.herror):
            return None

    def enumerate(self, domain: str, progress_callback=None) -> List[str]:
        """Enumerate subdomains using bruteforce"""
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
    """Main DNS scanning orchestrator"""

    def __init__(self, wordlist_path: str = None):
        self.resolver = DNSResolver()
        self.subenum = SubdomainEnumerator(wordlist_path or "data/wordlists/common.txt")
        self.zonetransfer = ZoneTransfer()

    def scan(self, domain: str, scan_type: str = "basic") -> Dict:
        """Perform complete DNS scan"""
        results = {
            "domain": domain,
            "records": {},
            "subdomains": [],
            "zone_transfer": {},
            "dmarc": {},
            "spf": {},
        }

        print(f"[*] Getting DNS records for {domain}...")
        results["records"] = self.resolver.get_all_records(domain)

        print(f"[*] Checking SPF for {domain}...")
        results["spf"] = self.resolver.check_spf(domain)

        print(f"[*] Checking DMARC for {domain}...")
        results["dmarc"] = self.resolver.check_dmarc(domain)

        if scan_type in ["full", "subdomains"]:
            print(f"[*] Enumerating subdomains for {domain}...")
            results["subdomains"] = self.subenum.enumerate(domain)

        if scan_type == "full":
            print(f"[*] Checking zone transfer for {domain}...")
            results["zone_transfer"] = self.zonetransfer.check_axfr_enabled(domain)

        return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dns_scanner.py <domain>")
        sys.exit(1)

    scanner = DNSScanner()
    results = scanner.scan(sys.argv[1], "full")

    print("\n=== DNS Scan Results ===")
    print(f"\n[Records]")
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
