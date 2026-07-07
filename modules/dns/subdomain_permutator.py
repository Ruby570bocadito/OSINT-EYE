"""OSINT EYE - Advanced Subdomain Permutation Engine"""

import socket
import dns.resolver
import concurrent.futures
import itertools
import hashlib
from typing import List, Dict, Set, Optional
from datetime import datetime


class SubdomainPermutator:
    """Advanced subdomain permutation algorithm"""

    def __init__(self, threads: int = 50, timeout: int = 2):
        self.threads = threads
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.found: Set[str] = set()

        self.prefixes = [
            "www",
            "mail",
            "ftp",
            "webmail",
            "smtp",
            "pop",
            "ns1",
            "ns2",
            "cpanel",
            "whm",
            "autodiscover",
            "autoconfig",
            "m",
            "imap",
            "test",
            "dev",
            "staging",
            "beta",
            "stage",
            "prod",
            "production",
            "preprod",
            "pre",
            "uat",
            "qa",
            "demo",
            "sandbox",
            "sandbox",
            "api",
            "app",
            "admin",
            "dashboard",
            "console",
            "portal",
            "my",
            "login",
            "auth",
            "sso",
            "oauth",
            "signin",
            "sign-in",
            "signin",
            "secure",
            "securemail",
            "vpn",
            "remote",
            "access",
            "gateway",
            "proxy",
            "lb",
            "loadbalancer",
            "cdn",
            "static",
            "assets",
            "media",
            "img",
            "images",
            "video",
            "videos",
            "audio",
            "files",
            "docs",
            "doc",
            "docs",
            "wiki",
            "kb",
            "help",
            "support",
            "faq",
            "blog",
            "news",
            "press",
            "careers",
            "jobs",
            "hr",
            "intranet",
            "extranet",
            "partner",
            "partners",
            "vendor",
            "vendors",
            "client",
            "clients",
            "customer",
            "customers",
            "user",
            "users",
            "member",
            "members",
            "team",
            "internal",
            "external",
            "dev1",
            "dev2",
            "dev3",
            "test1",
            "test2",
            "test3",
            "staging1",
            "staging2",
            "stg1",
            "stg2",
            "uat1",
            "uat2",
            "v1",
            "v2",
            "v3",
            "v4",
            "api1",
            "api2",
            "api3",
            "old",
            "new",
            "legacy",
            "archive",
            "backup",
            "bak",
            "db",
            "database",
            "sql",
            "mysql",
            "postgres",
            "mongodb",
            "redis",
            "cache",
            "memcached",
            "elastic",
            "kibana",
            "grafana",
            "monitor",
            "monitoring",
            "metrics",
            "logs",
            "log",
            "syslog",
            "jenkins",
            "gitlab",
            "github",
            "bitbucket",
            "svn",
            "cvs",
            "build",
            "ci",
            "cd",
            "deploy",
            "release",
            "artifacts",
            "docker",
            "k8s",
            "kubernetes",
            "helm",
            "registry",
            "harbor",
            "git",
            "repo",
            "repos",
            "code",
            "source",
            "src",
            "web",
            "web1",
            "web2",
            "web3",
            "webapp",
            "webapps",
            "app1",
            "app2",
            "app3",
            "mobile",
            "mapi",
            "mweb",
            "shop",
            "store",
            "ecommerce",
            "cart",
            "checkout",
            "payment",
            "billing",
            "invoice",
            "invoices",
            "account",
            "accounts",
            "crm",
            "erp",
            "hrms",
            "ats",
            "lms",
            "cms",
            "dms",
            "pms",
            "waf",
            "firewall",
            "ids",
            "ips",
            "siem",
            "soc",
            "dmz",
            "mail1",
            "mail2",
            "mail3",
            "mx1",
            "mx2",
            "mx3",
            "smtp1",
            "smtp2",
            "imap1",
            "imap2",
            "pop3",
            "owa",
            "exchange",
            "activesync",
            "dav",
            "cal",
            "carddav",
            "ldap",
            "ad",
            "active-directory",
            "domain",
            "dc",
            "print",
            "printer",
            "scanner",
            "camera",
            "cctv",
            "nvr",
            "iot",
            "iot1",
            "iot2",
            "sensor",
            "sensors",
            "wifi",
            "wireless",
            "ap",
            "controller",
            "cloud",
            "aws",
            "azure",
            "gcp",
            "digitalocean",
            "heroku",
            "vercel",
            "netlify",
            "render",
            "fly",
            "railway",
            "jira",
            "confluence",
            "slack",
            "discord",
            "teams",
            "zoom",
            "meet",
            "webinar",
            "webconf",
            "s3",
            "s3-console",
            "s3-bucket",
            "bucket",
            "buckets",
            "rds",
            "ec2",
            "lambda",
            "dynamodb",
            "sqs",
            "sns",
            "elasticsearch",
            "logstash",
            "kibana",
            "kafka",
            "rabbitmq",
            "nats",
            "mqtt",
            "amqp",
            "graphql",
            "rest",
            "soap",
            "grpc",
            "websocket",
            "ws",
            "webhook",
            "webhooks",
            "callback",
            "hooks",
            "status",
            "health",
            "healthcheck",
            "ping",
            "heartbeat",
            "metrics",
            "prometheus",
            "alertmanager",
            "alert",
            "debug",
            "trace",
            "profiler",
            "pprof",
            "debug1",
            "temp",
            "tmp",
            "scratch",
            "playground",
            "lab",
            "labs",
            "research",
            "r&d",
            "rnd",
            "innovation",
            "sandbox",
            "training",
            "learn",
            "edu",
            "education",
            "academy",
            "onboarding",
            "offboarding",
            "recruiting",
            "talent",
            "performance",
            "review",
            "feedback",
            "survey",
            "analytics",
            "tracking",
            "pixel",
            "tag",
            "tags",
            "ab",
            "experiment",
            "feature",
            "feature-flag",
            "toggle",
            "dark",
            "darkweb",
            "hidden",
            "secret",
            "private",
            "confidential",
            "classified",
            "restricted",
            "internal-only",
            "restricted",
            "protected",
            "sensitive",
            "confidential",
        ]

        self.suffixes = [
            "",
            "1",
            "2",
            "3",
            "4",
            "5",
            "-dev",
            "-test",
            "-staging",
            "-prod",
            "-uat",
            "-qa",
            "-api",
            "-app",
            "-web",
            "-admin",
            "-portal",
            "-internal",
            "-external",
            "-partner",
            "-client",
            "-v1",
            "-v2",
            "-v3",
            "-old",
            "-new",
            "-legacy",
            "-backup",
            "-bak",
            "-archive",
            "-us",
            "-eu",
            "-asia",
            "-ap",
            "-na",
            "-emea",
            "-east",
            "-west",
            "-north",
            "-south",
            "-1",
            "-2",
            "-3",
            "-4",
            "-5",
            "-dev1",
            "-dev2",
            "-staging1",
            "-staging2",
            ".dev",
            ".test",
            ".stage",
            ".prod",
        ]

    def _check_subdomain(self, subdomain: str, domain: str) -> Optional[str]:
        """Check if a subdomain resolves"""
        try:
            full = f"{subdomain}.{domain}"
            socket.gethostbyname(full)
            return full
        except (socket.gaierror, socket.herror):
            return None

    def _check_subdomain_dns(self, subdomain: str, domain: str) -> Optional[str]:
        """Check if subdomain has DNS records"""
        try:
            full = f"{subdomain}.{domain}"
            self.resolver.resolve(full, "A")
            return full
        except Exception:
            return None

    def generate_permutations(
        self, domain: str, base_names: Optional[List[str]] = None
    ) -> List[str]:
        """Generate subdomain permutations from base names"""
        permutations = set()

        if not base_names:
            base_names = [domain.split(".")[0]]

        for base in base_names:
            base = base.lower().replace("-", "").replace("_", "")

            for prefix in self.prefixes:
                permutations.add(f"{prefix}.{domain}")
                permutations.add(f"{prefix}-{base}.{domain}")
                permutations.add(f"{prefix}_{base}.{domain}")
                permutations.add(f"{base}-{prefix}.{domain}")
                permutations.add(f"{base}.{prefix}.{domain}")

            for suffix in self.suffixes:
                if suffix:
                    permutations.add(f"{base}{suffix}.{domain}")
                    permutations.add(f"{base}-{suffix.lstrip('-')}.{domain}")

            for p1 in self.prefixes[:20]:
                for p2 in self.prefixes[:20]:
                    if p1 != p2:
                        permutations.add(f"{p1}-{p2}.{domain}")
                        permutations.add(f"{p2}-{p1}.{domain}")

        return list(permutations)

    def generate_brute_force(self, domain: str, wordlist: List[str]) -> List[str]:
        """Generate brute force combinations"""
        permutations = set()

        for word in wordlist:
            permutations.add(f"{word}.{domain}")
            permutations.add(f"{word}-api.{domain}")
            permutations.add(f"{word}-app.{domain}")
            permutations.add(f"{word}-admin.{domain}")
            permutations.add(f"api-{word}.{domain}")
            permutations.add(f"app-{word}.{domain}")

        return list(permutations)

    def generate_from_discovered(self, domain: str, discovered: List[str]) -> List[str]:
        """Generate permutations from already discovered subdomains"""
        permutations = set()

        base_names = set()
        for sub in discovered:
            parts = sub.replace(f".{domain}", "").split(".")
            for part in parts:
                if len(part) > 1:
                    base_names.add(part)

        for base in base_names:
            for prefix in self.prefixes[:30]:
                permutations.add(f"{prefix}-{base}.{domain}")
                permutations.add(f"{base}-{prefix}.{domain}")

            for suffix in self.suffixes[:15]:
                if suffix:
                    permutations.add(f"{base}{suffix}.{domain}")

        return list(permutations)

    def enumerate(
        self,
        domain: str,
        discovered: Optional[List[str]] = None,
        wordlist: Optional[List[str]] = None,
    ) -> List[str]:
        """Full permutation enumeration"""
        all_permutations = set()

        all_permutations.update(self.generate_permutations(domain))

        if discovered:
            all_permutations.update(self.generate_from_discovered(domain, discovered))

        if wordlist:
            all_permutations.update(self.generate_brute_force(domain, wordlist))

        print(f"[*] Testing {len(all_permutations)} permutations for {domain}...")

        found = set()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            futures = {
                executor.submit(self._check_subdomain, sub, domain): sub
                for sub in all_permutations
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)

        self.found.update(found)

        return sorted(list(self.found))

    def get_stats(self) -> Dict:
        """Get enumeration statistics"""
        return {"total_found": len(self.found), "subdomains": sorted(list(self.found))}


class SubdomainTakeoverDetector:
    """Detect potential subdomain takeovers"""

    def __init__(self):
        self.takeover_signatures = {
            "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
            "GitHub Pages": ["There isn't a GitHub Pages site here"],
            "Heroku": ["No such app", "Could not find that application"],
            "Azure": ["404 Web Site not found", "Resource not found"],
            "Google Cloud": ["No such bucket", "BucketNotFound"],
            "Shopify": ["Sorry, this shop is currently unavailable"],
            "Tumblr": ["There's nothing here"],
            "WordPress": ["Do you want to register"],
            "Bitbucket": ["Repository not found"],
            "Pantheon": ["The gods are wise"],
            "Zendesk": ["Help Center Closed"],
            "Fastly": ["Fastly error: unknown domain"],
            "CloudFront": ["NoSuchDistribution"],
            "Vercel": ["The deployment could not be found"],
            "Netlify": ["Not Found - Request ID"],
        }

    def check_takeover(self, subdomain: str) -> Dict:
        """Check if a subdomain is vulnerable to takeover"""
        result = {
            "subdomain": subdomain,
            "vulnerable": False,
            "service": None,
            "signature": None,
        }

        try:
            import requests

            response = requests.get(
                f"http://{subdomain}", timeout=10, allow_redirects=True
            )

            for service, signatures in self.takeover_signatures.items():
                for sig in signatures:
                    if sig.lower() in response.text.lower():
                        result["vulnerable"] = True
                        result["service"] = service
                        result["signature"] = sig
                        break

                if result["vulnerable"]:
                    break
        except Exception:
            pass

        return result

    def scan_list(self, subdomains: List[str]) -> List[Dict]:
        """Check multiple subdomains for takeover"""
        results = []

        for sub in subdomains:
            result = self.check_takeover(sub)
            if result["vulnerable"]:
                results.append(result)

        return results


class SubdomainMonitor:
    """Monitor for new subdomains over time"""

    def __init__(self):
        self.history = {}

    def add_snapshot(self, domain: str, subdomains: List[str]):
        """Add a snapshot of discovered subdomains"""
        self.history[domain] = {
            "subdomains": set(subdomains),
            "timestamp": datetime.now().isoformat(),
        }

    def detect_new(self, domain: str, new_subdomains: List[str]) -> List[str]:
        """Detect new subdomains since last snapshot"""
        if domain not in self.history:
            return new_subdomains

        known = self.history[domain]["subdomains"]
        new = set(new_subdomains) - known

        return sorted(list(new))

    def detect_removed(self, domain: str, current_subdomains: List[str]) -> List[str]:
        """Detect subdomains that were removed"""
        if domain not in self.history:
            return []

        known = self.history[domain]["subdomains"]
        current = set(current_subdomains)

        removed = known - current

        return sorted(list(removed))


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python subdomain_permutator.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    permutator = SubdomainPermutator(threads=100)
    found = permutator.enumerate(domain)

    print(f"\n=== Permutation Results ===")
    print(f"Found: {len(found)} subdomains")
    for sub in found[:30]:
        print(f"  - {sub}")
    if len(found) > 30:
        print(f"  ... and {len(found) - 30} more")
