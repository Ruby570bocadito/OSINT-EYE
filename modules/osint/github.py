"""OSINT EYE - GitHub Dorking Module"""

import requests
import time
import re
from typing import List, Dict, Set
from urllib.parse import quote


class GitHubDorker:
    """GitHub code search and dorking (no API key required)"""

    def __init__(self, rate_limit_delay: float = 2.0):
        self.rate_limit_delay = rate_limit_delay
        self.base_url = "https://github.com/search"
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "OSINT-EYE/1.0 (OSINT-Tool; +https://github.com)"}
        )

        self.dorks = {
            "api_keys": [
                "api_key",
                "apikey",
                "api-key",
                "secret_key",
                "secretkey",
                "token",
                "access_token",
                "auth_token",
            ],
            "credentials": ["password", "passwd", "pwd", "username", "user", "login"],
            "aws": ["aws_access_key", "aws_secret_key", "AKIA", "aws_key"],
            "private_keys": [
                "PRIVATE KEY",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN OPENSSH PRIVATE KEY-----",
            ],
            "database": ["mysql_connect", "postgres://", "mongodb://", "redis://"],
            "config": [".env", "config.php", "settings.py", "application.yml"],
        }

    def search(self, query: str, dork_type: str = None) -> List[Dict]:
        """Search GitHub with specific dork"""
        results = []

        if dork_type and dork_type in self.dorks:
            for keyword in self.dorks[dork_type]:
                search_query = f"{keyword} {query}"
                results.extend(self._execute_search(search_query))
                time.sleep(self.rate_limit_delay)
        else:
            results = self._execute_search(query)

        return results

    def _execute_search(self, query: str, retries: int = 0) -> List[Dict]:
        """Execute search request"""
        if retries > 2:
            print("[!] Max retries reached for GitHub Search, aborting query.")
            return []
            
        try:
            params = {"q": query, "type": "code", "l": "Python"}

            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                return self._parse_results(response.text)
            elif response.status_code == 429:
                print(f"[!] GitHub Rate limited. Backing off...")
                time.sleep(15) # Shorter wait time and break out
                return self._execute_search(query, retries=retries + 1)

        except Exception as e:
            print(f"[!] Search error: {e}")

        return []

    def _parse_results(self, html: str) -> List[Dict]:
        """Parse search results from HTML"""
        results = []

        file_pattern = re.compile(r"file-entry[^>]*>(.*?)</a>", re.DOTALL)
        repo_pattern = re.compile(r'href="([^"]+)"[^>]*class="[^"]*link-[^"]*"')

        files = file_pattern.findall(html)

        for file in files[:20]:
            file = file.strip()
            if file:
                results.append({"file": file, "type": "code"})

        return results

    def search_by_org(self, org: str, dork_type: str = None) -> List[Dict]:
        """Search within organization"""
        return self.search(f"org:{org}", dork_type)

    def search_by_extension(self, extension: str, query: str = "*") -> List[Dict]:
        """Search by file extension"""
        return self.search(f"{query} extension:{extension}")

    def scan_repo(self, repo: str) -> Dict:
        """Scan repository for sensitive data"""
        results = {"repo": repo, "findings": []}

        for dork_type in self.dorks.keys():
            findings = self.search(f"repo:{repo}", dork_type)
            results["findings"].extend(findings)
            time.sleep(self.rate_limit_delay)

        return results

    def find_leaked_secrets(self, domain: str) -> Dict:
        """Find potentially leaked secrets for a domain"""
        print(f"[*] Searching GitHub for leaked data related to {domain}...")

        results = {
            "domain": domain,
            "api_keys": [],
            "credentials": [],
            "private_keys": [],
            "database_configs": [],
            "total_findings": 0,
        }

        queries = [
            (self.dorks["api_keys"], "api_keys"),
            (self.dorks["credentials"], "credentials"),
            (self.dorks["private_keys"], "private_keys"),
            (self.dorks["database"], "database_configs"),
        ]

        for keywords, category in queries:
            for keyword in keywords:
                query = f"{keyword} {domain}"
                findings = self._execute_search(query)

                for finding in findings:
                    finding["keyword"] = keyword
                    finding["query"] = query
                    results[category].append(finding)

                time.sleep(self.rate_limit_delay)

        results["total_findings"] = (
            len(results["api_keys"])
            + len(results["credentials"])
            + len(results["private_keys"])
            + len(results["database_configs"])
        )

        return results


class GitHubScanner:
    """Main GitHub scanning orchestrator"""

    def __init__(self):
        self.dorker = GitHubDorker()

    def scan(self, target: str, scan_type: str = "secrets") -> Dict:
        """Scan target via GitHub dorks"""
        if scan_type == "secrets":
            return self.dorker.find_leaked_secrets(target)
        elif scan_type == "full":
            return self.dorker.scan_repo(target)
        else:
            return self.dorker.search(target)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python github_scanner.py <domain>")
        sys.exit(1)

    scanner = GitHubScanner()
    results = scanner.scan(sys.argv[1])

    print(f"\n=== GitHub Dorking Results ===")
    print(f"\n[Domain] {results.get('domain')}")
    print(f"[API Keys] {len(results.get('api_keys', []))}")
    print(f"[Credentials] {len(results.get('credentials', []))}")
    print(f"[Private Keys] {len(results.get('private_keys', []))}")
    print(f"[Database Configs] {len(results.get('database_configs', []))}")
    print(f"\n[Total Findings] {results.get('total_findings', 0)}")
