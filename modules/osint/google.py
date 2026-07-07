"""OSINT EYE - Google Dorking Module"""

import requests
import time
import re
from typing import List, Dict
from urllib.parse import quote, urlencode


class GoogleDorker:
    """Google search dorking (no API key required)"""

    def __init__(self, rate_limit_delay: float = 3.0):
        self.rate_limit_delay = rate_limit_delay
        self.base_url = "https://www.google.com/search"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )
        self.session.cookies.set("CONSENT", "YES+")

        self.dorks = {
            "login_pages": [
                "site:{domain} inurl:login",
                "site:{domain} inurl:signin",
                "site:{domain} inurl:auth",
            ],
            "admin_panels": [
                "site:{domain} inurl:admin",
                "site:{domain} inurl:administrator",
                "site:{domain} inurl:panel",
            ],
            "sensitive_files": [
                "site:{domain} ext:pdf",
                "site:{domain} ext:doc OR ext:docx",
                "site:{domain} ext:xls OR ext:xlsx",
                "site:{domain} ext:txt",
            ],
            "config_files": [
                "site:{domain} ext:xml OR ext:conf OR ext:config",
                "site:{domain} filetype:env",
                "site:{domain} filetype:ini",
            ],
            "backup_files": [
                "site:{domain} ext:bak",
                "site:{domain} ext:old",
                "site:{domain} ext:backup",
            ],
            "subdomains": ["site:*.{domain}", "site:{domain} -www"],
            "exposed_cameras": ["site:{domain} inurl:cgi-bin", "inurl:/view.shtml"],
            "sql_errors": [
                'site:{domain} "SQL syntax"',
                'site:{domain} "MySQL syntax"',
                'site:{domain} "Warning:"',
            ],
        }

    def search(self, query: str, num_results: int = 10, retries: int = 0) -> List[Dict]:
        """Execute Google search"""
        if retries > 2:
            print("[!] Max retries reached for Google Search, aborting query.")
            return []
            
        results = []

        try:
            response = self.session.get(
                self.base_url, params={"q": query, "num": num_results}, timeout=30
            )

            if response.status_code == 200:
                results = self._parse_results(response.text)
            elif response.status_code == 429:
                print(f"[!] Google Rate limited. Backing off...")
                time.sleep(15) # Wait 15s instead of 60s
                return self.search(query, num_results, retries=retries + 1)

        except Exception as e:
            print(f"[!] Search error: {e}")

        return results

    def _parse_results(self, html: str) -> List[Dict]:
        """Parse search results"""
        results = []

        title_pattern = re.compile(r"<h3[^>]*>([^<]+)</h3>")
        url_pattern = re.compile(r'/url\?q=([^&"]+)')

        titles = title_pattern.findall(html)
        urls = url_pattern.findall(html)

        for i in range(min(len(titles), len(urls), 20)):
            results.append(
                {
                    "title": titles[i][:200] if i < len(titles) else "",
                    "url": urls[i][:500] if i < len(urls) else "",
                }
            )

        return results

    def dork(self, domain: str, dork_type: str) -> List[Dict]:
        """Execute specific dork type"""
        if dork_type not in self.dorks:
            return []

        all_results = []

        for dork_template in self.dorks[dork_type]:
            query = dork_template.replace("{domain}", domain)

            results = self.search(query)
            all_results.extend(results)

            time.sleep(self.rate_limit_delay)

        return all_results

    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains via Google"""
        results = self.dork(domain, "subdomains")

        subdomains = set()
        for r in results:
            url = r.get("url", "")
            if domain in url:
                match = re.search(
                    r"(https?://)?([a-zA-Z0-9\-\.]+)\." + re.escape(domain), url
                )
                if match:
                    subdomains.add(match.group(2))

        return sorted(list(subdomains))

    def find_login_pages(self, domain: str) -> List[Dict]:
        """Find login pages"""
        return self.dork(domain, "login_pages")

    def find_admin_panels(self, domain: str) -> List[Dict]:
        """Find admin panels"""
        return self.dork(domain, "admin_panels")

    def find_sensitive_files(self, domain: str) -> List[Dict]:
        """Find sensitive files"""
        return self.dork(domain, "sensitive_files")

    def find_config_files(self, domain: str) -> List[Dict]:
        """Find configuration files"""
        return self.dork(domain, "config_files")

    def find_sql_errors(self, domain: str) -> List[Dict]:
        """Find SQL error pages"""
        return self.dork(domain, "sql_errors")

    def full_scan(self, domain: str) -> Dict:
        """Perform comprehensive Google dork scan"""
        print(f"[*] Running Google dorks on {domain}...")

        results = {
            "domain": domain,
            "login_pages": [],
            "admin_panels": [],
            "sensitive_files": [],
            "config_files": [],
            "backup_files": [],
            "subdomains": [],
            "sql_errors": [],
        }

        scan_types = [
            ("login_pages", results["login_pages"]),
            ("admin_panels", results["admin_panels"]),
            ("sensitive_files", results["sensitive_files"]),
            ("config_files", results["config_files"]),
            ("backup_files", results["backup_files"]),
            ("sql_errors", results["sql_errors"]),
        ]

        for dork_type, target_list in scan_types:
            print(f"  [*] Running {dork_type} dork...")
            target_list.extend(self.dork(domain, dork_type))
            time.sleep(self.rate_limit_delay)

        results["subdomains"] = self.enumerate_subdomains(domain)

        return results


class GoogleScanner:
    """Main Google dorking orchestrator"""

    def __init__(self):
        self.dorker = GoogleDorker()

    def scan(self, target: str, scan_type: str = "full") -> Dict:
        """Scan target via Google dorks"""
        if scan_type == "full":
            return self.dorker.full_scan(target)
        elif scan_type == "subdomains":
            return {"subdomains": self.dorker.enumerate_subdomains(target)}
        else:
            return {"results": self.dorker.dork(target, scan_type)}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python google_scanner.py <domain>")
        sys.exit(1)

    scanner = GoogleScanner()
    results = scanner.scan(sys.argv[1])

    print(f"\n=== Google Dorking Results ===")
    print(f"\n[Login Pages] {len(results.get('login_pages', []))}")
    print(f"[Admin Panels] {len(results.get('admin_panels', []))}")
    print(f"[Sensitive Files] {len(results.get('sensitive_files', []))}")
    print(f"[Config Files] {len(results.get('config_files', []))}")
    print(f"[Subdomains] {len(results.get('subdomains', []))}")
