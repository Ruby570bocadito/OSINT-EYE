"""OSINT EYE - Wayback Machine Module"""

import requests
import re
from datetime import datetime
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse


class WaybackMachine:
    """Wayback Machine API integration for historical URL discovery"""

    def __init__(self, rate_limit: float = 1.0):
        self.rate_limit = rate_limit
        self.base_url = "https://web.archive.org"
        self.cdx_api = "https://web.archive.org/cdx/search/cdx"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OSINT-EYE/1.0 (OSINT-Tool)"})

    def get_wayback_urls(self, domain: str) -> List[Dict]:
        """Get all archived URLs for a domain"""
        params = {
            "url": domain,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "filter": "statuscode:200",
            "limit": 10000,
        }

        try:
            response = self.session.get(self.cdx_api, params=params, timeout=30)
            response.raise_for_status()

            if response.text.strip():
                data = response.json()
                return self._parse_wayback_data(data)
        except Exception as e:
            print(f"[!] Error querying Wayback: {e}")

        return []

    def _parse_wayback_data(self, data: List) -> List[Dict]:
        """Parse CDX API response"""
        results = []
        if not data or len(data) < 2:
            return results

        headers = data[0]
        for row in data[1:]:
            try:
                entry = dict(zip(headers, row))
                results.append(
                    {
                        "timestamp": entry.get("timestamp", ""),
                        "url": entry.get("original", ""),
                        "status_code": entry.get("statuscode", ""),
                        "mime_type": entry.get("mimetype", ""),
                    }
                )
            except Exception:
                continue

        return results

    def get_snapshots(self, domain: str, limit: int = 100) -> Dict:
        """Get snapshot summary for a domain"""
        print(f"[*] Querying Wayback Machine for {domain}...")

        urls = self.get_wayback_urls(domain)

        results = {
            "domain": domain,
            "total_snapshots": len(urls),
            "unique_paths": set(),
            "by_year": {},
            "interesting_urls": [],
        }

        interesting_patterns = [
            r"admin",
            r"login",
            r"wp-",
            r"phpmyadmin",
            r".env",
            r"config",
            r"backup",
            r".git",
            r"svn",
            r"api",
            r"dashboard",
            r"manager",
            r"phpinfo",
            r"shell",
            r"uploads",
            r"temp",
            r"tmp",
        ]

        for entry in urls:
            url = entry["url"]
            results["unique_paths"].add(urlparse(url).path)

            timestamp = entry["timestamp"]
            if timestamp:
                year = timestamp[:4]
                results["by_year"][year] = results["by_year"].get(year, 0) + 1

            for pattern in interesting_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    results["interesting_urls"].append(
                        {"url": url, "pattern": pattern, "timestamp": timestamp}
                    )
                    break

        results["unique_paths"] = sorted(list(results["unique_paths"]))
        results["by_year"] = dict(sorted(results["by_year"].items()))

        return results

    def get_archived_versions(self, url: str) -> List[Dict]:
        """Get all archived versions of a specific URL"""
        params = {
            "url": url,
            "output": "json",
            "fl": "timestamp,original,statuscode",
            "filter": "statuscode:200",
            "limit": 1000,
        }

        try:
            response = self.session.get(self.cdx_api, params=params, timeout=30)
            data = response.json()

            if data and len(data) > 1:
                headers = data[0]
                return [dict(zip(headers, row)) for row in data[1:]]
        except Exception as e:
            print(f"[!] Error getting archived versions: {e}")

        return []

    def check_wayback_available(self, url: str) -> Dict:
        """Check if URL has archived versions"""
        result = {
            "available": False,
            "latest_url": None,
            "latest_timestamp": None,
            "snapshots_count": 0,
        }

        versions = self.get_archived_versions(url)

        if versions:
            result["available"] = True
            result["snapshots_count"] = len(versions)

            latest = versions[0]
            result["latest_timestamp"] = latest.get("timestamp", "")

            ts = latest.get("timestamp", "")
            original = latest.get("original", url)
            result["latest_url"] = f"{self.base_url}/web/{ts}/{original}"

        return result

    def discover_directories(self, domain: str) -> List[str]:
        """Discover directories via Wayback Machine"""
        urls = self.get_wayback_urls(domain)

        directories = set()

        for entry in urls:
            url = entry["url"]
            path = urlparse(url).path

            parts = path.split("/")
            for i in range(1, len(parts)):
                if parts[i]:
                    directories.add("/".join(parts[: i + 1]))

        return sorted(list(directories))[:100]

    def discover_parameters(self, url: str) -> List[str]:
        """Discover URL parameters from archived versions"""
        versions = self.get_archived_versions(url)

        params = set()

        for version in versions:
            url_str = version.get("original", "")
            if "?" in url_str:
                query = url_str.split("?", 1)[1]
                param = query.split("=")[0]
                params.add(param)

        return sorted(list(params))

    def scan(self, domain: str) -> Dict:
        """Perform complete Wayback scan"""
        snapshots = self.get_snapshots(domain)

        print(f"[*] Found {snapshots['total_snapshots']} snapshots")
        print(f"[*] Found {len(snapshots['unique_paths'])} unique paths")
        print(f"[*] Found {len(snapshots['interesting_urls'])} interesting URLs")

        return snapshots


class WaybackScanner:
    """Main Wayback Machine scanning orchestrator"""

    def __init__(self):
        self.wayback = WaybackMachine()

    def scan(self, domain: str) -> Dict:
        """Scan domain via Wayback Machine"""
        return self.wayback.scan(domain)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python wayback_scanner.py <domain>")
        sys.exit(1)

    scanner = WaybackScanner()
    results = scanner.scan(sys.argv[1])

    print(f"\n=== Wayback Machine Results ===")
    print(f"\n[Total Snapshots: {results['total_snapshots']}]")
    print(f"[Unique Paths: {len(results['unique_paths'])}]")

    print(f"\n[Snapshots by Year]")
    for year, count in results["by_year"].items():
        print(f"  {year}: {count}")

    print(f"\n[Interesting URLs: {len(results['interesting_urls'])}]")
    for item in results["interesting_urls"][:15]:
        print(f"  [{item['pattern']}] {item['url']}")
