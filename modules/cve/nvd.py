"""OSINT EYE - CVE Module (NVD API - Free)"""

import requests
import time
from typing import List, Dict, Optional


class CVELookup:
    """CVE lookup via NVD API (free, no key required)"""

    def __init__(self, rate_limit_delay: float = 0.6):
        self.rate_limit_delay = rate_limit_delay
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OSINT-EYE/1.0 (OSINT-Tool)"})

    def search_cve(self, cve_id: str) -> Dict:
        """Get CVE by ID"""
        try:
            params = {"cveId": cve_id}
            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return self._parse_cve_data(data)
            elif response.status_code == 404:
                return {"error": "CVE not found", "cve_id": cve_id}
            else:
                return {"error": f"Status {response.status_code}", "cve_id": cve_id}

        except Exception as e:
            return {"error": str(e), "cve_id": cve_id}

    def _parse_cve_data(self, data: Dict) -> Dict:
        """Parse NVD API response"""
        if not data.get("vulnerabilities"):
            return {"error": "No data"}

        vuln = data["vulnerabilities"][0]["cve"]

        result = {
            "id": vuln.get("id"),
            "description": "",
            "published": vuln.get("published"),
            "last_modified": vuln.get("lastModified"),
            "severity": [],
            "references": [],
            "affected": [],
        }

        if vuln.get("descriptions"):
            for desc in vuln["descriptions"]:
                if desc.get("lang") == "en":
                    result["description"] = desc.get("value", "")
                    break

        if vuln.get("metrics"):
            metrics = vuln["metrics"]

            if metrics.get("cvssMetricV31"):
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                result["severity"].append(
                    {
                        "score": cvss.get("baseScore"),
                        "severity": cvss.get("baseSeverity"),
                        "vector": cvss.get("vectorString"),
                    }
                )
            elif metrics.get("cvssMetricV30"):
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                result["severity"].append(
                    {
                        "score": cvss.get("baseScore"),
                        "severity": cvss.get("baseSeverity"),
                        "vector": cvss.get("vectorString"),
                    }
                )

        if vuln.get("references"):
            for ref in vuln["references"]:
                result["references"].append(
                    {
                        "url": ref.get("url"),
                        "source": ref.get("source"),
                        "tags": ref.get("tags", []),
                    }
                )

        if vuln.get("configurations"):
            for config in vuln["configurations"]:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        result["affected"].append(
                            {
                                "criteria": match.get("criteria"),
                                "vulnerable": match.get("vulnerable"),
                                "version": match.get("version"),
                                "operation": match.get("matchCriteriaId"),
                            }
                        )

        return result

    def search_by_keyword(self, keyword: str, max_results: int = 20) -> List[Dict]:
        """Search CVEs by keyword"""
        results = []

        try:
            params = {"keywordSearch": keyword, "resultsPerPage": max_results}

            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get("vulnerabilities"):
                    for v in data["vulnerabilities"]:
                        results.append(self._parse_cve_data({"vulnerabilities": [v]}))

        except Exception as e:
            print(f"[!] Search error: {e}")

        return results

    def search_by_product(
        self, vendor: str, product: str, version: str = None
    ) -> List[Dict]:
        """Search CVEs by product"""
        keyword = f"{vendor} {product}"
        if version:
            keyword += f" {version}"

        return self.search_by_keyword(keyword)

    def get_recent_cves(self, days: int = 7, max_results: int = 20) -> List[Dict]:
        """Get recent CVEs"""
        results = []

        try:
            from datetime import datetime, timedelta

            pub_start = (datetime.now() - timedelta(days=days)).strftime(
                "%Y-%m-%dT00:00:00.000 UTC"
            )

            params = {"pubStartDate": pub_start, "resultsPerPage": max_results}

            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if data.get("vulnerabilities"):
                    for v in data["vulnerabilities"]:
                        results.append(self._parse_cve_data({"vulnerabilities": [v]}))

        except Exception as e:
            print(f"[!] Error getting recent CVEs: {e}")

        return results

    def correlate_cve(self, service_name: str, version: str = None) -> List[Dict]:
        """Correlate CVEs with discovered service"""
        print(f"[*] Looking for CVEs related to {service_name}...")

        cves = self.search_by_keyword(service_name, max_results=30)

        if version:
            version_filtered = []
            for cve in cves:
                if version in cve.get("description", ""):
                    version_filtered.append(cve)
            return version_filtered

        return cves


class CVEAnalyzer:
    """CVE analysis and severity scoring"""

    def __init__(self):
        self.cve = CVELookup()

    def analyze_service(self, service: Dict) -> Dict:
        """Analyze service and find related CVEs"""
        name = service.get("service", "")
        version = service.get("version", "")

        cves = self.cve.correlate_cve(name, version)

        critical_cves = []
        high_cves = []
        medium_cves = []
        low_cves = []

        for cve in cves:
            severity_list = cve.get("severity", [])
            if severity_list:
                score = severity_list[0].get("score", 0)
                if score >= 9.0:
                    critical_cves.append(cve)
                elif score >= 7.0:
                    high_cves.append(cve)
                elif score >= 4.0:
                    medium_cves.append(cve)
                else:
                    low_cves.append(cve)

        return {
            "service": name,
            "version": version,
            "cves_found": len(cves),
            "critical": critical_cves,
            "high": high_cves,
            "medium": medium_cves,
            "low": low_cves,
            "all_cves": cves,
        }

    def prioritize_cves(self, cves: List[Dict]) -> List[Dict]:
        """Prioritize CVEs by severity and age"""
        scored = []

        for cve in cves:
            severity_list = cve.get("severity", [])
            if severity_list:
                score = severity_list[0].get("score", 0)
                severity = severity_list[0].get("severity", "UNKNOWN")
            else:
                score = 0
                severity = "UNKNOWN"

            scored.append({"cve": cve, "priority_score": score, "severity": severity})

        scored.sort(key=lambda x: x["priority_score"], reverse=True)

        return scored


class CVEScanner:
    """Main CVE scanning orchestrator"""

    def __init__(self):
        self.cve = CVELookup()
        self.analyzer = CVEAnalyzer()

    def scan(self, target: str, scan_type: str = "keyword") -> Dict:
        """Scan for CVEs"""
        if scan_type == "keyword":
            return {"cves": self.cve.search_by_keyword(target)}
        elif scan_type == "recent":
            return {"cves": self.cve.get_recent_cves()}
        elif scan_type == "product":
            return {"cves": self.cve.search_by_product(target)}
        else:
            return {"cves": self.cve.search_cve(target)}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_scanner.py <product>")
        sys.exit(1)

    scanner = CVEScanner()
    results = scanner.scan(sys.argv[1])

    print(f"\n=== CVE Results ===")
    print(f"\n[Found] {len(results.get('cves', []))} CVEs")

    for cve in results.get("cves", [])[:5]:
        print(f"\n{cve.get('id')}")
        print(f"  Score: {cve.get('severity', [{}])[0].get('score', 'N/A')}")
        print(f"  Description: {cve.get('description', '')[:100]}...")
