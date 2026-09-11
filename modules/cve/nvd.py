"""OSINT EYE - CVE Module (NVD API 2.0 - Free)

Queries the free NVD REST API directly (no nvdlib/API key required to
WORK — but the key gives much better throughput: without it NVD allows
only ~5 requests per rolling 30 s window, so this module enforces a
conservative pacing by default).

    * Optional API key: pass ``api_key`` or set ``NVD_API_KEY`` env var.
    * Every request has a timeout and honours the rate limit.
    * HTTP 403/429 triggers a backoff + single retry; on persistent
      failure the lookup degrades to an empty list with a ``[!]``
      warning ("get a free key at https://nvd.nist.gov/developers/
      request-an-api-key") instead of raising.
    * CVEScanner().scan(service, "keyword") always returns
      {"cves": [...]}
"""

import os
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional

import requests


class CVELookup:
    """CVE lookup via the NVD API (free; optional API key).

    Without an API key NVD rate-limits to ~5 requests / 30 s, hence the
    default 6 s pacing. With a key (constructor arg or ``NVD_API_KEY``
    env var) the limit rises to ~50 requests / 30 s and pacing drops to
    ~0.7 s. All lookups degrade gracefully to empty results on failure.
    """

    #: NVD's documented no-key limit is 5 requests / 30 s.
    NO_KEY_DELAY = 6.0
    #: With a key: 50 requests / 30 s -> ~0.7 s per request is safe.
    WITH_KEY_DELAY = 0.7

    def __init__(
        self,
        rate_limit_delay: Optional[float] = None,
        api_key: Optional[str] = None,
    ):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or None
        if rate_limit_delay is not None:
            self.rate_limit_delay = max(0.0, rate_limit_delay)
        else:
            self.rate_limit_delay = (
                self.WITH_KEY_DELAY if self.api_key else self.NO_KEY_DELAY
            )
        self._last_request_ts: float = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OSINT-EYE/1.0 (OSINT-Tool)"})
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

    def _respect_rate_limit(self) -> None:
        """Sleep just enough to keep the configured minimum interval."""
        elapsed = time.time() - self._last_request_ts
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_ts = time.time()

    def _get(self, params: Dict) -> Optional[Dict]:
        """Rate-limited GET against NVD with timeout, backoff and retry.

        Returns parsed JSON on success, or None (after warning) on
        persistent failure/rate limiting. Never raises.
        """
        for attempt in range(2):
            try:
                self._respect_rate_limit()
                response = self.session.get(self.base_url, params=params, timeout=30)

                if response.status_code == 200:
                    return response.json()

                if response.status_code in (403, 429):
                    wait = 30 if not self.api_key else 10
                    print(
                        f"[!] NVD API rate limited (HTTP {response.status_code}). "
                        f"Backing off {wait}s..."
                    )
                    time.sleep(wait)
                    continue

                print(f"[!] NVD API returned HTTP {response.status_code}")
                return None

            except requests.RequestException as e:
                print(f"[!] NVD API request error: {e}")
                return None
            except ValueError as e:
                print(f"[!] NVD API returned non-JSON payload: {e}")
                return None

        print(
            "[!] NVD API unavailable/rate-limited - degrading to empty results. "
            "Tip: request a free API key at "
            "https://nvd.nist.gov/developers/request-an-api-key"
        )
        return None

    def search_cve(self, cve_id: str) -> Dict:
        """Get CVE by ID"""
        data = self._get({"cveId": cve_id})
        if data is None:
            return {"error": "NVD API unavailable", "cve_id": cve_id}

        if not data.get("vulnerabilities"):
            return {"error": "CVE not found", "cve_id": cve_id}

        return self._parse_cve_data(data)

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

            # NVD 2.0 exposes several metric generations. Prefer CVSS v3.x,
            # then fall back to v4.0 / v2.0 (older CVEs often carry ONLY a
            # cvssMetricV2 entry — previously those got an empty severity
            # list and were silently ignored by every consumer).
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                metric_list = metrics.get(metric_key)
                if metric_list and isinstance(metric_list[0], dict):
                    cvss = metric_list[0].get("cvssData")
                    if isinstance(cvss, dict):
                        result["severity"].append(
                            {
                                "score": cvss.get("baseScore"),
                                "severity": cvss.get("baseSeverity"),
                                "vector": cvss.get("vectorString"),
                            }
                        )
                        break

            if not result["severity"] and metrics.get("cvssMetricV2"):
                metric = metrics["cvssMetricV2"][0]
                cvss = metric.get("cvssData") if isinstance(metric, dict) else None
                if isinstance(cvss, dict):
                    # CVSS v2 entries may carry the severity on the metric
                    # itself ("severity") or inside cvssData ("baseSeverity").
                    severity = (
                        cvss.get("baseSeverity")
                        or metric.get("baseSeverity")
                        or metric.get("severity")
                    )
                    result["severity"].append(
                        {
                            "score": cvss.get("baseScore"),
                            "severity": severity,
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
        """Search CVEs by keyword (empty list if the API is unavailable)."""
        results = []

        params = {"keywordSearch": keyword, "resultsPerPage": max_results}
        data = self._get(params)

        if data and data.get("vulnerabilities"):
            for v in data["vulnerabilities"]:
                results.append(self._parse_cve_data({"vulnerabilities": [v]}))

        return results

    def search_by_product(
        self, vendor: str, product: Optional[str] = None, version: Optional[str] = None
    ) -> List[Dict]:
        """Search CVEs by vendor/product (all args optional)."""
        parts = [p for p in (vendor, product, version) if p]
        if not parts:
            return []

        keyword = " ".join(parts)
        return self.search_by_keyword(keyword)

    def get_recent_cves(self, days: int = 7, max_results: int = 20) -> List[Dict]:
        """Get CVEs published in the last ``days`` days.

        NVD 2.0 requires pubStartDate AND pubEndDate together (ISO-8601,
        range <= 120 days); the old code sent only one date with an
        invalid " UTC" suffix, which the API rejects.
        """
        results = []
        days = max(1, min(days, 120))

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)

        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": max_results,
        }

        data = self._get(params)

        if data and data.get("vulnerabilities"):
            for v in data["vulnerabilities"]:
                results.append(self._parse_cve_data({"vulnerabilities": [v]}))

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

    @staticmethod
    def _score_of(cve: Dict) -> float:
        """Numeric CVSS score of a CVE entry (0.0 when absent/malformed).

        NVD entries occasionally carry ``"score": null``; the old code
        compared that None directly (``None >= 9.0`` -> TypeError) and
        ``sorted()`` on mixed None/float scores crashed the same way.
        """
        severity = cve.get("severity")
        if isinstance(severity, list) and severity and isinstance(severity[0], dict):
            try:
                return float(severity[0].get("score") or 0)
            except (TypeError, ValueError):
                return 0.0
        return 0.0

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
            score = self._score_of(cve)
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
            if severity_list and isinstance(severity_list[0], dict):
                severity = severity_list[0].get("severity", "UNKNOWN")
            else:
                severity = "UNKNOWN"

            scored.append(
                {
                    "cve": cve,
                    "priority_score": self._score_of(cve),
                    "severity": severity,
                }
            )

        scored.sort(key=lambda x: x["priority_score"], reverse=True)

        return scored


class CVEScanner:
    """Main CVE scanning orchestrator.

    ``scan(target, scan_type)`` always returns {"cves": [...]} so the
    CLI/report layer can rely on the key even when the NVD API is
    unreachable or rate-limited (empty list + "error" key then).
    """

    def __init__(self):
        self.cve = CVELookup()
        self.analyzer = CVEAnalyzer()

    def scan(self, target: str, scan_type: str = "keyword") -> Dict:
        """Scan for CVEs ("keyword" | "recent" | "product" | CVE id)."""
        if scan_type == "keyword":
            return {"cves": self.cve.search_by_keyword(target)}
        elif scan_type == "recent":
            return {"cves": self.cve.get_recent_cves()}
        elif scan_type == "product":
            # "target" may be "vendor", "vendor product" or
            # "vendor product version".
            parts = target.split()[:3]
            return {"cves": self.cve.search_by_product(*parts)}
        else:
            # Single CVE id lookup (e.g. "CVE-2021-44228").
            result = self.cve.search_cve(target)
            if result.get("error"):
                return {"cves": [], "error": result["error"], "cve_id": target}
            return {"cves": [result]}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cve_scanner.py <product>")
        sys.exit(1)

    scanner = CVEScanner()
    results = scanner.scan(sys.argv[1])

    print("\n=== CVE Results ===")
    print(f"\n[Found] {len(results.get('cves', []))} CVEs")

    for cve in results.get("cves", [])[:5]:
        print(f"\n{cve.get('id')}")
        severity = cve.get("severity") or []
        score = severity[0].get("score", "N/A") if severity else "N/A"
        print(f"  Score: {score}")
        print(f"  Description: {cve.get('description', '')[:100]}...")
