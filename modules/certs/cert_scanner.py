"""OSINT EYE - Certificate Transparency Module (crt.sh)"""

import requests
import re
import concurrent.futures
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse
import time


class CertTransparency:
    """Certificate Transparency logs enumeration via crt.sh"""

    def __init__(self, rate_limit: float = 1.0):
        self.base_url = "https://crt.sh"
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OSINT-EYE/1.0 (OSINT-Tool)"})

    def search(self, query: str, search_type: str = "domain") -> List[Dict]:
        """Search crt.sh for certificates"""
        params = {"q": query, "output": "json"}

        try:
            response = self.session.get(f"{self.base_url}/", params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            return self._parse_certificates(data, search_type)
        except requests.RequestException as e:
            print(f"[!] Error querying crt.sh: {e}")
            return []
        except Exception as e:
            print(f"[!] Error parsing certificates: {e}")
            return []

    def _parse_certificates(self, data: List, search_type: str) -> List[Dict]:
        """Parse certificate data"""
        results = []
        seen_domains: Set[str] = set()

        for cert in data:
            try:
                common_name = cert.get("common_name", "")
                san_data = cert.get("subject_alt_name", "")

                domains = self._extract_domains(common_name, san_data)

                for domain in domains:
                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        results.append(
                            {
                                "domain": domain,
                                "issuer": cert.get("issuer_org", ""),
                                "created": cert.get("not_before", ""),
                                "expiry": cert.get("not_after", ""),
                                "fingerprint": cert.get("sha256", ""),
                            }
                        )
            except Exception:
                continue

        return results

    def _extract_domains(self, common_name: str, san_data: str) -> List[str]:
        """Extract domains from common name and SAN"""
        domains = []

        if common_name:
            domains.append(common_name.lower())

        if san_data:
            dns_names = re.findall(r"DNS:(?:\*\.)?([a-zA-Z0-9\-\.]+)", san_data)
            domains.extend([d.lower() for d in dns_names])

        return list(set(domains))

    def enumerate_subdomains(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate subdomains via certificate transparency"""
        print(f"[*] Searching crt.sh for certificates related to {domain}...")

        certs = self.search(domain)

        results = {
            "domain": domain,
            "certificates": [],
            "subdomains": set(),
            "unique_issuers": set(),
        }

        for cert in certs:
            if domain in cert["domain"] or cert["domain"].endswith(f".{domain}"):
                results["subdomains"].add(cert["domain"])
                results["unique_issuers"].add(cert["issuer"])
                results["certificates"].append(cert)

        results["subdomains"] = sorted(list(results["subdomains"]))
        results["unique_issuers"] = sorted(list(results["unique_issuers"]))

        return results

    def get_certificate_details(self, fingerprint: str) -> Optional[Dict]:
        """Get detailed certificate information"""
        params = {"q": fingerprint, "output": "json"}

        try:
            response = self.session.get(f"{self.base_url}/", params=params, timeout=30)
            data = response.json()

            if data:
                cert = data[0]
                return {
                    "common_name": cert.get("common_name"),
                    "issuer": cert.get("issuer_org"),
                    "subject": cert.get("subject"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "serial": cert.get("serial"),
                    "sha256": cert.get("sha256"),
                    "san": cert.get("subject_alt_name"),
                    "key_algorithm": cert.get("key_algorithm"),
                    "signature_algorithm": cert.get("signature_algorithm"),
                }
        except Exception as e:
            print(f"[!] Error getting certificate details: {e}")

        return None

    def scan(self, domain: str) -> Dict:
        """Perform complete certificate transparency scan"""
        results = self.enumerate_subdomains(domain)

        print(f"[*] Found {len(results['subdomains'])} unique subdomains via CT")
        print(f"[*] Found {len(results['unique_issuers'])} unique issuers")

        return results


class CertScanner:
    """Main certificate scanning orchestrator"""

    def __init__(self):
        self.ct = CertTransparency()

    def scan(self, domain: str) -> Dict:
        """Scan domain for certificate transparency data"""
        return self.ct.scan(domain)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python cert_scanner.py <domain>")
        sys.exit(1)

    scanner = CertScanner()
    results = scanner.scan(sys.argv[1])

    print(f"\n=== Certificate Transparency Results ===")
    print(f"\n[Subdomains: {len(results['subdomains'])}]")
    for sub in results["subdomains"][:30]:
        print(f"  - {sub}")
    if len(results["subdomains"]) > 30:
        print(f"  ... and {len(results['subdomains']) - 30} more")

    print(f"\n[Issuers: {len(results['unique_issuers'])}]")
    for issuer in results["unique_issuers"][:5]:
        print(f"  - {issuer}")
