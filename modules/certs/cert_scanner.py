"""OSINT EYE - Certificate Transparency Module (crt.sh)

Enumerates subdomains from public Certificate Transparency logs via the
free crt.sh JSON API (no API key required). crt.sh is often slow or
rate-limited; every query degrades gracefully to an empty/partial
result with a ``[!]`` warning instead of raising.

Contract consumed by osint_eye.py / tests:
    CertScanner().scan(target) -> dict with "subdomains" (list) among
    other keys.
    CertTransparency()._parse_certificates(raw, kind) -> list of dicts
    with at least a "domain" key.
"""

import re
import time
from typing import List, Dict, Set, Optional

import requests

from modules._http import HTTPClient


class CertTransparency:
    """Certificate Transparency logs enumeration via crt.sh

    ``rate_limit`` enforces a minimum interval (seconds) between
    consecutive HTTP requests so we stay polite with the free crt.sh
    service when several lookups are made back-to-back.
    """

    def __init__(self, rate_limit: float = 1.0):
        self.base_url = "https://crt.sh"
        self.rate_limit = max(0.0, rate_limit)
        self._last_request_ts: float = 0.0
        self.session = HTTPClient(timeout=30)

    def _respect_rate_limit(self) -> None:
        """Sleep just enough to keep the configured minimum interval."""
        elapsed = time.time() - self._last_request_ts
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_ts = time.time()

    def search(self, query: str, search_type: str = "domain") -> List[Dict]:
        """Search crt.sh for certificates (empty list on any failure)."""
        params = {"q": query, "output": "json"}

        try:
            self._respect_rate_limit()
            response = self.session.get(f"{self.base_url}/", params=params, timeout=30)
            response.raise_for_status()

            data = response.json()
            return self._parse_certificates(data, search_type)
        except requests.RequestException as e:
            print(f"[!] Error querying crt.sh: {e}")
            return []
        except ValueError as e:
            print(f"[!] crt.sh returned non-JSON payload: {e}")
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
                # crt.sh exposes the SAN list as "name_value" (newline
                # separated); fall back to "subject_alt_name" for other
                # sources/tests.
                san_data = cert.get("subject_alt_name") or cert.get("name_value", "")

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
        """Extract domains from common name and SAN/name_value fields.

        crt.sh's JSON exposes the full SAN list in ``name_value`` as a
        newline-separated string (older code looked for a
        ``subject_alt_name`` field that crt.sh does not actually return,
        so SAN-only subdomains were silently dropped).
        """
        domains = []

        if common_name:
            domains.append(common_name.lower())

        if san_data:
            # Format 1: "DNS:host1, DNS:host2" style SAN string.
            dns_names = re.findall(r"DNS:(?:\*\.)?([a-zA-Z0-9\-\.]+)", san_data)
            domains.extend([d.lower() for d in dns_names])
            # Format 2: crt.sh name_value, newline (or comma) separated.
            for token in san_data.replace("\r", "").replace(",", "\n").split("\n"):
                token = token.strip().lower()
                if not token:
                    continue
                if token.startswith("*."):
                    token = token[2:]
                if re.fullmatch(r"[a-z0-9\-\.]+", token):
                    domains.append(token)

        return list(dict.fromkeys(domains))

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
            cert_domain = cert["domain"]
            # Exact match or true subdomain (avoids substring matches like
            # "notexample.com" matching "example.com").
            if cert_domain == domain or cert_domain.endswith(f".{domain}"):
                results["subdomains"].add(cert_domain)
                # Skip empty issuers: crt.sh rows without issuer_org would
                # otherwise inflate the unique-issuer count with "".
                if cert["issuer"]:
                    results["unique_issuers"].add(cert["issuer"])
                results["certificates"].append(cert)

        results["subdomains"] = sorted(list(results["subdomains"]))
        results["unique_issuers"] = sorted(list(results["unique_issuers"]))

        return results

    def get_certificate_details(self, fingerprint: str) -> Optional[Dict]:
        """Get detailed certificate information"""
        params = {"q": fingerprint, "output": "json"}

        try:
            self._respect_rate_limit()
            response = self.session.get(f"{self.base_url}/", params=params, timeout=30)
            response.raise_for_status()
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

    print("\n=== Certificate Transparency Results ===")
    print(f"\n[Subdomains: {len(results['subdomains'])}]")
    for sub in results["subdomains"][:30]:
        print(f"  - {sub}")
    if len(results["subdomains"]) > 30:
        print(f"  ... and {len(results['subdomains']) - 30} more")

    print(f"\n[Issuers: {len(results['unique_issuers'])}]")
    for issuer in results["unique_issuers"][:5]:
        print(f"  - {issuer}")
