"""OSINT EYE - WHOIS Module"""

from datetime import datetime
from typing import Dict, Optional

import whois


class WhoisLookup:
    """WHOIS lookup for domains and IP addresses"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def lookup_domain(self, domain: str) -> Dict:
        """Perform WHOIS lookup for a domain"""
        try:
            w = whois.whois(domain, timeout=self.timeout)
            return self._parse_whois_data(w)
        except Exception as e:
            return {"error": str(e), "domain": domain}

    def _parse_whois_data(self, w) -> Dict:
        """Parse WHOIS data into structured format.

        python-whois returns a ``WhoisEntry`` (dict subclass); fields are
        read with dict access and normalised so callers always get the
        same keys (lists/strings or None).
        """
        result = {
            "domain": self._clean(w.get("domain")),
            "registrar": self._clean(w.get("registrar")),
            "creation_date": self._normalize_date(w.get("creation_date")),
            "expiration_date": self._normalize_date(w.get("expiration_date")),
            "updated_date": self._normalize_date(w.get("updated_date")),
            "status": self._normalize_status(w.get("status")),
            "name_servers": self._normalize_name_servers(w.get("name_servers")),
            "registrant": self._parse_registrant(w),
            "admin": self._parse_admin(w),
            "emails": self._normalize_emails(w.get("emails")),
            "raw": str(w)[:500] if w else None,
        }

        return result

    @staticmethod
    def _clean(value) -> Optional[str]:
        """Normalise scalar WHOIS values (empty strings become None)."""
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _normalize_emails(emails) -> list:
        """Normalise the emails field to a list of strings."""
        if not emails:
            return []
        if isinstance(emails, str):
            return [emails]
        return [str(e) for e in emails if e]

    def _normalize_date(self, date) -> Optional[str]:
        """Normalize date fields"""
        if not date:
            return None
        if isinstance(date, list):
            date = date[0]
        if isinstance(date, datetime):
            return date.strftime("%Y-%m-%d")
        return str(date)

    def _normalize_status(self, status) -> list:
        """Normalize status field"""
        if not status:
            return []
        if isinstance(status, str):
            return [status]
        if isinstance(status, list):
            return [s for s in status if s]
        return []

    def _normalize_name_servers(self, ns) -> list:
        """Normalize name servers"""
        if not ns:
            return []
        if isinstance(ns, list):
            return [str(n).lower() for n in ns if n]
        return [str(ns).lower()]

    def _parse_registrant(self, w) -> Optional[Dict]:
        """Parse registrant info from dict-style WHOIS entries.

        python-whois exposes flat keys ("name", "org", "country", ...);
        the old code used attribute access, which never matched and
        always returned None.
        """
        registrant = {
            "name": w.get("name"),
            "organization": w.get("org"),
            "country": w.get("country"),
            "city": w.get("city"),
            "state": w.get("state"),
        }
        if any(registrant.values()):
            return registrant
        return None

    def _parse_admin(self, w) -> Optional[Dict]:
        """Parse admin contact info (dict-style; best effort)."""
        admin = w.get("admin")
        if isinstance(admin, dict):
            cleaned = {
                "name": admin.get("name"),
                "email": admin.get("email"),
                "org": admin.get("organization") or admin.get("org"),
                "country": admin.get("country"),
            }
            if any(cleaned.values()):
                return cleaned
        elif isinstance(admin, str):
            return {"name": admin}
        return None

    def check_expiration(self, domain: str) -> Dict:
        """Check domain expiration status"""
        result = self.lookup_domain(domain)

        if "error" in result:
            return result

        exp_date = result.get("expiration_date")
        if exp_date:
            try:
                exp = datetime.strptime(exp_date, "%Y-%m-%d")
                days_left = (exp - datetime.now()).days
                result["days_until_expiry"] = days_left

                if days_left < 0:
                    result["expiry_status"] = "expired"
                elif days_left < 30:
                    result["expiry_status"] = "expiring_soon"
                else:
                    result["expiry_status"] = "active"
            except Exception:
                pass

        return result


class ASNLookup:
    """ASN and IP range lookup"""

    def __init__(self):
        self.cache = {}

    def get_asn_info(self, ip_or_asn: str) -> Dict:
        """Get ASN info for IP or ASN number"""
        try:
            import ipwhois

            obj = ipwhois.IPWhois(ip_or_asn)
            results = obj.lookup_rdap(depth=1)

            return {
                "asn": results.get("asn"),
                "asn_description": results.get("asn_description"),
                "network": results.get("network", {}).get("name"),
                "country": results.get("network", {}).get("country"),
                "cidr": results.get("network", {}).get("cidr"),
                "parent": results.get("network", {}).get("parent"),
                "abuse_contacts": results.get("abuse_contacts"),
                "created": results.get("network", {}).get("created"),
                "updated": results.get("network", {}).get("updated"),
            }
        except Exception as e:
            return {"error": str(e)}

    def get_asn_peers(self, asn: str) -> list:
        """Get ASN peers (basic implementation)"""
        return []


class WhoisScanner:
    """Main WHOIS scanning orchestrator"""

    def __init__(self):
        self.whois = WhoisLookup()
        self.asn = ASNLookup()

    def scan(self, target: str, scan_type: str = "domain") -> Dict:
        """Scan target via WHOIS"""
        if scan_type == "domain":
            return self.whois.lookup_domain(target)
        elif scan_type == "asn":
            return self.asn.get_asn_info(target)
        else:
            return self.whois.lookup_domain(target)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python whois_scanner.py <domain>")
        sys.exit(1)

    scanner = WhoisScanner()
    results = scanner.scan(sys.argv[1])

    print("\n=== WHOIS Results ===")
    print(f"\n[Domain] {results.get('domain')}")
    print(f"[Registrar] {results.get('registrar')}")
    print(f"[Created] {results.get('creation_date')}")
    print(f"[Expiry] {results.get('expiration_date')}")
    print(f"[Name Servers] {', '.join(results.get('name_servers', [])[:5])}")
    if results.get("days_until_expiry"):
        print(f"[Days until expiry] {results.get('days_until_expiry')}")
