"""OSINT EYE - ASN, ranges and netblocks of an organisation.

Expands the attack surface from one target to the organisation's
announced infrastructure using public, key-free sources only:

* RIPEstat public data API (stat.ripe.net) — origin ASN of the resolved
  IP, organisation holder and every announced prefix for that ASN;
* RDAP (rdap.org) — registration details of the IP's network object
  (name, country, start/end address, type).

Every source degrades independently: a dead endpoint lands in
``errors`` and never aborts the scan. Reported prefixes are intelligence
only — the tool never probes them.

Scope semantics (module label "asn_enum"): the target itself must be in
scope (entry guard, like the cloud module); RIPEstat/RDAP are third-party
lookup services queried *about* the in-scope target.

Contract consumed by osint_eye.py:
    ASNEnumerator().scan(target) -> dict (see shape below).
"""

import ipaddress
import socket
from typing import Dict, List, Optional

from modules._http import HTTPClient
from modules._scope import allowed as _scope_allowed

RIPESTAT_BASE = "https://stat.ripe.net/data"
RDAP_BASE = "https://rdap.org"

#: Hard cap on reported prefixes (bounded results).
MAX_PREFIXES = 500


def parse_asn_from_network_info(payload: Dict) -> Optional[str]:
    """Extract "AS<number>" from a RIPEstat network-info payload."""
    try:
        asn = payload["data"]["asn"]
        if isinstance(asn, int) and asn > 0:
            return f"AS{asn}"
    except (KeyError, TypeError):
        pass
    return None


def parse_holder(payload: Dict) -> Optional[str]:
    """Extract the organisation holder from a RIPEstat as-overview payload."""
    try:
        holder = payload["data"]["holder"]
        if isinstance(holder, str) and holder.strip():
            return holder.strip()
    except (KeyError, TypeError):
        pass
    return None


def parse_prefixes(payload: Dict) -> List[str]:
    """Extract announced prefixes (deduplicated, sorted) from RIPEstat."""
    prefixes = set()
    try:
        for entry in payload["data"]["prefixes"] or []:
            prefix = entry.get("prefix") if isinstance(entry, dict) else None
            if prefix and "/" in prefix:
                prefixes.add(prefix)
    except (KeyError, TypeError, AttributeError):
        pass
    return sorted(prefixes)[:MAX_PREFIXES]


def parse_rdap_network(payload: Dict) -> Dict:
    """Extract the readable fields of an RDAP IP network object."""
    network = {}
    for key, out in (
        ("name", "name"),
        ("country", "country"),
        ("startAddress", "start_address"),
        ("endAddress", "end_address"),
        ("type", "network_type"),
        ("handle", "handle"),
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            network[out] = value.strip()
    return network


class ASNEnumerator:
    """Enumerate the ASN and announced ranges behind a target."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = HTTPClient(timeout=timeout)

    @staticmethod
    def _result(target: str) -> Dict:
        return {
            "target": target,
            "ip": None,
            "asn": None,
            "holder": None,
            "prefixes": [],
            "prefix_count": 0,
            "network": {},
            "sources": [],
            "errors": {},
        }

    def _resolve_ip(self, target: str) -> Optional[str]:
        """Literal IP passes through; domains resolve via system DNS."""
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        try:
            return socket.gethostbyname(target)
        except (socket.gaierror, socket.herror, OSError):
            return None

    def _get_json(self, url: str):
        """GET + parse JSON; returns (payload, error)."""
        try:
            response = self.session.get(url, timeout=self.timeout)
            status = getattr(response, "status_code", None)
            if status is not None and status >= 400:
                return None, f"HTTP {status}"
            return response.json(), None
        except ValueError as e:
            return None, f"JSON no válido: {e}"
        except Exception as e:
            return None, str(e)

    def scan(self, target: str, scope=None) -> Dict:
        """Enumerate ASN/holder/prefixes/network for ``target``.

        ``scope`` is optional (``core.scope.Scope``): an out-of-scope
        target is never resolved nor looked up (module label "asn_enum").
        """
        results = self._result(target)

        if scope is not None and not _scope_allowed(scope, target, "asn_enum"):
            print(f"[!] {target} out of scope: skipping ASN enumeration")
            return results

        ip = self._resolve_ip(target)
        if ip is None:
            results["errors"]["resolve"] = "no se pudo resolver el target a una IP"
            return results
        results["ip"] = ip

        # RDAP: registration details of the IP's network object.
        payload, error = self._get_json(f"{RDAP_BASE}/ip/{ip}")
        if error:
            results["errors"]["rdap"] = error
        else:
            results["network"] = parse_rdap_network(payload or {})
            if results["network"]:
                results["sources"].append("rdap")

        # RIPEstat: origin ASN of the IP.
        payload, error = self._get_json(f"{RIPESTAT_BASE}/network-info/data.json?ip={ip}")
        if error:
            results["errors"]["ripestat.network-info"] = error
        else:
            results["asn"] = parse_asn_from_network_info(payload or {})

        if results["asn"]:
            results["sources"].append("ripestat")

            # Holder (organisation name).
            payload, error = self._get_json(
                f"{RIPESTAT_BASE}/as-overview/data.json?resource={results['asn']}"
            )
            if error:
                results["errors"]["ripestat.as-overview"] = error
            else:
                results["holder"] = parse_holder(payload or {})

            # Announced prefixes (the "netblocks" of the organisation).
            payload, error = self._get_json(
                f"{RIPESTAT_BASE}/announced-prefixes/data.json?resource={results['asn']}"
            )
            if error:
                results["errors"]["ripestat.announced-prefixes"] = error
            else:
                results["prefixes"] = parse_prefixes(payload or {})
                results["prefix_count"] = len(results["prefixes"])

        return results
