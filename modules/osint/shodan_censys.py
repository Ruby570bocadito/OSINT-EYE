"""OSINT EYE - Optional Shodan / Censys / FOFA host intelligence.

Enriches a scan with the public host-intelligence APIs when the operator
has an account: keys are read from the environment and never required —
a provider without its key is reported as ``"skipped"`` and the scan
continues, exactly like every other optional source.

Environment variables (all optional):

* ``OSINT_EYE_SHODAN_KEY``                    — Shodan API key
* ``OSINT_EYE_CENSYS_API_ID`` / ``OSINT_EYE_CENSYS_API_SECRET`` — Censys v2 basic auth pair
* ``OSINT_EYE_FOFA_EMAIL`` / ``OSINT_EYE_FOFA_KEY``             — FOFA account

For a domain target the collectors resolve it first and ask the APIs
about the IP(s) / the domain name; for an IP target the IP is used as
is. No derived host is ever contacted directly: the module only talks to
the provider APIs, so scope enforcement stays with the core (the target
itself is already authorized).

Every provider degrades independently: an HTTP failure, a rate limit or
malformed JSON yields a ``{"status": "error", "reason": ...}`` provider
block, never an exception to the caller. API keys are never included in
the returned dict (results may be exported/shared).

Contract: ``ShodanCensysCollector().scan(target)`` -> dict with keys
``"target"``, ``"ip"``, ``"providers"`` (``shodan``/``censys``/``fofa``,
each with ``status`` in {"skipped","ok","error"} plus provider data) and
``"summary"`` (merged ports/services/subdomains/providers_used).
"""

import base64
import ipaddress
import os
import socket
from typing import Dict, List, Optional

from modules._http import HTTPClient, get_client

SHODAN_BASE = "https://api.shodan.io"
CENSYS_BASE = "https://search.censys.io/api/v2"
FOFA_BASE = "https://fofa.info/api/v1/search/all"

MAX_SUBDOMAINS = 200
MAX_SERVICES = 50


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


class ShodanCensysCollector:
    """Query the optional host-intelligence providers configured via env."""

    def __init__(
        self,
        http: Optional[HTTPClient] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: float = 15.0,
    ):
        self.http = http or get_client()
        self.env = os.environ if env is None else env
        self.timeout = timeout

    # ── env access (test seam: self.env is a plain dict) ────────────────
    def _key(self, name: str) -> str:
        return (self.env.get(name) or "").strip()

    # ── providers ────────────────────────────────────────────────────────
    def _shodan(self, target: str, ip: Optional[str]) -> Dict[str, object]:
        key = self._key("OSINT_EYE_SHODAN_KEY")
        if not key:
            return {"status": "skipped", "reason": "no OSINT_EYE_SHODAN_KEY"}
        block: Dict[str, object] = {"status": "error"}
        try:
            # Domain targets: the DNS-entries endpoint lists known
            # subdomains without consuming host credits.
            if not _is_ip(target):
                resp = self.http.get(
                    f"{SHODAN_BASE}/dns/domain/{target}",
                    params={"key": key},
                    timeout=self.timeout,
                )
                if resp.status_code != 200:
                    block["reason"] = f"HTTP {resp.status_code} (dns/domain)"
                else:
                    data = resp.json() or {}
                    subs = [
                        f"{sub}.{target}"
                        for sub in (data.get("subdomains") or [])
                        if sub
                    ][:MAX_SUBDOMAINS]
                    block = {
                        "status": "ok",
                        "subdomains": subs,
                        "total_subdomains": len(subs),
                    }
            # IP lookups (both for IP targets and resolved domains) go
            # through /shodan/host/{ip}.
            if ip:
                resp = self.http.get(
                    f"{SHODAN_BASE}/shodan/host/{ip}",
                    params={"key": key},
                    timeout=self.timeout,
                )
                if resp.status_code != 200:
                    if "reason" in block:
                        block["reason"] = (
                            f"{block['reason']}; HTTP {resp.status_code} (host)"
                        )
                    else:
                        block["reason"] = f"HTTP {resp.status_code} (host)"
                else:
                    data = resp.json() or {}
                    services = []
                    for svc in (data.get("data") or [])[:MAX_SERVICES]:
                        if not isinstance(svc, dict):
                            continue
                        services.append(
                            {
                                "port": svc.get("port"),
                                "transport": svc.get("transport"),
                                "product": svc.get("product"),
                                "version": svc.get("version"),
                                "banner_module": svc.get("_shodan", {}).get("module")
                                if isinstance(svc.get("_shodan"), dict)
                                else None,
                            }
                        )
                    block.update(
                        {
                            "status": "ok",
                            "ip": data.get("ip_str") or ip,
                            "org": data.get("org"),
                            "isp": data.get("isp"),
                            "os": data.get("os"),
                            "country_name": data.get("country_name"),
                            "ports": sorted(
                                {s["port"] for s in services if s.get("port")}
                            ),
                            "services": services,
                            "hostnames": (data.get("hostnames") or [])[:MAX_SUBDOMAINS],
                        }
                    )
        except Exception as exc:  # network down, bad JSON, ...
            block = {"status": "error", "reason": _reason(exc)}
        return block

    def _censys(self, target: str, ip: Optional[str]) -> Dict[str, object]:
        api_id = self._key("OSINT_EYE_CENSYS_API_ID")
        api_secret = self._key("OSINT_EYE_CENSYS_API_SECRET")
        if not (api_id and api_secret):
            return {
                "status": "skipped",
                "reason": "no OSINT_EYE_CENSYS_API_ID/OSINT_EYE_CENSYS_API_SECRET",
            }
        auth = (api_id, api_secret)
        try:
            if ip:
                resp = self.http.get(
                    f"{CENSYS_BASE}/hosts/{ip}",
                    auth=auth,
                    timeout=self.timeout,
                )
                if resp.status_code != 200:
                    return {"status": "error", "reason": f"HTTP {resp.status_code} (hosts)"}
                data = (resp.json() or {}).get("result") or {}
                services = []
                for svc in (data.get("services") or [])[:MAX_SERVICES]:
                    if not isinstance(svc, dict):
                        continue
                    services.append(
                        {
                            "port": svc.get("port"),
                            "transport": svc.get("transport_protocol"),
                            "product": svc.get("service_name"),
                            "banner": (svc.get("banner") or "")[:200] or None,
                        }
                    )
                return {
                    "status": "ok",
                    "ip": ip,
                    "ports": sorted({s["port"] for s in services if s.get("port")}),
                    "services": services,
                    "autonomous_system": (data.get("autonomous_system") or {}).get("description"),
                    "dns_names": (data.get("dns") or {}).get("names", [])[:MAX_SUBDOMAINS],
                }
            # Domain without a resolved IP: fall back to the search API.
            resp = self.http.post(
                f"{CENSYS_BASE}/hosts/search",
                auth=auth,
                json={
                    "query": f"dns.names: {target}",
                    "per_page": 50,
                },
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return {"status": "error", "reason": f"HTTP {resp.status_code} (search)"}
            hits = (resp.json() or {}).get("result", {}).get("hits") or []
            names: List[str] = []
            for hit in hits:
                if not isinstance(hit, dict):
                    continue
                for name in (hit.get("dns") or {}).get("names") or []:
                    if name and name not in names and len(names) < MAX_SUBDOMAINS:
                        names.append(name)
            return {"status": "ok", "dns_names": names, "hits": len(hits)}
        except Exception as exc:
            return {"status": "error", "reason": _reason(exc)}

    def _fofa(self, target: str, ip: Optional[str]) -> Dict[str, object]:
        email = self._key("OSINT_EYE_FOFA_EMAIL")
        key = self._key("OSINT_EYE_FOFA_KEY")
        if not (email and key):
            return {"status": "skipped", "reason": "no OSINT_EYE_FOFA_EMAIL/OSINT_EYE_FOFA_KEY"}
        query = f'ip="{ip}"' if ip else f'domain="{target}"'
        encoded = base64.b64encode(query.encode("utf-8")).decode("ascii")
        try:
            resp = self.http.get(
                FOFA_BASE,
                params={
                    "email": email,
                    "key": key,
                    "qbase64": encoded,
                    "size": MAX_SERVICES,
                },
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return {"status": "error", "reason": f"HTTP {resp.status_code}"}
            data = resp.json() or {}
            if data.get("error"):
                # FOFA answers 200 with {"error": true, "errmsg": ...} on
                # bad credentials/plan limits; surface it without the key.
                return {"status": "error", "reason": f"API error: {data.get('errmsg')}"}
            results = data.get("results") or []
            services = []
            for row in results[:MAX_SERVICES]:
                # results rows: [host, ip, port, title, domain, protocol, ...]
                if isinstance(row, (list, tuple)) and len(row) >= 3:
                    services.append(
                        {
                            "host": row[0],
                            "ip": row[1],
                            "port": row[2],
                            "title": row[3] if len(row) > 3 else None,
                            "protocol": row[5] if len(row) > 5 else None,
                        }
                    )
            return {
                "status": "ok",
                "query": query,
                "total": data.get("size"),
                "services": services,
                "ports": sorted({s["port"] for s in services if isinstance(s.get("port"), int)}),
            }
        except Exception as exc:
            return {"status": "error", "reason": _reason(exc)}

    # ── orchestration ────────────────────────────────────────────────────
    def scan(self, target: str, resolve: bool = True) -> Dict[str, object]:
        """Query every configured provider; independent degradation."""
        target = (target or "").strip()
        ip: Optional[str] = target if _is_ip(target) else None
        if ip is None and resolve:
            try:
                ip = socket.gethostbyname(target)
            except Exception:
                ip = None  # providers that only need the domain still run

        providers = {
            "shodan": self._shodan(target, ip),
            "censys": self._censys(target, ip),
            "fofa": self._fofa(target, ip),
        }

        ports: List[int] = []
        services: List[Dict[str, object]] = []
        subdomains: List[str] = []
        used: List[str] = []
        for name, block in providers.items():
            if block.get("status") != "ok":
                continue
            used.append(name)
            for port in block.get("ports") or []:
                if isinstance(port, int) and port not in ports:
                    ports.append(port)
            for svc in block.get("services") or []:
                if isinstance(svc, dict):
                    services.append({"provider": name, **svc})
            for name_host in block.get("subdomains") or block.get("dns_names") or []:
                if isinstance(name_host, str) and name_host not in subdomains:
                    subdomains.append(name_host)

        return {
            "target": target,
            "ip": ip,
            "providers": providers,
            "summary": {
                "providers_used": used,
                "ports": sorted(ports),
                "services": services[:MAX_SERVICES],
                "subdomains": subdomains[:MAX_SUBDOMAINS],
                "total_subdomains": len(subdomains),
            },
        }


def _reason(exc: Exception) -> str:
    """Short provider-agnostic failure reason (never contains secrets)."""
    text = str(exc).strip()
    return (text[:160] if text else exc.__class__.__name__)
