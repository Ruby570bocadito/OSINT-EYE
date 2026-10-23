"""OSINT EYE - Passive subdomain sources (no API keys required).

Aggregates several public passive-DNS / certificate-log sources that work
without any API key and merges them into a single deduplicated set:

* HackerTarget   — https://api.hackertarget.com/hostsearch/   (text lines "host,ip")
* AlienVault OTX — https://otx.alienvault.com/.../passive_dns (JSON)
* Anubis (jldc)  — https://jldc.me/anubis/subdomains/         (JSON array)
* RapidDNS       — https://rapiddns.io/subdomain/             (HTML table)
* CertSpotter    — https://api.certspotter.com/v1/issuances   (JSON, free tier)

Design rules:
* Every source is queried through the shared :class:`HTTPClient`
  (bounded timeout, identifiable User-Agent, retries with backoff).
* Sources run concurrently; a failing/hijacked source never breaks the
  scan — it is reported with ``status="error"`` in ``per_source`` and the
  rest of the sources keep going (graceful degradation).
* Every answer is hostile input: hostnames are strictly validated
  (suffix of the scanned domain, sane charset, bounded length, no
  wildcard markers) before entering the result set, so a compromised
  source cannot inject arbitrary strings into reports.

Contract consumed by modules/dns/dns_scanner.py:
    PassiveSubdomainEnumerator().enumerate(domain) -> dict with keys
    "domain", "subdomains" (sorted list, deduplicated), "per_source"
    ({source: {"count", "status"[, "error"]}}) and "total".
"""

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional

from modules._http import HTTPClient

#: Bounded hostname length per RFC 1035 (and a hard cap for sanity).
MAX_HOSTNAME_LEN = 253


def _source_hackertarget(client: HTTPClient, domain: str) -> List[str]:
    """HackerTarget hostsearch API: plain text lines "host,ip"."""
    resp = client.get(
        "https://api.hackertarget.com/hostsearch/",
        params={"q": domain},
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    hosts = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Lines are "hostname,ip" (some error messages are plain text too).
        host = line.split(",")[0].strip()
        hosts.append(host)
    return hosts


def _source_alienvault_otx(client: HTTPClient, domain: str) -> List[str]:
    """AlienVault OTX passive DNS: JSON {"passive_dns": [{"hostname": ...}]}."""
    resp = client.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=20,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    data = resp.json()
    records = data.get("passive_dns") or []
    return [rec.get("hostname") for rec in records if isinstance(rec, dict)]


def _source_anubis(client: HTTPClient, domain: str) -> List[str]:
    """Anubis (jldc.me): JSON array of hostname strings."""
    resp = client.get(
        f"https://jldc.me/anubis/subdomains/{domain}",
        timeout=20,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    data = resp.json()
    if not isinstance(data, list):
        raise RuntimeError("unexpected payload (not a list)")
    return [item for item in data if isinstance(item, str)]


def _source_rapiddns(client: HTTPClient, domain: str) -> List[str]:
    """RapidDNS: HTML table — extract hostnames by strict regex."""
    resp = client.get(
        f"https://rapiddns.io/subdomain/{domain}",
        params={"full": "1"},
        timeout=20,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    pattern = re.compile(r"[a-zA-Z0-9_*\-_.]+\.%s\b" % re.escape(domain))
    return pattern.findall(resp.text)


def _source_certspotter(client: HTTPClient, domain: str) -> List[str]:
    """CertSpotter free tier: JSON issuances with dns_names entries."""
    resp = client.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=20,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    data = resp.json()
    if not isinstance(data, list):
        raise RuntimeError("unexpected payload (not a list)")
    names: List[str] = []
    for issuance in data:
        if isinstance(issuance, dict):
            names.extend(
                n for n in issuance.get("dns_names", []) if isinstance(n, str)
            )
    return names


#: Registry: stable source name -> fetch callable(client, domain) -> list.
SOURCES: Dict[str, Callable[[HTTPClient, str], List[str]]] = {
    "hackertarget": _source_hackertarget,
    "alienvault_otx": _source_alienvault_otx,
    "anubis": _source_anubis,
    "rapiddns": _source_rapiddns,
    "certspotter": _source_certspotter,
}


def valid_subdomain(value: object, domain: str) -> bool:
    """Strict validation of a remote-provided hostname.

    Accepts only plain hostnames that are strict suffixes of ``domain``
    (never the bare domain), lowercase-normalised, with a sane charset
    and length. Wildcards, spaces, slashes, ports, uppercase punycode
    debris and path fragments are all rejected.
    """
    if not isinstance(value, str):
        return False
    host = value.strip().lower().rstrip(".")
    if not host or len(host) > MAX_HOSTNAME_LEN:
        return False
    if "*" in host or "/" in host or "@" in host or ":" in host:
        return False
    domain = domain.strip().lower().rstrip(".")
    if not domain or not host.endswith("." + domain):
        return False
    labels = host[: -len(domain) - 1].split(".")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$")
    # An empty label (".example.com") is malformed: every label must match.
    return bool(labels) and all(label_re.match(label) for label in labels)


class PassiveSubdomainEnumerator:
    """Query every passive source concurrently and merge the results."""

    def __init__(
        self,
        timeout: int = 15,
        sources: Optional[List[str]] = None,
        rate_limit: float = 0.0,
    ):
        self.http = HTTPClient(timeout=timeout, rate_limit=rate_limit)
        unknown = [s for s in (sources or []) if s not in SOURCES]
        if unknown:
            raise ValueError(f"unknown passive sources: {', '.join(sorted(unknown))}")
        self.source_names = list(sources) if sources else list(SOURCES)

    def _query_source(self, name: str, domain: str) -> Dict[str, object]:
        """Run one source; never raises — errors become status entries."""
        entry: Dict[str, object] = {"count": 0, "status": "ok"}
        try:
            raw = SOURCES[name](self.http, domain)
            hosts = {
                h.strip().lower().rstrip(".")
                for h in raw
                if valid_subdomain(h, domain)
            }
            entry["count"] = len(hosts)
            entry["hosts"] = sorted(hosts)
            if not hosts:
                entry["status"] = "empty"
        except Exception as e:
            entry["status"] = "error"
            entry["error"] = str(e)
            entry["count"] = 0
        return entry

    def enumerate(self, domain: str) -> Dict[str, object]:
        """Aggregate all sources; always returns a complete, valid dict."""
        per_source: Dict[str, object] = {}
        all_hosts: set = set()

        # I/O-bound fan-out: each source isolated (own try/except inside
        # _query_source), so one dead source never stalls or breaks the rest.
        with ThreadPoolExecutor(max_workers=max(1, len(self.source_names))) as pool:
            futures = {
                name: pool.submit(self._query_source, name, domain)
                for name in self.source_names
            }
            for name, future in futures.items():
                entry = future.result()
                per_source[name] = entry
                all_hosts.update(entry.get("hosts", []))

        return {
            "domain": domain,
            "subdomains": sorted(all_hosts),
            "per_source": per_source,
            "total": len(all_hosts),
        }
