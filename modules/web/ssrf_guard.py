"""SSRF guard: never follow redirects into non-public address space.

OSINT targets are hostile by definition: a web server under scan can answer
with a 3xx pointing at the cloud metadata service (169.254.169.254),
loopback, or RFC1918 space, and the redirected response body/headers would
then land in scan reports. Collectors must fetch URLs through `safe_get`,
which validates every redirect hop (scheme + resolved addresses) before
following it. `SSRFBlockedError` derives from `requests.RequestException`,
so existing per-collector error handling keeps working and the scan
continues when a hop is refused.

Known limitation (accepted for now): DNS is resolved once for validation
and again by `requests` when the connection opens, so an adversary able to
rebind DNS between the two lookups could still pivot. Blocking that
requires pinning resolved IPs at the socket level in the shared HTTP
client.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional, Set
from urllib.parse import urljoin, urlparse

import requests

MAX_REDIRECTS = 5


class SSRFBlockedError(requests.RequestException):
    """A URL or redirect hop was refused by the SSRF guard."""


# Deterministic across Python releases: membership lists of
# ``is_private``/``is_global`` changed between versions, so the guard
# checks explicit networks instead.
_NON_PUBLIC_V4 = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",        # this network
        "10.0.0.0/8",       # RFC1918 private
        "100.64.0.0/10",    # carrier-grade NAT (cloud metadata in some VPCs)
        "127.0.0.0/8",      # loopback
        "169.254.0.0/16",   # link-local (cloud metadata: 169.254.169.254)
        "172.16.0.0/12",    # RFC1918 private
        "192.0.0.0/24",     # IETF protocol assignments
        "192.0.2.0/24",     # TEST-NET-1
        "192.88.99.0/24",   # 6to4 relay anycast (deprecated)
        "192.168.0.0/16",   # RFC1918 private
        "198.18.0.0/15",    # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",   # TEST-NET-3
        "224.0.0.0/4",      # multicast
        "240.0.0.0/4",      # reserved (incl. 255.255.255.255)
    )
)
_NON_PUBLIC_V6 = tuple(
    ipaddress.ip_network(net)
    for net in (
        "::/128",           # unspecified
        "::1/128",          # loopback
        "64:ff9b::/96",     # NAT64
        "100::/64",         # discard-only
        "2001:db8::/32",    # documentation
        "fc00::/7",         # unique local
        "fe80::/10",        # link-local
        "ff00::/8",         # multicast
    )
)


def _is_non_public(addr: "ipaddress._BaseAddress") -> bool:
    """True when addr is loopback/private/link-local/multicast/reserved."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # ::ffff:127.0.0.1 must not sneak through
    nets = _NON_PUBLIC_V4 if addr.version == 4 else _NON_PUBLIC_V6
    return any(addr in net for net in nets)


def _resolve(host: str) -> Optional[Set[str]]:
    """Resolve host to a set of IP strings; None when unresolvable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, UnicodeError):
        return None
    return {info[4][0] for info in infos}


def is_public_http_url(url: str, resolve: bool = True) -> bool:
    """True when url is http(s) and every resolved address is public.

    Literal-IP hosts are checked directly; hostnames are resolved and every
    answer must be public. Unresolvable, malformed and non-http(s) URLs are
    refused (False), never followed.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not host:
        return False
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        if not resolve:
            return True
        ips = _resolve(host)
        if not ips:
            return False
        addresses = []
        for raw in ips:
            try:
                addresses.append(ipaddress.ip_address(raw))
            except ValueError:
                return False
    else:
        addresses = [literal]
    return all(not _is_non_public(addr) for addr in addresses)


def safe_get(session: "requests.Session", url: str,
             timeout: float = 10, max_redirects: int = MAX_REDIRECTS,
             **kwargs) -> "requests.Response":
    """`session.get(url, allow_redirects=True)` with per-hop SSRF validation.

    Follows redirects manually (up to `max_redirects`, stricter than the
    requests default of 30), validating each hop with `is_public_http_url`.
    Refused or malformed hops raise `SSRFBlockedError`. The list of
    intermediate responses is attached to the final response as
    `response.history`, so callers reporting redirect chains keep working.
    Any explicit `allow_redirects` in kwargs is ignored: this function
    always manages redirects itself.
    """
    kwargs.pop("allow_redirects", None)
    current = url
    hops = []
    for _ in range(max_redirects + 1):
        if not is_public_http_url(current):
            raise SSRFBlockedError(
                f"SSRF guard: refusing non-public URL {current!r}"
            )
        response = session.get(
            current, timeout=timeout, allow_redirects=False, **kwargs
        )
        is_hop = response.is_redirect or response.is_permanent_redirect
        if not is_hop:
            response.history = hops
            return response
        location = response.headers.get("Location")
        if not location:
            response.history = hops
            return response
        hops.append(response)
        try:
            current = urljoin(current, location)
        except ValueError as exc:
            raise SSRFBlockedError(
                f"SSRF guard: malformed redirect target {location!r}"
            ) from exc
    raise SSRFBlockedError(
        f"SSRF guard: more than {max_redirects} redirects"
    )
