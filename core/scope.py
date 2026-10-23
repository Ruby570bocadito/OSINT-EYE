"""Scope control for OSINT EYE.

Defines what a scan is allowed to touch. The scope is built from include
entries (domains, wildcard domains, IPs, CIDRs — from ``--scope FILE``
and/or the target list itself) and exclude entries (``--exclude``, always
win). Anything a module is about to touch must pass :meth:`Scope.allows`;
rejected targets are recorded as discards (``Scope.discarded`` and
``results["scope"]``) so runs stay auditable.

Matching rules
==============
* ``example.com``      → the apex and every subdomain.
* ``*.example.com``    → subdomains only (the apex is NOT included).
* ``192.0.2.10``       → that exact IP.
* ``192.0.2.0/24``     → any IPv4/IPv6 inside the CIDR block.
* URLs and ``host:port`` strings are reduced to their hostname first.

Comparison is case-insensitive on ASCII (IDN entries must be given in
punycode). An empty include set means unrestricted: only excludes apply.
"""

import ipaddress
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when scope entries cannot be parsed."""


def _normalise_target(value: str) -> str:
    """Reduce a domain/IP/URL/host:port string to a bare hostname/IP.

    Raises ``ScopeError`` for empty or structurally broken input instead
    of letting odd strings silently match nothing.
    """
    if not isinstance(value, str):
        raise ScopeError(f"target no válido: {value!r}")
    candidate = value.strip().lower().rstrip(".")
    if not candidate:
        raise ScopeError("target vacío")
    if any(ord(ch) < 33 for ch in candidate):
        raise ScopeError(f"target con caracteres de control/espacio: {value!r}")
    if "://" in candidate:
        parsed = urlparse(candidate)
        host = parsed.hostname
        if not host:
            raise ScopeError(f"URL sin hostname: {value!r}")
        return host.lower().rstrip(".")
    if "/" in candidate or "@" in candidate:
        # "example.com/path" or "user@example.com" without scheme: parse
        # it with a fake scheme so urlparse does the work for us.
        parsed = urlparse("http://" + candidate)
        host = parsed.hostname
        if not host:
            raise ScopeError(f"target no reconocible: {value!r}")
        return host.lower().rstrip(".")
    if ":" in candidate and _is_ip(candidate) is None:
        # Bare "host:port" (IPv6 literals were handled by _is_ip above).
        head, _, tail = candidate.rpartition(":")
        if head and tail.isdigit():
            candidate = head.strip("[]")
    return candidate


def _is_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


class _DomainRule:
    """Include/exclude rule for one domain or wildcard entry."""

    __slots__ = ("base", "wildcard_only")

    def __init__(self, entry: str):
        cleaned = entry.strip().lower().rstrip(".")
        if cleaned.startswith("*.") or cleaned.startswith("."):
            self.base = cleaned.lstrip("*").lstrip(".")
            self.wildcard_only = True
        else:
            self.base = cleaned
            self.wildcard_only = False
        if not self.base or "/" in self.base:
            raise ScopeError(f"dominio no válido: {entry!r}")

    def matches(self, host: str) -> bool:
        if host == self.base:
            return not self.wildcard_only
        return host.endswith("." + self.base)


class Scope:
    """In-memory scope: includes, excludes and the discard audit log."""

    def __init__(
        self,
        includes: list[str] | None = None,
        excludes: list[str] | None = None,
    ) -> None:
        self._domains: list[_DomainRule] = []
        self._excluded_domains: list[_DomainRule] = []
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_networks: list[
            ipaddress.IPv4Network | ipaddress.IPv6Network
        ] = []
        self.unrestricted = not includes
        self.discarded: list[dict[str, str]] = []

        for entry in includes or []:
            self._add_entry(entry, excluded=False)
        for entry in excludes or []:
            self._add_entry(entry, excluded=True)

    # ── construction ────────────────────────────────────────────────────
    def _add_entry(self, entry: str, excluded: bool) -> None:
        if not isinstance(entry, str) or not entry.strip():
            raise ScopeError(f"entrada de scope vacía: {entry!r}")
        cleaned = entry.strip()
        if "/" in cleaned and "://" not in cleaned:
            try:
                network = ipaddress.ip_network(cleaned, strict=False)
            except ValueError:
                raise ScopeError(f"CIDR no válido: {entry!r}") from None
            (self._excluded_networks if excluded else self._networks).append(network)
            return
        host = _normalise_target(cleaned)
        ip = _is_ip(host)
        if ip is not None:
            network = ipaddress.ip_network(
                f"{ip}/32" if ip.version == 4 else f"{ip}/128"
            )
            (self._excluded_networks if excluded else self._networks).append(network)
            return
        rule = _DomainRule(host)
        (self._excluded_domains if excluded else self._domains).append(rule)

    @classmethod
    def from_file(cls, path: str | Path, excludes: list[str] | None = None) -> "Scope":
        """Build a Scope from a text file (one entry per line).

        Blank lines and ``#`` comments are ignored. Any unparsable entry
        raises ``ScopeError`` listing the offending line — the CLI turns
        that into a clean usage error before a scan starts.
        """
        includes = []
        with open(path, encoding="utf-8") as handle:
            for _line_number, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                includes.append(line)
        return cls(includes=includes, excludes=excludes)

    # ── queries ─────────────────────────────────────────────────────────
    def allows(self, target: str) -> bool:
        """True when ``target`` (domain/IP/URL/host:port) may be touched.

        Unparseable/hostile targets return False (they can never be
        matched against a rule, so they are never in scope) instead of
        raising — callers in the hot path must not crash on external data.
        """
        try:
            host = _normalise_target(target)
            ip = _is_ip(host)
        except ScopeError:
            return False

        if ip is not None:
            for network in self._excluded_networks:
                if ip in network:
                    return False
            if self.unrestricted:
                return True
            return any(ip in network for network in self._networks)

        for rule in self._excluded_domains:
            if rule.matches(host):
                return False
        if self.unrestricted:
            return True
        return any(rule.matches(host) for rule in self._domains)

    def reason(self, target: str) -> str:
        """Human-readable reason when :meth:`allows` returns False."""
        try:
            host = _normalise_target(target)
        except ScopeError:
            return "target no parseable"
        ip = _is_ip(host)
        if ip is not None:
            if any(ip_in_network(ip, net) for net in self._excluded_networks):
                return "IP excluida"
            return "IP fuera de scope"
        if any(rule.matches(host) for rule in self._excluded_domains):
            return "dominio excluido"
        return "fuera de scope"

    # ── audit ───────────────────────────────────────────────────────────
    def discard(self, target: str, module: str = "") -> dict[str, str]:
        """Record (and return) one out-of-scope attempt."""
        entry = {
            "target": str(target),
            "module": module or "unknown",
            "reason": self.reason(target),
            "timestamp": datetime.now().isoformat(),
        }
        self.discarded.append(entry)
        return entry

    def filter_targets(self, targets: Iterable[str], module: str = "") -> list[str]:
        """Return the subset of ``targets`` inside scope, logging the rest.

        Order is preserved; every rejected target gets a discard entry.
        """
        allowed: list[str] = []
        for target in targets:
            if self.allows(target):
                allowed.append(target)
            else:
                self.discard(target, module)
        return allowed

    def to_dict(self) -> dict[str, Any]:
        """Summary embedded in ``results["scope"]`` (JSON-safe)."""
        return {
            "unrestricted": self.unrestricted,
            "includes": len(self._domains) + len(self._networks),
            "excludes": len(self._excluded_domains) + len(self._excluded_networks),
            "discarded": list(self.discarded),
        }


def ip_in_network(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    """Containment check that never raises on version mismatch."""
    try:
        return ip in network
    except TypeError:
        return False
