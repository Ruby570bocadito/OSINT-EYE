"""OSINT EYE - DNS wildcard detection for subdomain enumeration.

A wildcard ``*.domain`` record makes EVERY random subdomain resolve, so
brute-force and permutation enumeration would report thousands of false
positives. :class:`WildcardDetector` resolves a handful of random labels
that cannot legitimately exist; if they answer, the zone has a wildcard
and the discovered IP set becomes the fingerprint used to discard
candidates that only "resolve" through it.

Design:
* Opt-in: enumerators only filter when a detector instance is handed to
  them, so no test or caller ever triggers hidden DNS traffic.
* The resolution primitive is injectable (``resolve_fn``), as is the
  random-label factory (``label_factory``), keeping every code path
  testable fully offline.
* ``detect()`` never raises on DNS failures — an unresolvable probe is
  simply evidence against the wildcard, and unexpected errors degrade to
  ``wildcard=False`` with an ``error`` note in the detection dict.

Contract consumed by modules/dns/dns_scanner.py and
modules/dns/subdomain_permutator.py:
    detector.detect(domain) -> dict with keys "domain", "wildcard",
    "confidence" ("none"|"medium"|"high"), "wildcard_ips", "probes",
    "resolved" (and optional "error").
    detector.is_false_positive([ip, ...]) -> bool (True when the answer
    set is non-empty and entirely inside the wildcard fingerprint).
"""

import secrets
import socket
from typing import Callable, Dict, List, Optional


def _default_resolve(host: str) -> Optional[str]:
    """Resolve a hostname to its first IPv4 (None on any failure)."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.herror, OSError):
        return None


def _random_label() -> str:
    """A label that cannot legitimately exist in the target zone."""
    return f"oe-wc-{secrets.token_hex(6)}"


class WildcardDetector:
    """Detect wildcard DNS answers and fingerprint their IP set."""

    def __init__(
        self,
        probes: int = 3,
        resolve_fn: Optional[Callable[[str], Optional[str]]] = None,
        label_factory: Optional[Callable[[], str]] = None,
    ):
        self.probes = max(1, int(probes))
        self._resolve_fn = resolve_fn or _default_resolve
        self._label_factory = label_factory or _random_label
        self.last_detection: Dict[str, object] = {}

    def detect(self, domain: str) -> Dict[str, object]:
        """Probe random labels under ``domain``; never raises."""
        detection: Dict[str, object] = {
            "domain": domain,
            "wildcard": False,
            "confidence": "none",
            "wildcard_ips": [],
            "probes": 0,
            "resolved": 0,
        }
        domain = (domain or "").strip().rstrip(".")
        if not domain:
            detection["error"] = "empty domain"
            self.last_detection = detection
            return detection

        detection["probes"] = self.probes
        ips = set()
        resolved = 0
        try:
            for _ in range(self.probes):
                host = f"{self._label_factory()}.{domain}"
                try:
                    ip = self._resolve_fn(host)
                except Exception:
                    ip = None
                if ip:
                    resolved += 1
                    ips.add(ip)
        except Exception as e:
            # Degradation: a broken resolver must never break the scan.
            detection["error"] = str(e)
            self.last_detection = detection
            return detection

        detection["resolved"] = resolved
        detection["wildcard_ips"] = sorted(ips)
        if resolved == 0:
            detection["wildcard"] = False
            detection["confidence"] = "none"
        elif resolved == self.probes:
            detection["wildcard"] = True
            detection["confidence"] = "high"
        else:
            detection["wildcard"] = True
            detection["confidence"] = "medium"

        self.last_detection = detection
        return detection

    def is_false_positive(self, ips: Optional[List[str]]) -> bool:
        """True when every resolved IP is explained by the wildcard."""
        detection = self.last_detection
        if not detection.get("wildcard") or not detection.get("wildcard_ips"):
            return False
        answer = [ip for ip in (ips or []) if ip]
        if not answer:
            return False
        return all(ip in detection["wildcard_ips"] for ip in answer)
