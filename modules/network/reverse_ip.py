"""OSINT EYE - Reverse IP neighbours and virtual host discovery.

Two independent views of the same question ("what else lives on this
IP?"), both reconnaissance-only:

* **Reverse IP** — neighbours reported by a public key-free source
  (HackerTarget reverse IP lookup). The neighbour hostnames are pure
  intelligence: the module never contacts them.
* **Virtual hosts** — active probing of the *target IP itself* with
  different ``Host:`` headers (operator's domain labels + optional
  candidates). A response that differs from the IP baseline (status,
  Server header, title or body length) reveals a virtual host served
  from the same box. Only the in-scope IP is requested.

Scope semantics (module labels "reverse_ip" for the entry guard and
"reverse_ip_vhosts" for derived Host candidates): ``scope=None`` keeps
the pre-scope behaviour (everything allowed); with a scope, out-of-scope
candidates are skipped and logged via ``Scope.discard()``.

Every source degrades independently: failures land in ``errors`` or a
``status`` field, never an exception to the caller.

Contract consumed by osint_eye.py:
    ReverseIPVHostScanner().scan(target, scope=None) -> dict:
    keys "target", "ip", "reverse_ip", "vhosts", "errors", "summary".
"""

import concurrent.futures
import ipaddress
import os
import re
import socket
from typing import Dict, List, Optional

from modules._http import HTTPClient, get_client
from modules._scope import allowed as _scope_allowed

HACKERTARGET_REVERSEIP = "https://api.hackertarget.com/reverseiplookup/"

#: Default Host labels tried against the target IP when the target is a
#: domain (``<label>.<domain>``); deliberately small and polite.
VHOST_LABELS: List[str] = [
    "www",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "dev",
    "staging",
    "test",
    "api",
    "admin",
    "portal",
    "intranet",
    "vpn",
    "cdn",
    "static",
    "app",
    "m",
    "blog",
]

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63})+$")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

MAX_CANDIDATES = 32
MAX_NEIGHBORS = 200

_WORDLIST_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "wordlists", "vhosts.txt"
)


def _load_labels() -> List[str]:
    """Vhost labels from data/wordlists/vhosts.txt (built-in fallback)."""
    try:
        with open(_WORDLIST_PATH, encoding="utf-8") as fh:
            labels = [
                line.strip().lower()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
        if labels:
            return labels
    except OSError:
        pass
    return list(VHOST_LABELS)


def parse_reverse_ip(text: str) -> List[str]:
    """Extract neighbour hostnames from a reverse-IP text answer.

    HackerTarget returns one hostname per line, or a human message on
    rate limits/errors ("error check your API rate limit", "API count
    exceeded"). Only hostname-shaped lines are kept; junk and messages
    are dropped so callers can treat an empty list as "no data".
    """
    neighbors: List[str] = []
    for raw in (text or "").splitlines():
        host = raw.strip().strip(".").lower()
        if not host or " " in host:
            continue
        if _HOSTNAME_RE.match(host) and host not in neighbors:
            neighbors.append(host)
        if len(neighbors) >= MAX_NEIGHBORS:
            break
    return neighbors


def extract_title(html: str) -> Optional[str]:
    """First <title> of a response body, truncated (never raises)."""
    try:
        match = _TITLE_RE.search(html or "")
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()
            return title[:120] or None
    except Exception:
        pass
    return None


class ReverseIPVHostScanner:
    """Reverse-IP neighbours + virtual hosts served by the target IP."""

    def __init__(
        self,
        timeout: int = 10,
        http: Optional[HTTPClient] = None,
        labels: Optional[List[str]] = None,
        max_workers: int = 8,
    ):
        self.timeout = timeout
        self.http = http or get_client()
        self.labels = labels if labels is not None else _load_labels()
        self.max_workers = max(1, int(max_workers))

    # ── helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _result(target: str) -> Dict:
        return {
            "target": target,
            "ip": None,
            "reverse_ip": {"status": "error", "source": "hackertarget", "neighbors": [], "total": 0},
            "vhosts": {"status": "error", "tested": 0, "found": [], "baseline": None},
            "errors": {},
            "summary": {"neighbors": 0, "vhosts_found": 0},
        }

    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _resolve_ip(self, target: str) -> Optional[str]:
        if self._is_ip(target):
            return target
        try:
            return socket.gethostbyname(target)
        except (socket.gaierror, socket.herror, OSError):
            return None

    def _reverse_ip_lookup(self, ip: str) -> Dict[str, object]:
        """HackerTarget reverse IP; degrades to status error."""
        try:
            resp = self.http.get(
                HACKERTARGET_REVERSEIP,
                params={"q": ip},
                timeout=self.timeout,
            )
            status = getattr(resp, "status_code", 0)
            text = getattr(resp, "text", "") or ""
            if status >= 400:
                return {
                    "status": "error",
                    "source": "hackertarget",
                    "reason": f"HTTP {status}",
                    "neighbors": [],
                    "total": 0,
                }
            neighbors = parse_reverse_ip(text)
            if not neighbors and not text.strip():
                return {
                    "status": "ok",
                    "source": "hackertarget",
                    "note": "no neighbours reported",
                    "neighbors": [],
                    "total": 0,
                }
            if not neighbors:
                # 200 but no hostname-shaped line: source message (rate
                # limit, blocked, ...) — report as error, never as data.
                return {
                    "status": "error",
                    "source": "hackertarget",
                    "reason": "unparseable source answer (rate limit?)",
                    "neighbors": [],
                    "total": 0,
                }
            return {"status": "ok", "source": "hackertarget", "neighbors": neighbors, "total": len(neighbors)}
        except Exception as exc:
            return {
                "status": "error",
                "source": "hackertarget",
                "reason": str(exc)[:160] or exc.__class__.__name__,
                "neighbors": [],
                "total": 0,
            }

    # ── virtual host probing ─────────────────────────────────────────────
    def _request_with_host(self, ip: str, host: str) -> Optional[Dict]:
        """GET http://<ip>/ with a custom Host header; None on failure."""
        try:
            resp = self.http.get(
                f"http://{ip}/", headers={"Host": host}, timeout=self.timeout
            )
            body = getattr(resp, "text", "") or ""
            return {
                "status": getattr(resp, "status_code", None),
                "length": len(body),
                "server": resp.headers.get("Server"),
                "title": extract_title(body),
            }
        except Exception:
            return None

    @staticmethod
    def _differs(baseline: Dict, candidate: Dict) -> Optional[str]:
        """First signal that ``candidate`` is a distinct virtual host."""
        if candidate.get("status") != baseline.get("status"):
            return "status"
        if candidate.get("server") != baseline.get("server"):
            return "server"
        if candidate.get("title") != baseline.get("title"):
            return "title"
        base_len = baseline.get("length") or 0
        cand_len = candidate.get("length") or 0
        if base_len and abs(cand_len - base_len) / max(1, base_len) > 0.25:
            return "length"
        return None

    def _vhost_candidates(self, target: str, ip: str, extra: List[str]) -> List[str]:
        candidates: List[str] = []
        if not self._is_ip(target):
            domain = target.lower()
            candidates.extend([domain, f"www.{domain}"])
            candidates.extend(f"{label}.{domain}" for label in self.labels)
        else:
            # IP target: PTR name of the in-scope IP is the only
            # self-derived candidate; everything else must be explicit.
            try:
                ptr = socket.gethostbyaddr(ip)[0]
                if ptr:
                    candidates.append(ptr.lower())
            except Exception:
                pass
        for item in extra:
            if item:
                candidates.append(str(item).strip().lower())
        # Dedupe, preserve order, cap.
        seen = set()
        unique = []
        for cand in candidates:
            if cand and cand not in seen:
                seen.add(cand)
                unique.append(cand)
        return unique[:MAX_CANDIDATES]

    def _probe_vhosts(self, ip: str, candidates: List[str], scope) -> Dict[str, object]:
        baseline = self._request_with_host(ip, ip)
        if baseline is None:
            return {
                "status": "error",
                "reason": "no HTTP answer from the target IP (baseline failed)",
                "tested": 0,
                "found": [],
                "baseline": None,
            }

        allowed = [
            c for c in candidates if _scope_allowed(scope, c, "reverse_ip_vhosts")
        ]
        found: List[Dict[str, object]] = []
        tested = 0

        def check(candidate: str):
            return candidate, self._request_with_host(ip, candidate)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for candidate, answer in pool.map(check, allowed):
                tested += 1
                if answer is None:
                    continue
                difference = self._differs(baseline, answer)
                if difference:
                    entry = {"host": candidate, "difference": difference, **answer}
                    found.append(entry)

        return {
            "status": "ok",
            "tested": tested,
            "found": found,
            "baseline": baseline,
            "candidates_skipped": len(candidates) - len(allowed),
        }

    # ── orchestration ────────────────────────────────────────────────────
    def scan(self, target: str, scope=None, candidates: Optional[List[str]] = None) -> Dict:
        """Reverse IP + vhost discovery for ``target``.

        ``scope`` is optional (``core.scope.Scope``): the target must be
        in scope (entry guard, label "reverse_ip"); vhost Host
        candidates derived from the target are gated individually
        (label "reverse_ip_vhosts").
        """
        target = (target or "").strip()
        results = self._result(target)

        if scope is not None and not _scope_allowed(scope, target, "reverse_ip"):
            print(f"[!] {target} out of scope: skipping reverse-IP/vhosts")
            return results

        ip = self._resolve_ip(target)
        if ip is None:
            results["errors"]["resolve"] = "could not resolve the target to an IP"
            return results
        results["ip"] = ip

        # Neighbours: intelligence only, never contacted.
        results["reverse_ip"] = self._reverse_ip_lookup(ip)
        results["summary"]["neighbors"] = results["reverse_ip"].get("total", 0)

        all_candidates = list(candidates or [])
        derived = self._vhost_candidates(target, ip, all_candidates)
        if derived:
            vhosts = self._probe_vhosts(ip, derived, scope)
            results["vhosts"] = vhosts
            results["summary"]["vhosts_found"] = len(vhosts.get("found", []))
        else:
            results["vhosts"] = {
                "status": "ok",
                "tested": 0,
                "found": [],
                "baseline": None,
                "reason": "no vhost candidates for an IP target (pass candidates explicitly)",
            }

        return results
