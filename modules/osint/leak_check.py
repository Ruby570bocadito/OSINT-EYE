"""OSINT EYE - Public breach metadata check (key-free, metadata only).

Answers "does the target domain / organisation show up in publicly
known breaches?" using only open, key-free breach metadata:

* The public HIBP breach catalogue (``GET /api/v3/breaches``) needs no
  API key and lists every known breach with its metadata (title,
  affected domain, date, data classes, record count, description).

Two matching layers, both metadata-only:

* **Exact domain** — the breach's ``Domain`` field equals the target
  domain (high confidence).
* **Name mention** — the organisation name derived from the domain
  appears in a breach title or description (heuristic, reported as
  such, with the matched name and field).

Hard limits baked in: NO credentials are ever looked up (no account
search, no password ranges — those APIs need keys anyway), the
catalogue is fetched once per scan, and every failure degrades to a
``status``/``errors`` entry instead of raising. The catalogue source
occasionally gates the unkeyed endpoint behind rate limits; a 429/403
is reported verbatim as a degradation, never retried aggressively.

Scope semantics (module label "leak_check"): entry guard only — the
catalogue is a third-party service queried *about* the in-scope target.

Contract consumed by osint_eye.py:
    LeakChecker().scan(target, scope=None) -> dict with keys
    "target", "names_checked", "status", "domain_breaches",
    "name_mentions", "summary", "errors", "notes".
"""

import re
from html import unescape
from typing import Dict, List, Optional

from modules._http import HTTPClient, get_client
from modules._scope import allowed as _scope_allowed
from modules.osint.social_footprint import derive_names

HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_html(text: str) -> str:
    """Crude HTML->text for breach descriptions (never raises)."""
    try:
        text = unescape(_TAG_RE.sub(" ", text or ""))
        return _WS_RE.sub(" ", text).strip()
    except Exception:
        return ""


def parse_breaches(payload) -> List[Dict]:
    """Validate the catalogue shape; junk entries are dropped."""
    if not isinstance(payload, list):
        return []
    breaches = []
    for entry in payload:
        if not isinstance(entry, dict) or not entry.get("Name"):
            continue
        breaches.append(
            {
                "name": entry.get("Name"),
                "title": entry.get("Title") or entry.get("Name"),
                "domain": (entry.get("Domain") or "").lower() or None,
                "breach_date": entry.get("BreachDate"),
                "pwn_count": entry.get("PwnCount"),
                "data_classes": [
                    dc for dc in (entry.get("DataClasses") or []) if isinstance(dc, str)
                ],
                "description": strip_html(entry.get("Description") or ""),
                "is_verified": entry.get("IsVerified"),
                "is_sensitive": entry.get("IsSensitive"),
            }
        )
    return breaches


class LeakChecker:
    """Check a target against the public breach catalogue (no keys)."""

    def __init__(self, timeout: int = 20, http: Optional[HTTPClient] = None):
        self.timeout = timeout
        self.http = http or get_client()

    # ── catalogue ────────────────────────────────────────────────────────
    def _fetch_catalogue(self) -> Dict[str, object]:
        """Fetch + parse the public catalogue; degrades, never raises."""
        try:
            resp = self.http.get(HIBP_BREACHES, timeout=self.timeout)
            status = getattr(resp, "status_code", 0)
            if status == 429:
                return {"status": "error", "reason": "rate limited (HTTP 429)"}
            if status in (401, 403):
                return {
                    "status": "error",
                    "reason": f"catalogue gated (HTTP {status}); retry later",
                }
            if status >= 400:
                return {"status": "error", "reason": f"HTTP {status}"}
            return {"status": "ok", "breaches": parse_breaches(resp.json())}
        except Exception as exc:
            reason = str(exc).strip()[:160] or exc.__class__.__name__
            return {"status": "error", "reason": reason}

    # ── matching ─────────────────────────────────────────────────────────
    @staticmethod
    def _match_domain(breaches: List[Dict], domain: str) -> List[Dict]:
        wanted = (domain or "").lower().strip()
        if wanted.startswith("www."):
            wanted = wanted[4:]
        hits = []
        for breach in breaches:
            breach_domain = breach.get("domain")
            if not breach_domain:
                continue
            if breach_domain == wanted or breach_domain.endswith("." + wanted) or (
                wanted.endswith("." + breach_domain)
            ):
                hits.append(breach)
        return hits

    @staticmethod
    def _match_names(breaches: List[Dict], names: List[str], exclude: set) -> List[Dict]:
        """Heuristic: org name inside a breach title/description."""
        hits = []
        for breach in breaches:
            if breach.get("name") in exclude:
                continue
            haystack_title = (breach.get("title") or "").lower()
            haystack_desc = (breach.get("description") or "").lower()
            for name in names:
                if len(name) < 4:
                    continue  # too short: 'app', 'm' would match everything
                if name in haystack_title or name in haystack_desc:
                    field = "title" if name in haystack_title else "description"
                    hits.append(
                        {
                            "breach": breach.get("name"),
                            "matched_name": name,
                            "field": field,
                            "breach_date": breach.get("breach_date"),
                            "pwn_count": breach.get("pwn_count"),
                            "data_classes": breach.get("data_classes"),
                        }
                    )
                    break
        return hits

    # ── orchestration ────────────────────────────────────────────────────
    def scan(
        self,
        target: str,
        names: Optional[List[str]] = None,
        scope=None,
    ) -> Dict[str, object]:
        """Metadata-only breach check for ``target`` (entry-guarded)."""
        target = (target or "").strip()
        errors: Dict[str, str] = {}
        notes = [
            "metadata only: no credentials are queried, ever",
            "public key-free catalogue; per-domain verification would need a paid key",
            "name mentions are heuristic: same-name organisations produce false positives",
        ]

        empty = {
            "target": target,
            "names_checked": [],
            "status": "error",
            "catalogue_size": 0,
            "domain_breaches": [],
            "name_mentions": [],
            "summary": {"exact_domain_breaches": 0, "name_mentions": 0, "total_records": 0},
            "errors": errors,
            "notes": notes,
        }

        if scope is not None and not _scope_allowed(scope, target, "leak_check"):
            print(f"[!] {target} out of scope: skipping leak check")
            return empty

        domain = target.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        org_names = derive_names(domain, names)

        catalogue = self._fetch_catalogue()
        if catalogue.get("status") != "ok":
            errors["catalogue"] = catalogue.get("reason", "catalogue unavailable")
            return empty

        breaches = catalogue.get("breaches", [])
        domain_breaches = self._match_domain(breaches, domain)
        excluded = {b.get("name") for b in domain_breaches}
        name_mentions = self._match_names(breaches, org_names, excluded)

        total_records = sum(
            int(b.get("pwn_count") or 0)
            for b in domain_breaches
            if isinstance(b.get("pwn_count"), int)
        )

        return {
            "target": target,
            "names_checked": org_names,
            "status": "ok",
            "catalogue_size": len(breaches),
            "domain_breaches": domain_breaches,
            "name_mentions": name_mentions,
            "summary": {
                "exact_domain_breaches": len(domain_breaches),
                "name_mentions": len(name_mentions),
                "total_records": total_records,
            },
            "errors": errors,
            "notes": notes,
        }


__all__ = ["LeakChecker", "parse_breaches", "strip_html"]
