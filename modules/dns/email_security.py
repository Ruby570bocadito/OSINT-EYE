"""OSINT EYE - Email security / anti-spoofing audit (DNS-only, no keys).

Goes beyond the SPF/DMARC check of the DNS module and reports the full
picture a defender (or an attacker picking an impersonation route) sees:

* DKIM via the most common selector names (``<selector>._domainkey.<domain>``)
* MTA-STS (``_mta-sts.<domain>`` TXT, ``v=STSv1``)
* TLS-RPT (``_smtp._tls.<domain>`` TXT, ``v=TLSRPTv1``)
* BIMI (``<selector>._bimi.<domain>`` TXT, ``v=BIMI1``)
* MX presence (MTA-STS/TLS-RPT only make sense with inbound mail)
* An explicable spoofing score (0-100) built from SPF/DMARC policy
  strength, DKIM evidence and MTA-STS/TLS-RPT hardening, with the
  per-component deductions surfaced in ``score_breakdown`` and human
  readable ``recommendations``.

All lookups go through :class:`~modules.dns.dns_scanner.DNSResolver`
(injectable for offline tests); every check degrades independently — a
failing lookup is just "not found", never an exception to the caller.

Contract consumed by modules/dns/dns_scanner.py (mode "full"):
    EmailSecurityAuditor().audit(domain, spf=..., dmarc=...) -> dict with
    keys "domain", "spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi",
    "mx", "spoofing_score", "risk", "score_breakdown", "recommendations".
"""

import re
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:  # runtime import would be circular (dns_scanner ↔ here)
    from modules.dns.dns_scanner import DNSResolver

#: Widely used DKIM selector names (Google Workspace, Microsoft 365,
#: Zoho, Mandrill, ProtonMail, common cPanel/Plesk defaults...).
DKIM_SELECTORS: List[str] = [
    "default",
    "google",
    "google2",
    "selector1",
    "selector2",
    "selector3",
    "s1",
    "s2",
    "k1",
    "dkim",
    "mail",
    "smtp",
    "zoho",
    "mandrill",
    "protonmail",
    "protonmail2",
    "everlytickey1",
    "everlytickey2",
]

BIMI_SELECTORS: List[str] = ["default", "selector1", "selector2"]

_SPF_MECHANISM_RE = re.compile(r"[~+\-?]all\b")

#: ``p=`` with an empty value (up to the next ``;`` or end of record):
#: a revoked DKIM key per RFC 6376 §3.6.1.1, never evidence of signing.
_EMPTY_P_RE = re.compile(r"(?<![\w.-])p=\s*(?:;|$)", re.IGNORECASE)


def _txt_text(answers: List[str]) -> str:
    """Join TXT fragments into one record string (robust to quoting)."""
    joined = " ".join(str(a).strip().strip('"') for a in answers)
    return joined.replace('" "', "").strip()


def _tag_value(record: str, tag: str) -> Optional[str]:
    """Extract ``tag=value`` from a DNS record (case-insensitive)."""
    match = re.search(
        rf"(?<![\w.-]){re.escape(tag)}=([^\s;]+)", record, re.IGNORECASE
    )
    return match.group(1) if match else None


class EmailSecurityAuditor:
    """Audit a domain's anti-spoofing posture with an explicable score."""

    def __init__(self, resolver: Optional["DNSResolver"] = None, timeout: int = 5):
        if resolver is None:
            # Lazy import: dns_scanner imports this module, so a top-level
            # import of DNSResolver would be circular.
            from modules.dns.dns_scanner import DNSResolver

            resolver = DNSResolver(timeout=timeout)
        self.resolver = resolver

    def _lookup(self, name: str, rtype: str) -> List[str]:
        """DNS lookup that degrades to 'not found' on any failure."""
        try:
            return self.resolver.resolve(name, rtype) or []
        except Exception:
            return []

    # ── individual checks ────────────────────────────────────────────────
    def check_dkim(self, domain: str) -> Dict[str, object]:
        """Probe common DKIM selectors; evidence only (we cannot validate)."""
        found = []
        revoked = []
        for selector in DKIM_SELECTORS:
            name = f"{selector}._domainkey.{domain}"
            record = _txt_text(self._lookup(name, "TXT"))
            # A DKIM key record carries a p= (key) or v=DKIM1 tag; bare
            # garbage TXT must not count as evidence.
            lowered = record.lower()
            if not record or ("p=" not in lowered and "v=dkim1" not in lowered):
                continue
            key = _tag_value(record, "p")
            if key is not None and key.strip():
                found.append({"selector": selector, "record": record})
                continue
            if key is not None or _EMPTY_P_RE.search(record):
                # p= empty (after strip) is a REVOKED key (RFC 6376
                # §3.6.1.1), not proof of signing.
                reason = "revoked"
            else:
                # v=DKIM1 without p= is malformed (p= is REQUIRED).
                reason = "malformed"
            revoked.append(
                {"selector": selector, "record": record, "reason": reason}
            )
        return {
            "selectors_probed": len(DKIM_SELECTORS),
            "found": found,
            "revoked": revoked,
            "present": bool(found),
        }

    def check_mta_sts(self, domain: str) -> Dict[str, object]:
        """MTA-STS discovery record at ``_mta-sts.<domain>``."""
        record = _txt_text(self._lookup(f"_mta-sts.{domain}", "TXT"))
        present = record.lower().startswith("v=stsv1")
        return {
            "present": present,
            "id": _tag_value(record, "id") if present else None,
            "record": record if present else None,
        }

    def check_tls_rpt(self, domain: str) -> Dict[str, object]:
        """TLS-RPT reporting record at ``_smtp._tls.<domain>``."""
        record = _txt_text(self._lookup(f"_smtp._tls.{domain}", "TXT"))
        present = record.lower().startswith("v=tlsrptv1")
        rua = []
        if present:
            raw = _tag_value(record, "rua")
            if raw:
                rua = [r for r in raw.split(",") if r]
        return {
            "present": present,
            "rua": rua,
            "record": record if present else None,
        }

    def check_bimi(self, domain: str) -> Dict[str, object]:
        """BIMI record (brand indicators) at ``<selector>._bimi.<domain>``."""
        for selector in BIMI_SELECTORS:
            record = _txt_text(self._lookup(f"{selector}._bimi.{domain}", "TXT"))
            if record.lower().startswith("v=bimi1"):
                return {"present": True, "selector": selector, "record": record}
        return {"present": False, "selector": None, "record": None}

    def check_mx(self, domain: str) -> Dict[str, object]:
        """MX presence: inbound mail exists (guards MTA-STS relevance)."""
        answers = self._lookup(domain, "MX")
        return {"present": bool(answers), "count": len(answers)}

    # ── score ────────────────────────────────────────────────────────────
    @staticmethod
    def _spf_deduction(spf: Dict[str, object]) -> int:
        if not spf.get("exists"):
            return 40
        policy = spf.get("policy")
        if policy == "pass-all":
            return 30  # +all: anyone may send as the domain
        if policy is None:  # exists but no all-mechanism matched (redirect=…)
            return 15
        if policy == "softfail":
            return 10
        return 0  # hardfail (-all)

    @staticmethod
    def _dmarc_deduction(dmarc: Dict[str, object]) -> int:
        if not dmarc.get("exists"):
            return 40
        policy = dmarc.get("policy")
        if policy == "none":
            return 20  # reports only, spoofing still delivered
        if policy == "quarantine":
            return 10
        return 0  # p=reject

    # ── orchestration ────────────────────────────────────────────────────
    def audit(
        self,
        domain: str,
        spf: Optional[Dict[str, object]] = None,
        dmarc: Optional[Dict[str, object]] = None,
    ) -> Dict[str, object]:
        """Full audit; ``spf``/``dmarc`` may be precomputed by the caller."""
        spf = spf if spf is not None else self.resolver.check_spf(domain)
        dmarc = dmarc if dmarc is not None else self.resolver.check_dmarc(domain)

        dkim = self.check_dkim(domain)
        mta_sts = self.check_mta_sts(domain)
        tls_rpt = self.check_tls_rpt(domain)
        bimi = self.check_bimi(domain)
        mx = self.check_mx(domain)

        breakdown: Dict[str, int] = {
            "spf": -self._spf_deduction(spf),
            "dmarc": -self._dmarc_deduction(dmarc),
            "dkim": 0 if dkim.get("present") else -15,
            # MTA-STS/TLS-RPT only protect inbound mail: without MX they
            # are not deductions, just "n/a" recommendations.
            "mta_sts": (-5 if not mta_sts.get("present") else 0)
            if mx.get("present")
            else 0,
            "tls_rpt": (-5 if not tls_rpt.get("present") else 0)
            if mx.get("present")
            else 0,
        }
        score = max(0, min(100, 100 + sum(breakdown.values())))
        if score >= 80:
            risk = "low"
        elif score >= 50:
            risk = "medium"
        elif score >= 20:
            risk = "high"
        else:
            risk = "critical"

        recommendations: List[str] = []
        if not spf.get("exists"):
            recommendations.append(
                "Publish an SPF record (v=spf1) listing the hosts allowed to send as this domain."
            )
        elif spf.get("policy") in ("pass-all", None, "softfail"):
            recommendations.append(
                "Tighten SPF: end the record with -all instead of a permissive mechanism."
            )
        if not dmarc.get("exists"):
            recommendations.append(
                "Publish a DMARC record (v=DMARC1) with rua reporting and enforce p=quarantine/reject."
            )
        elif dmarc.get("policy") == "none":
            recommendations.append(
                "DMARC p=none only observes: move to p=quarantine or p=reject to block spoofing."
            )
        if not dkim.get("present"):
            recommendations.append(
                "No DKIM key found on common selectors: sign outbound mail and publish selector keys."
            )
        if dkim.get("revoked") and not dkim.get("found"):
            recommendations.append(
                "DKIM selectors only publish empty p= keys (revoked/malformed, RFC 6376): republish a valid selector key."
            )
        if mx.get("present"):
            if not mta_sts.get("present"):
                recommendations.append(
                    "Publish an MTA-STS record (_mta-sts) to enforce STARTTLS for inbound mail."
                )
            if not tls_rpt.get("present"):
                recommendations.append(
                    "Publish a TLS-RPT record (_smtp._tls) to receive STARTTLS failure reports."
                )

        return {
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "mta_sts": mta_sts,
            "tls_rpt": tls_rpt,
            "bimi": bimi,
            "mx": mx,
            "spoofing_score": score,
            "risk": risk,
            "score_breakdown": breakdown,
            "recommendations": recommendations,
        }
