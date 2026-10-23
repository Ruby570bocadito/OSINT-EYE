"""Canonical findings extraction for OSINT EYE.

Single source of truth for "what did this scan find". Every module result
shape (takeover, public buckets, GitHub leaks, CVEs, sensitive files,
login/admin panels) is projected onto one :class:`Finding` record with a
normalized severity, a stable fingerprint and the evidence that produced
it. Consumers (SARIF export, CI exit codes, risk scoring, dashboard) must
derive their views from this layer instead of re-parsing module dicts, so
a fix in one module shape automatically propagates everywhere.

Everything is tolerant to hand-loaded/corrupt JSON: malformed entries are
skipped, never raised, and an empty scan simply yields no findings.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

#: Canonical severity ladder (lowest → highest).
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}

#: Rule catalogue: rule id → default severity + human label.
RULE_CATALOG: dict[str, dict[str, str]] = {
    "subdomain_takeover": {
        "severity": "critical",
        "label": "Subdomain takeover",
    },
    "public_cloud_bucket": {
        "severity": "high",
        "label": "Public cloud bucket",
    },
    "github_secret_leak": {
        "severity": "medium",
        "label": "Secret/config leaked on GitHub",
    },
    "vulnerable_service_cve": {
        "severity": "high",
        "label": "Known CVE affecting a discovered service",
    },
    "sensitive_file": {
        "severity": "medium",
        "label": "Sensitive file exposed",
    },
    "exposed_admin_panel": {
        "severity": "medium",
        "label": "Admin panel indexed",
    },
    "exposed_login_page": {
        "severity": "low",
        "label": "Login page indexed",
    },
}

_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _d(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _clean(value: Any) -> str:
    return _BAD_CHARS.sub("", str(value or "")).strip()


@dataclass(frozen=True)
class Finding:
    """One actionable finding with the evidence that produced it."""

    rule: str
    severity: str
    title: str
    uri: str = ""
    evidence: str = ""
    source_module: str = ""
    fingerprint: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        # Fingerprint is derived, never part of identity comparisons: two
        # findings extracted twice must compare equal AND dedupe the same.
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", self.compute_fingerprint())

    def compute_fingerprint(self) -> str:
        basis = f"{self.rule}|{self.uri}|{self.title}".encode()
        return hashlib.sha256(basis).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "uri": self.uri,
            "evidence": self.evidence,
            "source_module": self.source_module,
            "fingerprint": self.fingerprint,
        }


def normalize_cve_severity(cve: dict[str, Any]) -> str:
    """Map a CVE entry's many severity shapes onto the canonical ladder.

    Accepts the NVD list shape, a flat dict, a bare score or nothing:
    named severities win; otherwise the CVSS score decides; unknown →
    ``low`` (never invents a scary rating without evidence).
    """
    sev = cve.get("severity")
    if isinstance(sev, list) and sev and isinstance(sev[0], dict):
        sev = sev[0]
    if not isinstance(sev, dict):
        sev = {}
    named = str(sev.get("severity", "") or "").upper()
    if named in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return named.lower()
    raw_score: Any = sev.get("score")
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        return "low"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _finding(
    rule: str,
    title: str,
    uri: str,
    evidence: str,
    module: str,
    severity: str | None = None,
) -> Finding | None:
    title = _clean(title)
    if not title:
        return None
    spec = RULE_CATALOG[rule]
    return Finding(
        rule=rule,
        severity=severity or spec["severity"],
        title=title,
        uri=_clean(uri),
        evidence=_clean(evidence)[:300],
        source_module=module,
    )


def extract_findings(results: dict[str, Any]) -> list[Finding]:
    """Project a results dict onto the canonical finding list."""
    results = _d(results)
    modules = _d(results.get("modules"))
    target = _clean(results.get("target")) or "unknown"
    findings: list[Finding] = []

    # Subdomain takeover (critical)
    for item in _l(_d(modules.get("takeover")).get("vulnerable")):
        if isinstance(item, dict):
            sub, service = _clean(item.get("subdomain")), _clean(item.get("service"))
        elif isinstance(item, str):
            sub, service = _clean(item), ""
        else:
            continue  # scalar junk (int/float/None) is never a subdomain
        if not sub:
            continue
        detail = f" (dangling fingerprint: {service})" if service else ""
        finding = _finding(
            "subdomain_takeover",
            f"Subdomain {sub} appears takeable{detail}",
            f"https://{sub}",
            f"takeover fingerprint: {service or 'unknown'}",
            "takeover",
        )
        if finding:
            findings.append(finding)

    # Public cloud buckets (high)
    for item in _l(_d(modules.get("cloud_buckets")).get("public")):
        if isinstance(item, dict):
            url, provider = _clean(item.get("url")), _clean(item.get("provider"))
        elif isinstance(item, str):
            url, provider = _clean(item), ""
        else:
            continue
        if not url:
            continue
        detail = f" [{provider}]" if provider else ""
        finding = _finding(
            "public_cloud_bucket",
            f"Public cloud bucket readable without authentication{detail}: {url}",
            url,
            f"provider={provider or 'unknown'}",
            "cloud_buckets",
        )
        if finding:
            findings.append(finding)

    # GitHub secret/config leaks (medium — potential, unverified)
    for item in _l(_d(modules.get("github")).get("findings")):
        if isinstance(item, dict):
            label = _clean(item.get("file") or item.get("match") or item.get("url"))
            snippet = _clean(item.get("snippet") or item.get("dork"))
        elif isinstance(item, str):
            label, snippet = _clean(item), ""
        else:
            continue
        if not label:
            continue
        detail = f" — {snippet}" if snippet else ""
        finding = _finding(
            "github_secret_leak",
            f"Potential secret/config leak on GitHub: {label}{detail}",
            label
            if label.startswith("http")
            else f"https://github.com/search?q={label}",
            snippet,
            "github",
        )
        if finding:
            findings.append(finding)

    # CVEs (severity per CVSS)
    for item in _l(_d(modules.get("cve")).get("cves")):
        if not isinstance(item, dict):
            continue
        cve_id = _clean(item.get("id"))
        if not cve_id:
            continue
        severity = normalize_cve_severity(item)
        sev = item.get("severity")
        if isinstance(sev, list) and sev and isinstance(sev[0], dict):
            sev = sev[0]
        score = _clean(sev.get("score")) if isinstance(sev, dict) else ""
        description = _clean(item.get("description"))[:200]
        detail = f": {description}" if description else ""
        finding = _finding(
            "vulnerable_service_cve",
            f"{cve_id} affects a discovered service{detail}",
            f"https://{target}",
            f"score={score or 'unknown'} severity={severity}",
            "cve",
            severity=severity,
        )
        if finding:
            findings.append(finding)

    # Sensitive files (medium) — orchestrator shape first, web fallback second
    endpoints = _d(modules.get("endpoints"))
    sensitive = _l(endpoints.get("sensitive")) or _l(
        _d(_d(modules.get("web")).get("endpoints")).get("sensitive")
    )
    for item in sensitive:
        if isinstance(item, dict):
            url, status = _clean(item.get("url")), _clean(item.get("status"))
        elif isinstance(item, str):
            url, status = _clean(item), ""
        else:
            continue
        if not url:
            continue
        detail = f" (HTTP {status})" if status else ""
        finding = _finding(
            "sensitive_file",
            f"Sensitive file exposed{detail}: {url}",
            url,
            f"http_status={status or 'unknown'}",
            "endpoints",
        )
        if finding:
            findings.append(finding)

    # Google dorks: admin panels (medium) and login pages (low)
    google = _d(modules.get("google"))
    for item in _l(google.get("admin_panels")):
        url = (
            _clean(item.get("url") if isinstance(item, dict) else item)
            if isinstance(item, (dict, str))
            else ""
        )
        if url:
            finding = _finding(
                "exposed_admin_panel",
                f"Admin panel indexed by search engines: {url}",
                url,
                "source=google dorking",
                "google",
            )
            if finding:
                findings.append(finding)
    for item in _l(google.get("login_pages")):
        url = (
            _clean(item.get("url") if isinstance(item, dict) else item)
            if isinstance(item, (dict, str))
            else ""
        )
        if url:
            finding = _finding(
                "exposed_login_page",
                f"Login page indexed by search engines: {url}",
                url,
                "source=google dorking",
                "google",
            )
            if finding:
                findings.append(finding)

    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest severity first; ties broken by URI for deterministic output."""
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.uri, f.rule),
    )


def findings_summary(findings: list[Finding]) -> dict[str, Any]:
    """Aggregate counts by severity and rule (JSON-safe)."""
    by_severity = {name: 0 for name in SEVERITY_ORDER}
    by_rule: dict[str, int] = {}
    for finding in findings:
        if finding.severity in by_severity:
            by_severity[finding.severity] += 1
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_rule": by_rule}


def worst_severity(findings: list[Finding]) -> str | None:
    """Highest severity present, or ``None`` with no findings."""
    if not findings:
        return None
    return max(
        (f.severity for f in findings),
        key=lambda s: SEVERITY_RANK.get(s, 0),
    )
