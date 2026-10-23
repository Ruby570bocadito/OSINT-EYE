"""SARIF 2.1.0 export for OSINT EYE findings.

Produces a SARIF log that GitHub Code Scanning ingests directly
(``--output`` runs emit ``<base>.sarif`` alongside the other exports):

* one static rule per finding class (takeover, public buckets, GitHub
  secret leaks, CVEs, sensitive files);
* one result per finding, with the SARIF level (error/warning/note)
  derived from the finding's severity and the affected URL as artifact
  location;
* a stable ``partialFingerprints`` entry so repeated scans of the same
  target deduplicate instead of re-alerting.

Everything is tolerant to hand-loaded/corrupt shapes: malformed entries
are skipped, never crash the export, and an empty scan still produces a
structurally valid (zero-result) SARIF log.
"""

import hashlib
import json
import re
from datetime import datetime
from typing import Dict, List

from core.logging_config import get_logger

logger = get_logger(__name__)

SARIF_VERSION = "2.1.0"
SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "OSINT EYE"
INFORMATION_URI = "https://github.com/Ruby570bocadito/OSINT-EYE"

#: Control characters are illegal in SARIF message strings and ugly in URIs.
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")

#: Rule catalogue: id → (name, severity default, short description).
RULES: Dict[str, Dict[str, str]] = {
    "OE001": {
        "name": "SubdomainTakeover",
        "level": "error",
        "short": "Subdomain takeover vulnerability",
    },
    "OE002": {
        "name": "PublicCloudBucket",
        "level": "error",
        "short": "Cloud bucket readable without authentication",
    },
    "OE003": {
        "name": "GitHubSecretLeak",
        "level": "warning",
        "short": "Potential secret or config leaked on GitHub",
    },
    "OE004": {
        "name": "VulnerableServiceCVE",
        "level": "warning",
        "short": "Known CVE affecting a discovered service",
    },
    "OE005": {
        "name": "SensitiveFileExposed",
        "level": "warning",
        "short": "Sensitive file reachable on a public endpoint",
    },
}


def _d(value) -> Dict:
    return value if isinstance(value, dict) else {}


def _l(value) -> List:
    return value if isinstance(value, list) else []


def _clean(value) -> str:
    return _BAD_CHARS.sub("", str(value or "")).strip()


def _tool_version() -> str:
    """Best-effort tool version (pyproject package name when installed)."""
    try:
        from importlib.metadata import version

        return version("osint-eye")
    except Exception:
        return "unknown"


def _cve_severity(cve: Dict) -> Dict:
    """Normalise the many shapes a CVE 'severity' field can take."""
    sev = cve.get("severity")
    if isinstance(sev, list) and sev and isinstance(sev[0], dict):
        return sev[0]
    if isinstance(sev, dict):
        return sev
    return {}


def _cve_level(cve: Dict) -> str:
    """Map a CVE entry to a SARIF level; unknown/malformed → 'note'."""
    sev = _cve_severity(cve)
    severity = str(sev.get("severity", "") or "").upper()
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    if severity == "MEDIUM":
        return "warning"
    if severity in ("LOW", "INFO"):
        return "note"
    try:
        score = float(sev.get("score"))
    except (TypeError, ValueError):
        return "note"
    if score >= 7.0:
        return "error"
    if score >= 4.0:
        return "warning"
    return "note"


def _level_for(rule_id: str, finding: Dict) -> str:
    if rule_id == "OE004":
        return _cve_level(finding)
    return RULES[rule_id]["level"]


def extract_findings(results: Dict) -> List[Dict]:
    """Pull every SARIF-worthy finding out of a results dict.

    Returns a list of ``{rule_id, message, uri, level}`` dicts. Malformed
    entries (None, scalars, empty) are skipped.
    """
    results = _d(results)
    modules = _d(results.get("modules"))
    target = _clean(results.get("target")) or "unknown"
    findings: List[Dict] = []

    def _add(rule_id: str, message: str, uri: str, finding: Dict = None):
        uri = _clean(uri) or f"https://{target}"
        if not message:
            return
        findings.append(
            {
                "rule_id": rule_id,
                "message": _clean(message),
                "uri": uri,
                "level": _level_for(rule_id, finding or {}),
            }
        )

    # OE001 — subdomain takeover
    for item in _l(_d(modules.get("takeover")).get("vulnerable")):
        if isinstance(item, dict):
            sub = _clean(item.get("subdomain"))
            service = _clean(item.get("service"))
        else:
            sub, service = _clean(item), ""
        if sub:
            detail = f" (dangling fingerprint: {service})" if service else ""
            _add("OE001", f"Subdomain {sub} appears takeable{detail}", f"https://{sub}")

    # OE002 — public cloud buckets
    for item in _l(_d(modules.get("cloud_buckets")).get("public")):
        if isinstance(item, dict):
            url = _clean(item.get("url"))
            provider = _clean(item.get("provider"))
        else:
            url, provider = _clean(item), ""
        if url:
            detail = f" [{provider}]" if provider else ""
            _add(
                "OE002",
                f"Public cloud bucket readable without authentication{detail}: {url}",
                url,
            )

    # OE003 — GitHub secret leaks
    for item in _l(_d(modules.get("github")).get("findings")):
        if isinstance(item, dict):
            label = _clean(item.get("file") or item.get("match") or item.get("url"))
            snippet = _clean(item.get("snippet") or item.get("dork"))
        else:
            label, snippet = _clean(item), ""
        if label:
            detail = f" — {snippet}" if snippet else ""
            _add(
                "OE003",
                f"Potential secret/config leak on GitHub: {label}{detail}",
                label if label.startswith("http") else f"https://github.com/search?q={label}",
            )

    # OE004 — CVEs
    for item in _l(_d(modules.get("cve")).get("cves")):
        if not isinstance(item, dict):
            continue
        cve_id = _clean(item.get("id"))
        if not cve_id:
            continue
        sev = _cve_severity(item)
        score = _clean(sev.get("score")) or "n/a"
        description = _clean(item.get("description"))[:200]
        detail = f": {description}" if description else ""
        _add(
            "OE004",
            f"{cve_id} (score {score}) affects a discovered service{detail}",
            f"https://{target}",
            item,
        )

    # OE005 — sensitive files
    endpoints = _d(modules.get("endpoints"))
    sensitive = _l(endpoints.get("sensitive")) or _l(
        _d(_d(modules.get("web")).get("endpoints")).get("sensitive")
    )
    for item in sensitive:
        if isinstance(item, dict):
            url = _clean(item.get("url"))
            status = _clean(item.get("status"))
        else:
            url, status = _clean(item), ""
        if url:
            detail = f" (HTTP {status})" if status else ""
            _add("OE005", f"Sensitive file exposed{detail}: {url}", url)

    return findings


def _fingerprint(rule_id: str, uri: str, message: str) -> str:
    digest = hashlib.sha256(f"{rule_id}|{uri}|{message}".encode("utf-8")).hexdigest()
    return digest[:16]


def _build_log(results: Dict) -> Dict:
    findings = extract_findings(results)
    rules = [
        {
            "id": rule_id,
            "name": spec["name"],
            "shortDescription": {"text": spec["short"]},
            "defaultConfiguration": {"level": spec["level"]},
            "helpUri": INFORMATION_URI,
        }
        for rule_id, spec in RULES.items()
    ]
    sarif_results = [
        {
            "ruleId": f["rule_id"],
            "level": f["level"],
            "message": {"text": f["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["uri"]},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "partialFingerprints": {
                "osintEye/finding/v1": _fingerprint(
                    f["rule_id"], f["uri"], f["message"]
                )
            },
        }
        for f in findings
    ]
    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": _tool_version(),
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().replace(
                            microsecond=0
                        ).isoformat()
                        + "Z",
                    }
                ],
            }
        ],
    }


def _safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(value or ""))
    return safe.strip("._") or "unknown"


class SarifExporter:
    """Export OSINT EYE findings as a SARIF 2.1.0 log."""

    def export(self, results: Dict, filename: str = None) -> str:
        """Write the SARIF log; returns the path written."""
        results = _d(results)
        if not filename:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = (
                f"osint_eye_{_safe_name(results.get('target'))}_{stamp}.sarif"
            )

        log = _build_log(results)
        with open(filename, "w", encoding="utf-8") as handle:
            json.dump(log, handle, indent=2, ensure_ascii=False)

        logger.info(
            "SARIF report saved to: %s (%d findings)",
            filename,
            len(log["runs"][0]["results"]),
        )
        return filename
