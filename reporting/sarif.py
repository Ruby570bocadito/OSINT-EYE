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

from core.findings import extract_findings as extract_canonical_findings
from core.logging_config import get_logger

logger = get_logger(__name__)

SARIF_VERSION = "2.1.0"
SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "OSINT EYE"
INFORMATION_URI = "https://github.com/Ruby570bocadito/OSINT-EYE"

#: Control characters are illegal in SARIF message strings and ugly in URIs.
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")

#: Rule catalogue: id → (name, default SARIF level, short description).
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
        "level": "error",
        "short": "Known CVE affecting a discovered service",
    },
    "OE005": {
        "name": "SensitiveFileExposed",
        "level": "warning",
        "short": "Sensitive file reachable on a public endpoint",
    },
    "OE006": {
        "name": "ExposedLoginPage",
        "level": "note",
        "short": "Login page indexed by search engines",
    },
    "OE007": {
        "name": "ExposedAdminPanel",
        "level": "warning",
        "short": "Admin panel indexed by search engines",
    },
}

#: Canonical finding rules (core/findings.py) → SARIF rule ids.
CANONICAL_TO_OE = {
    "subdomain_takeover": "OE001",
    "public_cloud_bucket": "OE002",
    "github_secret_leak": "OE003",
    "vulnerable_service_cve": "OE004",
    "sensitive_file": "OE005",
    "exposed_login_page": "OE006",
    "exposed_admin_panel": "OE007",
}

#: Canonical severity → SARIF level.
SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
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


def extract_findings(results: Dict) -> List[Dict]:
    """Project the canonical findings (core/findings.py) into SARIF dicts.

    Each entry: ``{rule_id, message, uri, level, evidence, source_module}``.
    Malformed module shapes are already handled by the canonical layer.
    """
    sarif_findings = []
    for finding in extract_canonical_findings(results):
        rule_id = CANONICAL_TO_OE.get(finding.rule)
        if rule_id is None:
            continue  # canonical rule without SARIF mapping yet
        sarif_findings.append(
            {
                "rule_id": rule_id,
                "message": _clean(finding.title),
                "uri": _clean(finding.uri),
                "level": SEVERITY_TO_SARIF.get(
                    finding.severity, RULES[rule_id]["level"]
                ),
                "evidence": _clean(finding.evidence),
                "source_module": finding.source_module,
            }
        )
    return sarif_findings


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
            "properties": {
                "evidence": f["evidence"],
                "sourceModule": f["source_module"],
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
