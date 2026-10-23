"""OSINT EYE - HTTP security headers audit (canonical location).

Extended successor of the original ``SecurityHeadersAuditor`` (which
lived in modules/dns/advanced_dns.py and is re-exported from there for
backwards compatibility). Adds to the original missing-header report:

* **CORS analysis**: wildcard ``Access-Control-Allow-Origin: *`` and
  credential-revealing combinations are reported with severity.
* **Cookie analysis**: ``Set-Cookie`` flags audited per attribute
  (missing ``Secure``, ``HttpOnly``, ``SameSite``).
* **Severities on every finding** and a single explicable ``score``:
  the original deductions are untouched; CORS/cookie findings only
  subtract further.

TLS verification is never bypassed (an invalid certificate is itself a
finding): the fetch goes through the shared :class:`HTTPClient` with
``verify=True`` and an SSL failure aborts the audit with score 0 / F.

Contract (superset of the original, consumed by osint_eye.py, the UI
and the old imports):
    SecurityHeadersAuditor().audit(url) -> dict with keys "url",
    "missing_headers", "misconfigured_headers", "information_disclosure",
    "cors_findings", "cookie_findings", "score", "grade",
    "all_headers" (and "error" on failures).
"""

import re
from typing import Dict, List, Optional

import requests

from modules._http import HTTPClient

_SEVERITY_DEDUCTION = {"HIGH": 15, "MEDIUM": 10, "LOW": 5}


class SecurityHeadersAuditor:
    """Audit HTTP security headers with severities and an explicable score."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.http = HTTPClient(timeout=timeout)

        self.required_headers = {
            "Strict-Transport-Security": {
                "severity": "HIGH",
                "description": "HSTS not enabled - vulnerable to downgrade attacks",
            },
            "Content-Security-Policy": {
                "severity": "MEDIUM",
                "description": "No CSP - vulnerable to XSS and injection attacks",
            },
            "X-Content-Type-Options": {
                "severity": "MEDIUM",
                "description": "Missing X-Content-Type-Options - MIME sniffing possible",
            },
            "X-Frame-Options": {
                "severity": "MEDIUM",
                "description": "Missing X-Frame-Options - vulnerable to clickjacking",
            },
            "X-XSS-Protection": {
                "severity": "LOW",
                "description": "Missing X-XSS-Protection header",
            },
            "Referrer-Policy": {
                "severity": "LOW",
                "description": "Missing Referrer-Policy - may leak sensitive URLs",
            },
            "Permissions-Policy": {
                "severity": "LOW",
                "description": "Missing Permissions-Policy - browser features unrestricted",
            },
        }

        self.dangerous_headers = {
            "Server": "Reveals server software",
            "X-Powered-By": "Reveals technology stack",
            "X-AspNet-Version": "Reveals ASP.NET version",
            "X-AspNetMvc-Version": "Reveals ASP.NET MVC version",
        }

    @staticmethod
    def _parse_max_age(hsts_value: str) -> Optional[int]:
        """Extract max-age from an HSTS header value (None if malformed)."""
        m = re.search(r"max-age\s*=\s*(\d+)", hsts_value, re.IGNORECASE)
        return int(m.group(1)) if m else None

    # ── new checks ───────────────────────────────────────────────────────
    @staticmethod
    def _audit_cors(headers: Dict[str, str]) -> List[Dict[str, str]]:
        """CORS findings: wildcard origins and credential leakage."""
        findings: List[Dict[str, str]] = []
        acao = headers.get("Access-Control-Allow-Origin")
        acac = (headers.get("Access-Control-Allow-Credentials") or "").lower()
        if not acao:
            return findings
        if acao.strip() == "*":
            severity = "HIGH" if acac == "true" else "MEDIUM"
            desc = (
                "CORS allows any origin with credentials: any site can read "
                "authenticated responses"
                if acac == "true"
                else "CORS allows any origin to read responses (no credentials)"
            )
            findings.append(
                {
                    "header": "Access-Control-Allow-Origin",
                    "value": acao[:100],
                    "severity": severity,
                    "description": desc,
                }
            )
        elif acac == "true":
            findings.append(
                {
                    "header": "Access-Control-Allow-Credentials",
                    "value": "true",
                    "severity": "MEDIUM",
                    "description": (
                        "Credentials allowed with a specific origin: verify the "
                        "origin is not attacker-controlled"
                    ),
                }
            )
        return findings

    @staticmethod
    def _audit_cookies(headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Cookie findings: missing Secure/HttpOnly/SameSite flags."""
        findings: List[Dict[str, str]] = []
        raw_cookies: List[str] = []
        set_cookie = headers.get("Set-Cookie")
        if set_cookie:
            raw_cookies.append(set_cookie)
        return SecurityHeadersAuditor._cookie_findings(raw_cookies)

    @staticmethod
    def _cookie_findings(raw_cookies: List[str]) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        for cookie in raw_cookies:
            name = cookie.split("=", 1)[0].strip() or "(cookie)"
            lowered = cookie.lower()
            if "secure" not in lowered:
                findings.append(
                    {
                        "header": "Set-Cookie",
                        "cookie": name,
                        "flag": "Secure",
                        "severity": "MEDIUM",
                        "description": f"Cookie '{name}' without Secure: sent over plain HTTP",
                    }
                )
            if "httponly" not in lowered:
                findings.append(
                    {
                        "header": "Set-Cookie",
                        "cookie": name,
                        "flag": "HttpOnly",
                        "severity": "MEDIUM",
                        "description": f"Cookie '{name}' without HttpOnly: readable by JS (XSS theft)",
                    }
                )
            if "samesite" not in lowered:
                findings.append(
                    {
                        "header": "Set-Cookie",
                        "cookie": name,
                        "flag": "SameSite",
                        "severity": "LOW",
                        "description": f"Cookie '{name}' without SameSite: CSRF protection weakened",
                    }
                )
        return findings

    # ── orchestration ────────────────────────────────────────────────────
    def audit(self, url: str) -> Dict:
        """Audit security headers of a URL (never raises)."""
        result = {
            "url": url,
            "missing_headers": [],
            "misconfigured_headers": [],
            "information_disclosure": [],
            "cors_findings": [],
            "cookie_findings": [],
            "score": 100,
            "grade": None,
        }

        try:
            try:
                resp = self.http.get(url, verify=True)
            except requests.exceptions.SSLError as e:
                # Never bypass TLS verification: an invalid certificate is
                # itself a security finding, not a reason to downgrade.
                result["error"] = f"TLS certificate verification failed: {e}"
                result["score"] = 0
                result["grade"] = "F"
                return result
            headers = dict(resp.headers)

            for header, info in self.required_headers.items():
                if header not in headers:
                    result["missing_headers"].append(
                        {
                            "header": header,
                            "severity": info["severity"],
                            "description": info["description"],
                        }
                    )
                    result["score"] -= _SEVERITY_DEDUCTION.get(info["severity"], 5)

            if "Strict-Transport-Security" in headers:
                hsts = headers["Strict-Transport-Security"]
                if "max-age" in hsts.lower():
                    max_age = self._parse_max_age(hsts)
                    if max_age is not None and max_age < 31536000:
                        result["misconfigured_headers"].append(
                            {
                                "header": "Strict-Transport-Security",
                                "issue": f"max-age too low: {max_age}s (recommended: 31536000s)",
                                "severity": "MEDIUM",
                            }
                        )
                        result["score"] -= 10

                if "includeSubDomains" not in hsts:
                    result["misconfigured_headers"].append(
                        {
                            "header": "Strict-Transport-Security",
                            "issue": "Missing includeSubDomains directive",
                            "severity": "LOW",
                        }
                    )
                    result["score"] -= 5

            for header, desc in self.dangerous_headers.items():
                if header in headers:
                    result["information_disclosure"].append(
                        {
                            "header": header,
                            "value": headers[header][:100],
                            "description": desc,
                            "severity": "LOW",
                        }
                    )
                    result["score"] -= 3

            result["cors_findings"] = self._audit_cors(headers)
            for finding in result["cors_findings"]:
                if finding["severity"] == "HIGH":
                    result["score"] -= 15
                else:
                    result["score"] -= 10

            result["cookie_findings"] = self._audit_cookies(headers)
            for finding in result["cookie_findings"]:
                result["score"] -= (
                    5 if finding["severity"] == "MEDIUM" else 3
                )

            result["score"] = max(0, result["score"])

            if result["score"] >= 90:
                result["grade"] = "A"
            elif result["score"] >= 70:
                result["grade"] = "B"
            elif result["score"] >= 50:
                result["grade"] = "C"
            elif result["score"] >= 30:
                result["grade"] = "D"
            else:
                result["grade"] = "F"

            result["all_headers"] = {k: v[:100] for k, v in headers.items()}

        except Exception as e:
            result["error"] = str(e)

        return result
