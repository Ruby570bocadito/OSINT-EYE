"""OSINT EYE - Secret and endpoint extraction from JavaScript files.

Regexes + Shannon entropy with a false-positive verification pass:
placeholder values (docs examples, ``${...}``, ``process.env.*``, "YOUR_
KEY"), comment-only lines and low-diversity strings are rejected before
they reach the findings list. Pure stdlib.

Findings are recon material for the operator (they are NOT verified
against the providers): every item carries type, confidence and the
line number where it was seen so the report stays auditable.

Degradation contract: ``scan()`` always returns the full result shape;
a dead base URL, a 4xx JS file or a hostile response degrades to error
entries instead of raising.

Contract consumed by osint_eye.py:
    JSSecretsScanner().scan(target) -> dict (see shape below).
"""

import math
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

from modules._http import HTTPClient
from modules._scope import allowed as _scope_allowed
from modules._scope import apply_scope as _apply_scope

#: Never fetch more than this many JS files per scan (bounded runtime).
MAX_FILES = 20

#: Never analyse more than this many bytes of a single JS file.
MAX_BYTES = 2_000_000

#: Shannon entropy (bits/char) above which a long token is reported.
ENTROPY_THRESHOLD = 4.0

#: Minimum token length for the entropy pass.
ENTROPY_MIN_LENGTH = 24

#: Maximum findings kept per file (bounded results).
MAX_FINDINGS_PER_FILE = 50

#: Maximum entropy tokens kept per file.
MAX_ENTROPY_PER_FILE = 10

#: Maximum endpoints kept per file.
MAX_ENDPOINTS_PER_FILE = 100

#: AWS documentation examples that must never be reported.
_KNOWN_EXAMPLE_VALUES = (
    "AKIAIOSFODNN7" + "EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)

#: Substrings that mark a value as a placeholder / template, not a secret.
_PLACEHOLDER_MARKERS = (
    "changeme",
    "change_me",
    "your_",
    "your-",
    "example",
    "sample",
    "dummy",
    "todo",
    "fixme",
    "placeholder",
    "insert_",
    "_here",
    "<",
    ">",
    "${",
    "{{",
    "%s",
    "%(",
    "process.env",
    "os.environ",
    "getenv",
    "undefined",
    "bower_components",
    "node_modules",
)

#: (type, regex, base confidence) — order defines priority on overlap.
PATTERNS = (
    (
        "aws_access_key",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "high",
    ),
    (
        "aws_secret_key",
        re.compile(
            r"(?i)aws.{0,25}?secret.{0,25}?[\"']([A-Za-z0-9/+=]{40})[\"']"
        ),
        "high",
    ),
    (
        "google_api_key",
        re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        "high",
    ),
    (
        "github_token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
        "high",
    ),
    (
        "slack_token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"),
        "high",
    ),
    (
        "private_key",
        re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
        "critical",
    ),
    (
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"
        ),
        "medium",
    ),
    (
        "bearer_token",
        re.compile(
            r"(?i)[\"']?(?:authorization|auth)[\"']?\s*[:=]\s*[\"']Bearer\s+"
            r"([A-Za-z0-9_\-\.=]{16,})[\"']"
        ),
        "high",
    ),
    (
        "firebase_api_key",
        re.compile(r"(?i)apiKey[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{30,})[\"']"),
        "high",
    ),
    (
        "password",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']([^\"'\s]{6,64})[\"']"
        ),
        "medium",
    ),
    (
        "generic_api_key",
        re.compile(
            r"(?i)\b(?:api[_-]?key|api[_-]?token|access[_-]?token|client[_-]?secret)"
            r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{16,})[\"']"
        ),
        "medium",
    ),
)

_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)

_ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")

_RELATIVE_ENDPOINT_RE = re.compile(
    r"[\"'](/(?:api|rest|v\d{1,2}/|graphql)[A-Za-z0-9_\-/.]{0,120})[\"']"
)

_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{%d,}" % ENTROPY_MIN_LENGTH)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character (0.0 for empty input)."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )


def _charset_diversity(value: str) -> int:
    """How many of [lower, upper, digit, punctuation] classes appear."""
    return sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )


def is_likely_placeholder(value: str) -> bool:
    """False-positive verification for a candidate secret value.

    Rejects documentation examples, template/env placeholders, very
    short values, single-character runs and low-diversity strings.
    """
    if not value or len(value) < 6:
        return True
    if value in _KNOWN_EXAMPLE_VALUES:
        return True
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if len(set(value)) <= 2:
        return True
    return False


def _diverse_enough(value: str) -> bool:
    """At least three character classes (generic keys / entropy tokens)."""
    return _charset_diversity(value) >= 3


class JSSecretsScanner:
    """Fetch JS assets of a target and extract secrets/endpoints."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = HTTPClient(timeout=timeout)

    # ── pure helpers (offline-testable) ─────────────────────────────────
    @staticmethod
    def fetch_js_urls(html: str, base_url: str) -> List[str]:
        """Resolve ``<script src>`` to absolute .js URLs, deduplicated."""
        urls: List[str] = []
        for src in _SCRIPT_SRC_RE.findall(html or ""):
            path_only = src.split("?", 1)[0].split("#", 1)[0]
            if not path_only.endswith(".js"):
                continue
            if src.startswith("//"):
                urls.append(f"https:{src}")
            elif src.startswith("http"):
                urls.append(src)
            else:
                urls.append(urljoin(base_url if base_url.endswith("/") else base_url + "/", src))
        return list(dict.fromkeys(urls))

    @staticmethod
    def _is_comment(line: str) -> bool:
        return line.startswith(("//", "/*", "*"))

    def analyze_js(self, source: str, url: str = "") -> Dict:
        """Extract findings from one JS source string (no network)."""
        secrets: List[Dict] = []
        high_entropy: List[Dict] = []
        endpoints: List[str] = []
        seen_values = set()

        for line_number, line in enumerate((source or "").splitlines(), 1):
            stripped = line.strip()
            if not stripped or self._is_comment(stripped):
                continue

            for ptype, regex, confidence in PATTERNS:
                for match in regex.finditer(line):
                    value = match.group(1) or match.group(0)
                    if not value or value in seen_values:
                        continue
                    if is_likely_placeholder(value):
                        continue
                    if ptype in ("generic_api_key",) and not _diverse_enough(value):
                        continue
                    seen_values.add(value)
                    if len(secrets) < MAX_FINDINGS_PER_FILE:
                        secrets.append(
                            {
                                "type": ptype,
                                "match": value[:80],
                                "confidence": confidence,
                                "line": line_number,
                                "file": url,
                            }
                        )

            for token in _LONG_TOKEN_RE.findall(line):
                if token in seen_values or is_likely_placeholder(token):
                    continue
                entropy = shannon_entropy(token)
                if entropy < ENTROPY_THRESHOLD or not _diverse_enough(token):
                    continue
                seen_values.add(token)
                if len(high_entropy) < MAX_ENTROPY_PER_FILE:
                    high_entropy.append(
                        {
                            "match": token[:80],
                            "entropy": round(entropy, 2),
                            "line": line_number,
                            "file": url,
                        }
                    )

            if len(endpoints) < MAX_ENDPOINTS_PER_FILE:
                for match in _ABSOLUTE_URL_RE.findall(line):
                    if len(endpoints) >= MAX_ENDPOINTS_PER_FILE:
                        break
                    endpoints.append(match.rstrip(".,;)"))
                for match in _RELATIVE_ENDPOINT_RE.findall(line):
                    if len(endpoints) >= MAX_ENDPOINTS_PER_FILE:
                        break
                    endpoints.append(match)

        return {
            "secrets": secrets,
            "high_entropy": high_entropy,
            "endpoints": list(dict.fromkeys(endpoints)),
        }

    # ── network orchestration ───────────────────────────────────────────
    def scan(self, base_url: str, scope=None) -> Dict:
        """Fetch the target page, then its JS files, and analyse them.

        ``scope`` is optional (``core.scope.Scope``): both the base page
        and every JS file URL are checked before being requested (module
        label "js_secrets"); out-of-scope files are never fetched.
        """
        results = {
            "target": base_url,
            "js_files_found": 0,
            "js_scanned": 0,
            "js_files": [],
            "secrets": [],
            "endpoints": [],
            "high_entropy": [],
            "errors": {},
        }

        if scope is not None and not _scope_allowed(scope, base_url, "js_secrets"):
            print(f"[!] {base_url} out of scope: skipping JS secrets scan")
            return results

        try:
            response = self.session.get(base_url, timeout=self.timeout)
            html = getattr(response, "text", "") or ""
        except Exception as e:
            results["errors"][base_url] = str(e)
            return results

        js_urls = self.fetch_js_urls(html, base_url)
        results["js_files_found"] = len(js_urls)
        js_urls = _apply_scope(scope, js_urls, "js_secrets")

        seen_secret_values = set()
        seen_endpoint_values = set()
        seen_entropy_values = set()

        for js_url in js_urls[:MAX_FILES]:
            try:
                response = self.session.get(js_url, timeout=self.timeout)
                status = getattr(response, "status_code", None)
                if status is not None and status >= 400:
                    results["errors"][js_url] = f"HTTP {status}"
                    continue
                source = getattr(response, "text", "") or ""
            except Exception as e:
                results["errors"][js_url] = str(e)
                continue

            results["js_scanned"] += 1
            results["js_files"].append(js_url)
            file_findings = self.analyze_js(source[:MAX_BYTES], js_url)

            for finding in file_findings["secrets"]:
                if finding["match"] in seen_secret_values:
                    continue
                seen_secret_values.add(finding["match"])
                results["secrets"].append(finding)
            for token in file_findings["high_entropy"]:
                if token["match"] in seen_entropy_values:
                    continue
                seen_entropy_values.add(token["match"])
                results["high_entropy"].append(token)
            for endpoint in file_findings["endpoints"]:
                if endpoint in seen_endpoint_values:
                    continue
                seen_endpoint_values.add(endpoint)
                results["endpoints"].append(endpoint)

        return results
