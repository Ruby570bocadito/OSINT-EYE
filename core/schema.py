"""Results contract (schema) for OSINT EYE.

Single source of truth for the ``results`` dict that the collectors
(``modules/``, IMP-1) produce and that core/reporting/ui (IMP-3/IMP-2)
consume. The contract is intentionally permissive:

* unknown top-level keys and unknown module names never fail validation
  (plugins and future collectors must not break older consumers);
* per-module validation only checks keys it knows about, and only when
  they are present (modules degrade gracefully and may return partial
  data or an error status);
* everything is JSON round-trip safe: a scan saved to disk and loaded
  again must still validate (with the same problems, never new ones).

Versioning: ``SCHEMA_VERSION`` is embedded in every scan as
``results["schema_version"]``. Consumers should read it and refuse (or
migrate) only on a different major version.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, TypedDict

SCHEMA_VERSION = "2.0"

VALID_DEPTHS = ("quick", "normal", "deep", "full")

#: Severities used across the tool (correlation score, findings, exports).
KNOWN_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class ResultsSchemaError(ValueError):
    """Raised by :func:`require_valid_results` on a contract violation."""


class ModuleResult(TypedDict, total=False):
    """Minimum shape every collector entry in ``results["modules"]`` keeps.

    Collectors are free to add module-specific keys; ``status``/``error``
    are the graceful-degradation channel (a module that could not run
    reports ``status: "unavailable"`` or ``"error"`` instead of raising).
    """

    status: str
    error: str
    domain: str
    target: str
    url: str
    host: str


class ScanResults(TypedDict, total=False):
    """Top-level scan contract (see ``osint_eye.OSINTEye.results``)."""

    schema_version: str
    target: str
    scan_date: str
    depth: str
    modules: Dict[str, Dict[str, Any]]
    errors: List[str]
    correlation: Dict[str, Any]
    graph: Dict[str, Any]
    mitre: Dict[str, Any]
    attack_chains: List[Dict[str, Any]]
    ai_analysis: Dict[str, Any]
    plugins: Dict[str, Any]
    agent_playbook: str
    scope: Dict[str, Any]


def new_results(target: str, depth: str = "normal") -> ScanResults:
    """Factory for a fresh, schema-versioned results dict.

    Keeps the exact key set the orchestrator has always produced plus
    ``schema_version``; extra sections are added by the scan itself.
    """
    from datetime import datetime

    return {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "depth": depth,
        "modules": {},
        "errors": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Small predicate helpers
# ─────────────────────────────────────────────────────────────────────────────
def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _is_dict_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, dict) for v in value)


def _str_or_none(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _int_or_none(value: Any) -> bool:
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


# ─────────────────────────────────────────────────────────────────────────────
# Per-module validators
#
# Each validator receives the module's entry (always a dict — validate_results
# guarantees that) and returns a list of human-readable problems. Only keys
# known to the contract are checked, and only when present.
# ─────────────────────────────────────────────────────────────────────────────
def _validate_dns(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "domain" in d and not isinstance(d["domain"], str):
        problems.append("dns.domain debe ser string")
    if "subdomains" in d and not _is_str_list(d["subdomains"]):
        problems.append("dns.subdomains debe ser lista de strings")
    if "records" in d and not isinstance(d["records"], dict):
        problems.append("dns.records debe ser dict")
    return problems


def _validate_certs(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "subdomains" in d and not _is_str_list(d["subdomains"]):
        problems.append("certs.subdomains debe ser lista de strings")
    if "certificates" in d and not _is_dict_list(d["certificates"]):
        problems.append("certs.certificates debe ser lista de dicts")
    return problems


def _validate_wayback(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "total_snapshots" in d and not _int_or_none(d["total_snapshots"]):
        problems.append("wayback.total_snapshots debe ser int o null")
    if "interesting_urls" in d and not isinstance(d["interesting_urls"], list):
        problems.append("wayback.interesting_urls debe ser lista")
    if "unique_paths" in d and not _is_str_list(d["unique_paths"]):
        problems.append("wayback.unique_paths debe ser lista de strings")
    return problems


def _validate_network(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "host" in d and not _str_or_none(d["host"]):
        problems.append("network.host debe ser string o null")
    if "services" in d and not _is_dict_list(d["services"]):
        problems.append("network.services debe ser lista de dicts")
    return problems


def _validate_whois(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "registrar" in d and not _str_or_none(d["registrar"]):
        problems.append("whois.registrar debe ser string o null")
    if "name_servers" in d and not isinstance(d["name_servers"], list):
        problems.append("whois.name_servers debe ser lista")
    if "emails" in d and not isinstance(d["emails"], list):
        problems.append("whois.emails debe ser lista")
    return problems


def _validate_web(d: Dict[str, Any]) -> List[str]:
    raw = d.get("technologies", None)
    if raw is not None and not isinstance(raw, (dict, list, set, tuple)):
        problems = ["web.technologies debe ser dict/list"]
    else:
        problems = []
    if "endpoints" in d and not isinstance(d["endpoints"], dict):
        problems.append("web.endpoints debe ser dict")
    return problems


def _validate_endpoints(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "found" in d and not isinstance(d["found"], list):
        problems.append("endpoints.found debe ser lista")
    if "sensitive" in d and not isinstance(d["sensitive"], list):
        problems.append("endpoints.sensitive debe ser lista")
    if "total_found" in d and not _int_or_none(d["total_found"]):
        problems.append("endpoints.total_found debe ser int o null")
    return problems


def _validate_cloud(d: Dict[str, Any]) -> List[str]:
    problems = []
    for key in ("found", "public"):
        if key in d and not isinstance(d[key], list):
            problems.append(f"cloud_buckets.{key} debe ser lista")
    return problems


def _validate_emails(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "emails_found" in d and not _is_str_list(d["emails_found"]):
        problems.append("emails.emails_found debe ser lista de strings")
    return problems


def _validate_github(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "findings" in d and not isinstance(d["findings"], list):
        problems.append("github.findings debe ser lista")
    if "total_findings" in d and not _int_or_none(d["total_findings"]):
        problems.append("github.total_findings debe ser int o null")
    return problems


def _validate_google(d: Dict[str, Any]) -> List[str]:
    problems = []
    for key in (
        "login_pages",
        "admin_panels",
        "sensitive_files",
        "config_files",
        "backup_files",
        "sql_errors",
        "subdomains",
    ):
        if key in d and not isinstance(d[key], list):
            problems.append(f"google.{key} debe ser lista")
    return problems


def _validate_cve(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "cves" in d and not _is_dict_list(d["cves"]):
        problems.append("cve.cves debe ser lista de dicts")
    return problems


def _validate_permutation(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "subdomains" in d and not _is_str_list(d["subdomains"]):
        problems.append("permutation.subdomains debe ser lista de strings")
    if "total_found" in d and not _int_or_none(d["total_found"]):
        problems.append("permutation.total_found debe ser int o null")
    if "domain" in d and not isinstance(d["domain"], str):
        problems.append("permutation.domain debe ser string")
    return problems


def _validate_takeover(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "checked" in d and not _int_or_none(d["checked"]):
        problems.append("takeover.checked debe ser int o null")
    if "vulnerable" in d and not isinstance(d["vulnerable"], list):
        problems.append("takeover.vulnerable debe ser lista")
    return problems


def _validate_cdn_waf(d: Dict[str, Any]) -> List[str]:
    problems = []
    for key in ("cdn", "waf"):
        if key in d and not _str_or_none(d[key]):
            problems.append(f"cdn_waf.{key} debe ser string o null")
    return problems


def _validate_correlation(d: Dict[str, Any]) -> List[str]:
    problems = []
    score = d.get("attack_surface_score")
    if score is not None:
        if not isinstance(score, dict):
            problems.append("correlation.attack_surface_score debe ser dict")
        else:
            if "score" in score and not _int_or_none(score["score"]):
                problems.append(
                    "correlation.attack_surface_score.score debe ser int o null"
                )
            severity = score.get("severity")
            if severity is not None and (
                not isinstance(severity, str) or severity not in KNOWN_SEVERITIES
            ):
                problems.append(
                    "correlation.attack_surface_score.severity no reconocida"
                )
    if "relationships" in d and not _is_dict_list(d["relationships"]):
        problems.append("correlation.relationships debe ser lista de dicts")
    return problems


def _validate_graph(d: Dict[str, Any]) -> List[str]:
    problems = []
    for key in ("nodes", "edges"):
        if key in d and not _is_dict_list(d[key]):
            problems.append(f"graph.{key} debe ser lista de dicts")
    return problems


def _validate_mitre(d: Dict[str, Any]) -> List[str]:
    problems = []
    if "findings" in d and not _is_dict_list(d["findings"]):
        problems.append("mitre.findings debe ser lista de dicts")
    return problems


#: Registry consulted by validate_results(); modules not listed here are
#: accepted without per-key checks (forward compatibility for plugins).
MODULE_VALIDATORS: Dict[str, Callable[[Dict[str, Any]], List[str]]] = {
    "dns": _validate_dns,
    "certs": _validate_certs,
    "wayback": _validate_wayback,
    "network": _validate_network,
    "whois": _validate_whois,
    "web": _validate_web,
    "endpoints": _validate_endpoints,
    "cloud_buckets": _validate_cloud,
    "emails": _validate_emails,
    "github": _validate_github,
    "google": _validate_google,
    "cve": _validate_cve,
    "permutation": _validate_permutation,
    "takeover": _validate_takeover,
    "cdn_waf": _validate_cdn_waf,
    "correlation": _validate_correlation,
    "graph": _validate_graph,
    "mitre": _validate_mitre,
}


# ─────────────────────────────────────────────────────────────────────────────
# Top-level validation
# ─────────────────────────────────────────────────────────────────────────────
def _check_section(
    results: Mapping[str, Any],
    key: str,
    expected: type,
    description: str,
    problems: List[str],
) -> None:
    if key in results and results[key] is not None and not isinstance(
        results[key], expected
    ):
        problems.append(f"{key} debe ser {description}")


def validate_results(results: Any) -> List[str]:
    """Validate a results dict against the contract.

    Returns a list of human-readable problems (empty when the dict is
    valid). Never raises for missing optional sections, never mutates the
    input, and accepts anything a hand-edited JSON file may contain.
    """
    if not isinstance(results, Mapping):
        return ["results debe ser un dict"]

    problems: List[str] = []

    target = results.get("target")
    if not isinstance(target, str) or not target.strip():
        problems.append("target debe ser un string no vacío")

    if "scan_date" in results and not isinstance(results["scan_date"], str):
        problems.append("scan_date debe ser string")

    depth = results.get("depth")
    if depth is not None and depth not in VALID_DEPTHS:
        problems.append(f"depth debe ser uno de {VALID_DEPTHS}")

    version = results.get("schema_version")
    if version is not None:
        if not isinstance(version, str):
            problems.append("schema_version debe ser string")
        elif version.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
            problems.append(
                f"schema_version {version} incompatible con {SCHEMA_VERSION} "
                "(major distinto)"
            )

    modules = results.get("modules")
    if modules is None or modules == {}:
        pass  # an empty module set is valid (scan interrupted before phase 1)
    elif not isinstance(modules, dict):
        problems.append("modules debe ser dict")
    else:
        for name, data in modules.items():
            if not isinstance(name, str):
                problems.append("las claves de modules deben ser strings")
                continue
            if not isinstance(data, dict):
                problems.append(f"modules[{name!r}] debe ser dict (no {type(data).__name__})")
                continue
            validator = MODULE_VALIDATORS.get(name)
            if validator is not None:
                for problem in validator(data):
                    problems.append(problem)

    errors = results.get("errors")
    if errors is not None and not _is_str_list(errors):
        if not isinstance(errors, list):
            problems.append("errors debe ser lista")
        else:
            problems.append("cada entrada de errors debe ser string")

    _check_section(results, "correlation", Mapping, "dict", problems)
    _check_section(results, "graph", Mapping, "dict", problems)
    _check_section(results, "mitre", Mapping, "dict", problems)
    _check_section(results, "ai_analysis", Mapping, "dict", problems)
    _check_section(results, "plugins", Mapping, "dict", problems)
    _check_section(results, "scope", Mapping, "dict", problems)
    _check_section(results, "attack_chains", list, "lista", problems)
    if "agent_playbook" in results and not isinstance(
        results["agent_playbook"], str
    ):
        problems.append("agent_playbook debe ser string")

    return problems


def require_valid_results(results: Any) -> None:
    """Raise :class:`ResultsSchemaError` when ``results`` breaks the contract."""
    problems = validate_results(results)
    if problems:
        raise ResultsSchemaError(
            "results viola el contrato del esquema:\n- " + "\n- ".join(problems)
        )
