"""Synthetic, offline benchmark cases for OSINT EYE core.

Every case builds its own data in ``setup()`` and exposes ``run(ctx, i)``
which performs one unit of representative work. All inputs are generated
locally: no network, no API keys, no scan dumps. The runner in
``bench_runner.py`` measures each case and compares it against the
generous floors in ``floors.json`` so gross performance regressions are
caught before they reach users.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.config import Config
from core.correlator import AssetCorrelator
from core.findings import extract_findings, findings_summary, sort_findings
from core.schema import new_results, validate_results
from core.scope import Scope
from core.session_cache import ScanCache

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic data builders (deterministic, offline)
# ─────────────────────────────────────────────────────────────────────────────
N_HOSTS = 50
INCLUDE_DOMAINS = [f"dom{i}.example.test" for i in range(40)]
INCLUDE_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "2001:db8::/32",
    "fd00::/8",
]
EXCLUDES = [
    "excluded.example.test",
    "*.quarantine.example.test",
    "10.9.9.9",
    "203.0.113.77/32",
]

_SCOPE_TARGETS: list[str] = []
for _i in range(150):
    _SCOPE_TARGETS.append(f"host{_i}.dom{_i % 40}.example.test")
    _SCOPE_TARGETS.append(f"10.{_i % 250}.{_i}.55")
    _SCOPE_TARGETS.append(f"https://sub{_i}.dom{_i % 40}.example.test/path?x={_i}")
    _SCOPE_TARGETS.append(f"2001:db8::{_i:x}")
_SCOPE_TARGETS.extend(
    [
        "excluded.example.test",
        "10.9.9.9",
        "203.0.113.77",
        "deep.sub.quarantine.example.test",
        "no es un target!!",
        "1999.example.test",
    ]
)


def _dns_section(host_index: int) -> dict[str, Any]:
    host = f"dom{host_index}.example.test"
    return {
        "domain": host,
        "subdomains": [f"s{j}.dom{host_index}.example.test" for j in range(5)],
        "records": {
            "A": [f"10.{host_index}.0.{j + 1}" for j in range(3)],
            "MX": [f"mail{j}.dom{host_index}.example.test" for j in range(2)],
            "NS": [f"ns{j}.dom{host_index}.example.test" for j in range(2)],
            "TXT": ["v=spf1 include:_spf.example.test -all"],
        },
    }


def _certs_section(host_index: int) -> dict[str, Any]:
    return {
        "certificates": [
            {
                "hostname": f"dom{host_index}.example.test",
                "issuer": "Test CA",
                "sans": [f"s{j}.dom{host_index}.example.test" for j in range(3)],
            }
            for _ in range(2)
        ]
    }


def _web_section(host_index: int) -> dict[str, Any]:
    return {
        "domain": f"dom{host_index}.example.test",
        "technologies": [f"tech{j}" for j in range(4)],
        "endpoints": {
            "sensitive": [
                {"url": f"https://dom{host_index}.example.test/.env", "status": "200"}
            ]
        },
    }


def _ingest_all(correlator: AssetCorrelator) -> None:
    for i in range(N_HOSTS):
        correlator.ingest_dns(_dns_section(i))
        correlator.ingest_certs(_certs_section(i))
        correlator.ingest_web(_web_section(i))


def _big_results() -> dict[str, Any]:
    results = new_results("bench.example.test", depth="deep")
    modules: dict[str, Any] = results["modules"]
    modules["takeover"] = {
        "vulnerable": [
            {"subdomain": f"take{i}.bench.example.test", "service": "s3"}
            for i in range(200)
        ]
    }
    modules["cloud_buckets"] = {
        "public": [
            {"url": f"https://bucket{i}.s3.amazonaws.com/", "provider": "aws"}
            for i in range(200)
        ]
    }
    modules["github"] = {
        "findings": [
            {"file": f"repo{i}/config.py", "snippet": "API_KEY=..."} for i in range(200)
        ]
    }
    modules["cve"] = {
        "cves": [
            {
                "id": f"CVE-2024-{i:05d}",
                "severity": [{"score": "7.5"}],
                "description": f"Synthetic vulnerability number {i}",
            }
            for i in range(300)
        ]
    }
    modules["endpoints"] = {
        "sensitive": [
            {"url": f"https://bench.example.test/backup{i}.sql", "status": "403"}
            for i in range(200)
        ]
    }
    modules["google"] = {
        "admin_panels": [
            {"url": f"https://bench.example.test/admin{i}"} for i in range(200)
        ],
        "login_pages": [
            {"url": f"https://bench.example.test/login{i}"} for i in range(200)
        ],
    }
    return results


CONFIG_TOML = """
[scan]
depth = "normal"
stealth = false
no_ai = true
modules = ["dns", "certs", "web"]

[timeouts]
monitor_interval = 3600

[scope]
includes = ["dom0.example.test", "dom1.example.test"]
excludes = ["10.0.0.0/8"]

[exports]
formats = ["json", "sarif"]

[profiles.deep]
[profiles.deep.scan]
depth = "full"
modules = ["dns", "certs", "web", "cve"]
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# Case definitions
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class BenchCase:
    name: str
    setup: Callable[[], Any]
    run: Callable[[Any, int], Any]
    iters: int
    description: str


def _setup_scope_allows() -> Any:
    scope = Scope(includes=INCLUDE_DOMAINS + INCLUDE_CIDRS, excludes=EXCLUDES)
    return scope, _SCOPE_TARGETS


def _run_scope_allows(ctx: Any, i: int) -> bool:
    scope, targets = ctx
    return scope.allows(targets[i % len(targets)])


def _setup_scope_filter() -> Any:
    scope = Scope(includes=INCLUDE_DOMAINS + INCLUDE_CIDRS, excludes=EXCLUDES)
    return scope, _SCOPE_TARGETS


def _run_scope_filter(ctx: Any, i: int) -> int:
    del i
    scope, targets = ctx
    return len(scope.filter_targets(targets, module="bench"))


def _setup_correlator_ingest() -> Any:
    return [
        (i, _dns_section(i), _certs_section(i), _web_section(i))
        for i in range(N_HOSTS)
    ]


def _run_correlator_ingest(ctx: Any, i: int) -> int:
    del i
    correlator = AssetCorrelator()
    for _host_index, dns_data, certs_data, web_data in ctx:
        correlator.ingest_dns(dns_data)
        correlator.ingest_certs(certs_data)
        correlator.ingest_web(web_data)
    return len(correlator.assets["subdomains"])


def _setup_correlator_queries() -> Any:
    correlator = AssetCorrelator()
    _ingest_all(correlator)
    return correlator


def _run_correlator_queries(ctx: Any, i: int) -> int:
    del i  # the queries are context-only; the iteration index is irrelevant
    shared = ctx.find_shared_infrastructure()
    hidden = ctx.find_hidden_relationships()
    surface = ctx.calculate_attack_surface_score()
    graph = ctx.generate_attack_graph()
    report = ctx.export_report()
    return len(shared) + len(hidden) + len(surface) + len(graph) + len(report)


def _setup_findings() -> Any:
    return _big_results()


def _run_findings(ctx: Any, i: int) -> int:
    del i
    findings = extract_findings(ctx)
    ordered = sort_findings(findings)
    summary = findings_summary(ordered)
    return len(ordered) + len(summary)


def _setup_schema_validate() -> Any:
    errors = validate_results(_big_results())
    if errors:
        raise RuntimeError(f"los datos sintéticos deben validar limpio: {errors[:3]}")
    return _big_results()


def _run_schema_validate(ctx: Any, i: int) -> int:
    del i
    return len(validate_results(ctx))


def _setup_cache_roundtrip() -> Any:
    tmp = tempfile.TemporaryDirectory(prefix="osint-eye-bench-")
    cache = ScanCache(str(Path(tmp.name) / "bench_cache.sqlite3"))
    results = new_results("cache.example.test", depth="normal")
    return tmp, cache, results


def _run_cache_roundtrip(ctx: Any, i: int) -> int:
    tmp, cache, results = ctx
    del tmp
    target = f"t{i % 7}.cache.example.test"
    cache.save_scan(target, "bench", results, depth="normal")
    loaded = cache.get_last_scan(target)
    cache.add_subdomain(target, f"s{i}.cache.example.test", source="bench")
    known = cache.get_subdomains(target)
    return len(known) + (1 if loaded else 0)


def _setup_config_parse() -> Any:
    tmp = tempfile.TemporaryDirectory(prefix="osint-eye-bench-")
    path = Path(tmp.name) / "osint_eye.toml"
    path.write_text(CONFIG_TOML, encoding="utf-8")
    return tmp, str(path)


def _run_config_parse(ctx: Any, i: int) -> int:
    del i
    tmp, path = ctx
    del tmp
    cfg = Config.load(path)
    if cfg is None:
        raise RuntimeError("Config.load devolvió None con TOML válido")
    cfg.validate_modules(["dns", "certs", "web", "cve"])
    deep = cfg.apply_profile("deep")
    return len(cfg.modules or []) + len(deep.depth or "")


def build_cases() -> list[BenchCase]:
    """The full offline benchmark catalogue (order is also report order)."""
    return [
        BenchCase(
            name="scope_allows",
            setup=_setup_scope_allows,
            run=_run_scope_allows,
            iters=1200,
            description="Scope.allows() sobre targets mixtos (dominios, IPs, URLs, basura)",
        ),
        BenchCase(
            name="scope_filter_targets",
            setup=_setup_scope_filter,
            run=_run_scope_filter,
            iters=60,
            description="Scope.filter_targets() con descartes auditables",
        ),
        BenchCase(
            name="correlator_ingest",
            setup=_setup_correlator_ingest,
            run=_run_correlator_ingest,
            iters=3,
            description="AssetCorrelator: ingest de 50 hosts (DNS + certs + web) desde cero",
        ),
        BenchCase(
            name="correlator_queries",
            setup=_setup_correlator_queries,
            run=_run_correlator_queries,
            iters=8,
            description="AssetCorrelator: infraestructura compartida + surface score + grafo + informe",
        ),
        BenchCase(
            name="extract_findings",
            setup=_setup_findings,
            run=_run_findings,
            iters=8,
            description="extract_findings + sort + summary sobre resultados con ~1500 hallazgos",
        ),
        BenchCase(
            name="schema_validate",
            setup=_setup_schema_validate,
            run=_run_schema_validate,
            iters=20,
            description="validate_results sobre un results grande y válido",
        ),
        BenchCase(
            name="cache_roundtrip",
            setup=_setup_cache_roundtrip,
            run=_run_cache_roundtrip,
            iters=30,
            description="ScanCache en disco: save_scan + get_last_scan + subdominios (SQLite)",
        ),
        BenchCase(
            name="config_parse",
            setup=_setup_config_parse,
            run=_run_config_parse,
            iters=300,
            description="Config.load + validate_modules + apply_profile (TOML en disco)",
        ),
    ]
