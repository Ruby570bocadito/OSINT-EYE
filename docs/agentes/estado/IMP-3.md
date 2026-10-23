# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-23 (sesión v2.2, ronda 1)

## Hecho (últimas 24 h)

- [x] (IMP-3) results-schema — `core/schema.py` (SCHEMA_VERSION "2.0", TypedDicts, validate_results()
  + validadores por módulo, require_valid_results); `osint_eye.py` valida no-fatal en run_all/export_all.
- [x] (IMP-3) logging-real — `core/logging_config.py` (árbol `osint_eye.*`, idempotente); monitor,
  builder y los 5 exportadores de reporting sin print(); flags `--log-level`/`--log-file`.
- [x] (IMP-3) scope-file — `core/scope.py` (dominios, wildcards, IPs, CIDR v4/v6; excludes siempre
  ganan; targets hostiles nunca en scope; descartes auditados) + `--scope`/`--exclude` con gateo en
  CLI targets, candidatos de permutación y sondas de takeover; resumen vivo en `results["scope"]`.
  Conflicto del CHANGELOG con la consolidación de PUL-1 resuelto conservando ambas estructuras.
  356 tests en verde al subir.

## En curso

- (IMP-3) sarif-export — `reporting/sarif.py` (SARIF 2.1 para GitHub Code Scanning).

## Bloqueado

- (nada)

## Peticiones a otras zonas

- IMP-1: cuando migréis colectores al cliente HTTP compartido, aplicad `Scope.allows()`/`filter_targets()`
  a las URLs derivadas dentro de cada módulo (dns brute-force de wordlist, endpoints, cloud) — la infraestructura
  está en `core/scope.py` con `tests/test_core_scope.py` como referencia.
- PUL-2: `reporting/markdown_reporter.py` f-string sin placeholders preexistente (`f"\n### Attack Graph"`);
  cae dentro de vuestra tarea ruff-config.

## Propuestas para el roadmap

- [ ] (IMP-3) findings-extract — extractor único de hallazgos (takeover, buckets públicos, secretos, CVE, ficheros sensibles) a una lista canónica con severidad y evidencia, reutilizable por SARIF/exit-codes/risk-scoring-v2 — core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,stix,csv,... con exportadores selectivos en lugar de exportar todo con --output — osint_eye.py, reporting/
