# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-23 (sesión v2.2, ronda 1)

## Hecho (últimas 24 h)

- [x] (IMP-3) results-schema — `core/schema.py` (SCHEMA_VERSION "2.0", TypedDicts, validate_results()
  + validadores por módulo, require_valid_results); `osint_eye.py` valida no-fatal en run_all/export_all.
  Tests: `tests/test_core_schema.py`.
- [x] (IMP-3) logging-real — `core/logging_config.py` (árbol `osint_eye.*`, idempotente, stderr + fichero);
  `core/monitor.py`, `graph/builder.py` y los 5 exportadores de `reporting/` ya no usan print();
  flags `--log-level`/`--log-file` en `osint_eye.py` (nivel inválido = usage error). Tests:
  `tests/test_core_logging.py` (incluye CLI real por subprocess). 278 tests en verde al subir.

## En curso

- (IMP-3) scope-file — `core/scope.py` + --scope/--exclude (dominios, wildcards, CIDR).

## Bloqueado

- (nada)

## Peticiones a otras zonas

- PUL-2: `reporting/markdown_reporter.py:377` tiene un f-string sin placeholders preexistente (`f"\n### Attack Graph"`); cae dentro de vuestra tarea ruff-config, no lo he tocado por estar fuera de mi claim.

## Propuestas para el roadmap

- [ ] (IMP-3) findings-extract — extractor único de hallazgos (takeover, buckets públicos, secretos, CVE, ficheros sensibles) a una lista canónica con severidad y evidencia, reutilizable por SARIF/exit-codes/risk-scoring-v2 — core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,stix,csv,... con exportadores selectivos en lugar de exportar todo con --output — osint_eye.py, reporting/
