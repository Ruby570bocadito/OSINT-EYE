# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-23 (sesión v2.2, ronda 1 — cierre: 5/5 tareas)

## Hecho (últimas 24 h)

- [x] (IMP-3) results-schema — `core/schema.py` (SCHEMA_VERSION "2.0", TypedDicts, validate_results()
  + validadores por módulo, require_valid_results); `osint_eye.py` valida no-fatal en run_all/export_all.
- [x] (IMP-3) logging-real — `core/logging_config.py` (árbol `osint_eye.*`, idempotente); monitor,
  builder y los 5 exportadores de reporting sin print(); flags `--log-level`/`--log-file`.
- [x] (IMP-3) scope-file — `core/scope.py` (dominios, wildcards, IPs, CIDR v4/v6; excludes siempre
  ganan; hostiles nunca en scope; descartes auditados) + `--scope`/`--exclude` con gateo en targets
  CLI, permutación y takeover; resumen en `results["scope"]`.
- [x] (IMP-3) sarif-export — `reporting/sarif.py` (5 reglas OE001-OE005, niveles por severidad,
  partialFingerprints estables, tolerante a shapes corruptos); `export_all` emite `<base>.sarif`.
- [x] (IMP-3) exit-codes-ci — `--fail-on low|medium|high` con exit codes 0/1/2/3 documentados en
  --help; `max_severity()` tolera shapes corruptos; e2e real por subprocess (scope vacío → exit 3).
- Suite al cierre: 451 tests offline en verde; pyflakes limpio en todo lo tocado.

## En curso

- (IMP-3) config-file — osint_eye.toml con perfiles/timeouts/módulos/exportadores (última de v2.2).
- Petición IMP-2 asumida para esta ronda: ScanDiff.compare() no debe mutar self.diff entre llamadas;
  markdown_reporter: exponer el informe como texto sin escribir fichero; PUL-1: f-string pyflakes +
  imports lazy de reportlab.

## Bloqueado

- (nada)

## Peticiones a otras zonas

- IMP-1: al migrar colectores al cliente HTTP compartido, aplicar `Scope.allows()`/`filter_targets()`
  a las URLs derivadas dentro de cada módulo (dns brute-force de wordlist, endpoints, cloud) — la
  infraestructura está en `core/scope.py` con `tests/test_core_scope.py` de referencia.
- PUL-2: f-string sin placeholders preexistente en `reporting/markdown_reporter.py` (`f"\n### Attack Graph"`); cae en vuestra tarea ruff-config.

## Propuestas para el roadmap

- [ ] (IMP-3) findings-extract — extractor único de hallazgos (takeover, buckets públicos, secretos, CVE, ficheros sensibles) a una lista canónica con severidad y evidencia, reutilizable por SARIF/exit-codes/risk-scoring-v2 — core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,stix,csv,... con exportadores selectivos en lugar de exportar todo con --output — osint_eye.py, reporting/
