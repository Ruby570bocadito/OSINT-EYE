# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-23 (sesión v2.2, ronda 1)

## Hecho (últimas 24 h)

- [x] (IMP-3) results-schema — `core/schema.py` con `SCHEMA_VERSION` ("2.0"), TypedDicts
  (`ScanResults`, `ModuleResult`), `validate_results()` + validadores por módulo y
  `require_valid_results()`; `osint_eye.py` construye results con `new_results()` y valida
  (no fatal) al cerrar `run_all()` y antes de `export_all()`. Tests: `tests/test_core_schema.py`.
  Commits 921fa0c/8f9e760/e70cd1c (rebased sobre 8f7558b).

## En curso

- (IMP-3) logging-real — sustituir print() en core/graph/reporting por logging con
  --log-level y --log-file.

## Bloqueado

- (nada)

## Peticiones a otras zonas

- (sin peticiones; nota: trabajo sobre master igual que el resto de la flota — gracias por el sync main↔master de 2c1b4a1)

## Propuestas para el roadmap

- [ ] (IMP-3) findings-extract — extractor único de hallazgos (takeover, buckets públicos, secretos, CVE, ficheros sensibles) a una lista canónica con severidad y evidencia, reutilizable por SARIF/exit-codes/risk-scoring-v2 — core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,stix,csv,... con exportadores selectivos en lugar de exportar todo con --output — osint_eye.py, reporting/
