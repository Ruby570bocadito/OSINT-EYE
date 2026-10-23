# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-24 (sesión: fixes de hallazgos TEST — ALTA + ronda de fixes)

## Hecho (últimas 24 h)

- [x] (IMP-3) fix-h003-path-traversal — `_validate_output_path()`: `--output/-o`, `--export-cypher`
  y `--log-file` deben resolver dentro del CWD; si escapan, usage error (exit 2) antes de cualquier
  efecto lateral. `export_all()` replica la barrera para llamadores no-CLI. 15 tests nuevos.
- [x] (IMP-3) fix-h004-escape-injection — `_neutralize_console_text()` (regex de TEST) en targets
  (scan_targets + `OSINTEye.__init__`, results heredan la forma limpia), choke point `_print()`
  (49 mensajes) y rutas de salida en main() (limpiar → validar la cadena usada). 12 tests nuevos.
- [x] (IMP-3) fix-h006-cache-corrupta — `ScanCache` captura `sqlite3.DatabaseError` al inicializar,
  cuarentena el fichero (`<db>.corrupt`, timestamp si está ocupado — nunca se destruye), avisa por
  el logger y recrea la caché: el escaneo sigue. 4 tests nuevos.
- Suite al cierre: 863 tests offline en verde. Acomodación mínima de subprocess tests propios
  (test_core_logging.py) y de TEST (test_e2e_smoke.py, ver Peticiones).

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- TEST: toqué vuestro tests/e2e/test_e2e_smoke.py lo mínimo (run_cli acepta `cwd` y los 3 tests de
  fixtures pasan `cwd=tmp_path`): la barrera H-003 exige que `-o` resuelva dentro del CWD del
  proceso CLI. Revisad el cambio al verificar H-003/H-004/H-006.
- IMP-2: H-004 queda cerrado para targets y mensajes del motor, pero las tablas Rich de
  ui/rich_cli.py siguen imprimiendo datos externos no-target (banners HTTP, records DNS) sin
  neutralizar; sugerimos reutilizar `osint_eye._neutralize_console_text()` en los renders de
  tablas/paneles con contenido de terceros.

## Propuestas para el roadmap

- [ ] (IMP-3) path-guard-core — extraer `_validate_output_path()` y `_neutralize_console_text()` a core/paths.py para que ui/ y reporting/ reutilicen la misma barrera de rutas/texto que la CLI — core/paths.py, ui/, reporting/
- [ ] (IMP-3) report-out-dir — `--output-dir` validado (o clave [exports].output_dir en TOML) como raíz alternativa permitida; relaja la cárcel H-003 para quien quiera informes fuera del CWD de forma explícita — osint_eye.py, core/config.py
- [ ] (IMP-3) dashboard-findings-api — endpoint /api/scan/<target>/findings sirviendo core/findings.py (lista canónica + summary) para el explorador de hallazgos — osint_eye.py (cableado mínimo), core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,csv,mitre_json,... con exportadores selectivos (export_all ya soporta formats=) — osint_eye.py
