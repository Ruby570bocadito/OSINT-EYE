# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-24 (sesión: fixes de hallazgos TEST — ALTA)

## Hecho (últimas 24 h)

- [x] (IMP-3) fix-h003-path-traversal — `_validate_output_path()` en osint_eye.py: `--output/-o`,
  `--export-cypher` y `--log-file` deben resolver dentro del CWD; si escapan, usage error limpio
  (exit 2) ANTES de crear el log o escanear. `export_all()` aplica la misma barrera a llamadores
  no-CLI; `--help` documenta la restricción. 15 tests nuevos en tests/test_output_path_validation.py.
- [x] (IMP-3) fix-h004-escape-injection — `_neutralize_console_text()` (regex de TEST) en los puntos
  de entrada y render: targets en `scan_targets()` y `OSINTEye.__init__` (results heredan la forma
  limpia), choke point `_print()` (49 mensajes del motor) y rutas de salida en main() (limpiar,
  después validar). ESC/OSC ya no llegan al terminal; sin efectos de título ni salida falsa.
  12 tests nuevos en tests/test_console_neutralization.py.
- Suite al cierre: 827 tests offline en verde. Acomodación mínima de tests de subprocess
  (tests/test_core_logging.py propio; tests/e2e/test_e2e_smoke.py de TEST, ver Peticiones).

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- TEST: toqué vuestro tests/e2e/test_e2e_smoke.py lo mínimo (run_cli acepta `cwd` y los 3 tests de
  fixtures pasan `cwd=tmp_path`): la barrera H-003 exige que `-o` resuelva dentro del CWD del
  proceso CLI. Revisad el cambio al verificar H-003/H-004.
- IMP-2: H-004 queda cerrado para targets y mensajes del motor, pero las tablas Rich de
  ui/rich_cli.py siguen imprimiendo datos externos no-target (banners HTTP, records DNS) sin
  neutralizar; sugerimos reutilizar `osint_eye._neutralize_console_text()` en los renders de
  tablas/paneles con contenido de terceros.

## Propuestas para el roadmap

- [ ] (IMP-3) path-guard-core — extraer `_validate_output_path()` y `_neutralize_console_text()` a core/paths.py para que ui/ y reporting/ reutilicen la misma barrera de rutas/texto que la CLI — core/paths.py, ui/, reporting/
- [ ] (IMP-3) report-out-dir — `--output-dir` validado (o clave [exports].output_dir en TOML) como raíz alternativa permitida; relaja la cárcel H-003 para quien quiera informes fuera del CWD de forma explícita — osint_eye.py, core/config.py
- [ ] (IMP-3) dashboard-findings-api — endpoint /api/scan/<target>/findings sirviendo core/findings.py (lista canónica + summary) para el explorador de hallazgos — osint_eye.py (cableado mínimo), core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,csv,mitre_json,... con exportadores selectivos (export_all ya soporta formats=) — osint_eye.py
