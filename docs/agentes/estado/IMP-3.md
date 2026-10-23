# Estado IMP-3 — Núcleo, análisis y salidas

Actualizado: 2026-10-24 (sesión: bloque de fixes de hallazgos TEST — 5 tareas)

## Hecho (últimas 24 h)

- [x] (IMP-3) fix-h007-ctrlc — el bucle de targets captura KeyboardInterrupt, reúne parciales
  (completados + en vuelo vía engine.results; engine se resetea por iteración para no atribuir mal)
  en ScanInterrupted y main() sale con EXIT_INTERRUPTED=130 (128+SIGINT) tras resumen por target.
  8 tests (test_cli_interrupt.py).
- [x] (IMP-3) fix-h001-persistencia — sin -o cada escaneo auto-guarda osint_eye_<target>_<ts>.json
  en CWD (convención del PDF por defecto) + mensaje con ubicación y caché; --dashboard reutiliza el
  fichero (antes duplicaba con otro timestamp). 5 tests (test_default_persistence.py).
- [x] (IMP-3) fix-h008-pdf-duplicado — con -o la rama --pdf solo renderiza si 'pdf' NO está entre
  los formatos; si está, export_all ya produce base.pdf; si no está, deriva la ruta de la base
  (sufijo por target). 5 tests (test_pdf_dedupe.py).
- [x] (IMP-3) fix-h010-modules-comas — --modules acepta comas y espacios (split por token, dedupe
  estable), unknown = error corto accionable; adiós al muro de ~40 líneas de choices=[...].
  9 tests (test_modules_flag.py).
- [x] (IMP-3) fix-h002-validacion-targets — _normalize_cli_target(): URLs → scheme://host[:port]
  (scheme conservado para web, puerto para fixtures loopback, corchetes IPv6), paths fuera, host en
  minúsculas; validación final con reglas del wizard; lo no explicable → exit 2 accionable.
  10 tests (test_target_validation.py).
- Suite al cierre: 984 tests offline en verde. Conflicto de CHANGELOG con IMP-1 (h011) resuelto
  conservando ambas entradas.

## En curso

- (nada)

## Bloqueado

- (nada)

## Peticiones a otras zonas

- TEST: pendiente de verificar H-007/H-001/H-008/H-010/H-002 (todos resuelto-pendiente-verificación);
  los e2e de fixtures siguen pasando (run_cli con cwd=tmp_path de la ronda anterior).
- IMP-2: ui/rich_cli.py sigue imprimiendo datos externos no-target (banners, records) sin
  neutralizar — sugerimos reutilizar osint_eye._neutralize_console_text() (petición de la ronda
  anterior, sigue abierta).

## Propuestas para el roadmap

- [ ] (IMP-3) path-guard-core — extraer _validate_output_path/_neutralize_console_text y las reglas de target a core/paths.py; API pública única para CLI/wizard/ui/reporting (evita que IMP-2 tenga que importar privados) — core/paths.py, osint_eye.py, ui/
- [ ] (IMP-3) dashboard-findings-api — endpoint /api/scan/<target>/findings sirviendo core/findings.py (lista canónica + summary) — osint_eye.py (cableado mínimo), core/findings.py
- [ ] (IMP-3) export-cli-flags — --export sarif,csv,mitre_json,... con exportadores selectivos (export_all ya soporta formats=) — osint_eye.py
- [ ] (IMP-3) interrupt-checkpoint — guardar los parciales del Ctrl+C (ScanInterrupted) en un JSON de output/ automáticamente, combinable con resume-scan (v2.3) — osint_eye.py, core/session_cache.py
