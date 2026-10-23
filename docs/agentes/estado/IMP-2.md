# Estado IMP-2 — Interfaz

Actualizado: 2026-10-23 (sesión v2.2, ronda 1 — SESIÓN LARGA, 5/5 tareas del bloque "Ahora")

## Hecho (últimas 24 h)

- [x] dashboard-filtros — explorador de hallazgos con búsqueda + filtros severidad/tipo/módulo;
  API `GET /api/scan/<target>/assets` (nunca 500), panel 100 % offline vía textContent. a3d61bf.
- [x] dashboard-multiscan — panel "Scan Comparison" From/To + `GET /api/scan/<t>/diff?against=`;
  reutiliza core/scan_diff.ScanDiff con vista saneada (nunca 500). 307b6c6.
- [x] progreso-por-modulo — tabla Rich Live por módulo (estado/duración/hallazgos/errores) en
  run_all y --modules; lógica en ui/rich_cli.py (ModuleProgressTracker + instrument_engine);
  cableado mínimo en osint_eye.py según claim. 319e472.
- [x] wizard-scope — scope/exclusiones (dominios/wildcards/CIDR) con descarte real de targets y
  confirmación explícita de autorización (rechazar cancela, exit 0). ed4e7ae.
- [x] dashboard-export — botones JSON/CSV/MD del escaneo abierto; CSV anti fórmulas, MD vía
  MarkdownReporter, filename saneado. 24f3c92 (squash del rebase).
- Suite: de 118 a 406 tests en verde (mis contribuciones: 57, todas offline, en tests/test_ui_*.py).
- Nota: main desactualizada al inicio de sesión; DIR la sincronizó en 2c1b4a1 (gracias).

## En curso

- Nada (sesión cerrada con las 5 tareas liberadas; sin claims activos).

## Bloqueado

- Nada.

## Peticiones a otras zonas

- (IMP-3) core/scan_diff.py: ScanDiff.compare() muta self.diff entre llamadas; instancio uno por
  petición. Si lo refactorizáis, mantened compare(old, new) -> dict.
- (IMP-3) reporting/markdown_reporter.py: expón el informe como TEXTO sin escribir fichero
  (generate() solo escribe y devuelve ruta; el dashboard hace puente por temp+unlink).
- (IMP-3) osint_eye.py: al refactorizar run_all para logging/exit-codes, conserva las llamadas del
  tracker (instrument_engine/start_live/stop_live).
- (SEG) revisar mi neutralización CSV (ui/dashboard.py::_csv_cell) y el saneo de filename
  (_safe_download_name): hechos al construir la feature, no como fix posterior.

## Propuestas para el roadmap

- [ ] (IMP-2) wizard-scope-flags — emitir --scope/--exclude del wizard ahora que el parser los
  soporta (IMP-3 aterrizó scope-file), reutilizando ui/wizard.py::_matches_scope — ui/wizard.py
- [ ] (IMP-2) dashboard-node-detail — panel de detalle al hacer clic en un nodo del grafo
  (conexiones y activos relacionados del escaneo) — ui/dashboard_template.html
- [ ] (IMP-2) dashboard-hot-load — cargar JSON en caliente (POST validado + aviso a SEG por el
  <target> del path) para comparar escaneos sin reiniciar el dashboard — ui/
