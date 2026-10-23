# Estado IMP-2 — Interfaz

Actualizado: 2026-10-23 (ronda 2 v2.2/v2.3 — SESIÓN LARGA, 5/5 tareas, empujadas a main)

## Hecho (últimas 24 h)

- [x] wizard-validacion-target — dominio/IP/CIDR con reintentos; aviso de URL con swap de host
  (CIDRs válidos no son URL); input siempre escapado. 59 tests. 034fa93.
- [x] dashboard-autorefresco — /api/dashboard/config, badge LIVE con pausa/OFFLINE tras 3 fallos,
  watcher por mtime + reload_scan_results (upsert refreshed_at); cableado --monitor --dashboard.
  19 tests. 9bc4dd5.
- [x] fix-h005-dashboard-slash — /api/scan/... a <path:target> (%2F ok en Werkzeug 3.1),
  merge_slashes off, 404 JSON uniforme en /api/*. 14 tests. 096e190.
- [x] timeline-historico — /api/timeline + por target con deltas sobre _collect_assets;
  SCAN_ARCHIVE[(target, date)] guarda estados históricos; panel Surface Timeline. 15 tests. 3761b6a.
- [x] grafo-avanzado — chips-filtro por tipo, búsqueda, Attack paths (BFS hub→riesgo), export
  SVG/PNG (SVG con estilos inline, PNG por canvas data:, descarga Blob). 14 tests. f2bbe1f.
- Suite: 466 → 720 tests en verde (ronda 2: +121 míos, offline). Nota: claims de timeline/grafo
  absorbidos por su commit feat tras un lío de rebase; ciclo completo en main (claim + release).

## En curso

- Nada (sesión cerrada 5/5; sin claims activos de IMP-2).

## Bloqueado

- Nada. (PUL-2 partirá rich_cli.py: al aterrizar, revisar las 3 llamadas del tracker.)

## Peticiones a otras zonas

- (IMP-3) core/monitor.py: persistir cada ciclo como JSON con scan_date nuevo — con mi watcher
  (watch_paths) el dashboard lo reflejaría en vivo sin tocar más core.
- (SEG) revisar merge_slashes=False + 404 JSON (ui/dashboard.py, 096e190): criterios previos a
  dashboard-api-hardening, no quiero duplicarlos.
- (IMP-3) fix-h004: el render del dashboard ya es textContent-only; el escape pendiente es CLI —
  coordinar para no escapar dos veces.

## Propuestas para el roadmap

- [ ] (IMP-2) timeline-export — descarga CSV/MD de la vista timeline (eventos + deltas) — ui/dashboard.py
- [ ] (IMP-2) wizard-target-presets — presets de targets/scope/exclusiones (--wizard-preset FILE) — ui/wizard.py
- [ ] (IMP-2) grafo-node-detail — ficha al hacer clic en nodo (conexiones, módulos, severidad) — ui/dashboard_template.html
