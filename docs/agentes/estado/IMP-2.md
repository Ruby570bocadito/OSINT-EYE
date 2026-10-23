# Estado IMP-2 — Interfaz

Actualizado: 2026-10-23 (ronda 2 v2.2/v2.3 — SESIÓN LARGA, 5/5 tareas, empujadas a main)

## Hecho (últimas 24 h)

- [x] wizard-validacion-target — dominio/IP/CIDR validados con reintentos; aviso de URL con swap
  de host (CIDRs válidos no se marcan como URL); todo texto escapa el input (sin MarkupError).
  59 tests; 1 test heredado hostil adaptado (mismo contrato: sobrevive). 034fa93.
- [x] dashboard-autorefresco — /api/dashboard/config + badge LIVE con pausa/OFFLINE tras 3 fallos;
  watcher por mtime + reload_scan_results (upsert con refreshed_at, sin duplicados); cableado
  mínimo --monitor --dashboard en osint_eye.py (excepción OWNERSHIP). 19 tests. 9bc4dd5.
- [x] fix-h005-dashboard-slash — rutas /api/scan/... a <path:target> (verificado en Werkzeug 3.1:
  %2F decodifica post-routing), merge_slashes off, 404 JSON uniforme en /api/*. 14 tests. 096e190.
- [x] timeline-historico — /api/timeline + /api/scan/<t>/timeline encadenando deltas sobre
  _collect_assets; SCAN_ARCHIVE[(target, date)] preserva estados históricos; panel Surface
  Timeline (rail con badges +nuevos/−desaparecidos). 15 tests. 3761b6a.
- [x] grafo-avanzado — chips-filtro por tipo en la leyenda, búsqueda, Attack paths (BFS del hub
  a nodos de riesgo) y export SVG/PNG (estilos inline en el SVG, canvas data: por CSP, Blob).
  14 tests + node --check. f2bbe1f.
- Suite: 466 → 720 tests en verde (mis contribuciones ronda 2: 121, todas offline).
- Nota: el claim de timeline/grafo fue absorbido por su commit feat por un lío de rebase; el
  ciclo quedó completo en main (claim + release como commits propios).

## En curso

- Nada (sesión cerrada 5/5; sin claims activos de IMP-2).

## Bloqueado

- Nada. (Aviso: PUL-2 partirá rich_cli.py — cuando aterrice, revisar mis 3 llamadas del tracker.)

## Peticiones a otras zonas

- (IMP-3) core/monitor.py: persistir cada ciclo del monitor como JSON de escaneo (parcial vale,
  con scan_date nuevo por ciclo) — con mi watcher del dashboard (watch_paths) se vería en vivo sin
  tocar más core.
- (SEG) revisar merge_slashes=False + handler 404 JSON (ui/dashboard.py, commit 096e190): son
  cambios de routing previos a dashboard-api-hardening; quiero evitar duplicar criterios.
- (IMP-3) fix-h004: mi render es textContent-only; el escape pendiente es el de salidas CLI —
  coordinar para no escapar dos veces en el dashboard.

## Propuestas para el roadmap

- [ ] (IMP-2) timeline-export — descarga CSV/MD de la vista timeline (eventos + deltas), mismo
  patrón que /export del explorer — ui/dashboard.py
- [ ] (IMP-2) wizard-target-presets — presets reutilizables de targets/scope/exclusiones
  (--wizard-preset FILE; guardar preset al final del wizard) — ui/wizard.py
- [ ] (IMP-2) grafo-node-detail — clic en nodo abre ficha: conexiones, módulos que lo reportan y
  severidad; encadena con dashboard-detalle-activo (Banco) — ui/dashboard_template.html
