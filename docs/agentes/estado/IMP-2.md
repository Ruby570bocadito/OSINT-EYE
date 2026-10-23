# Estado IMP-2 — Interfaz

Actualizado: 2026-10-23 (ronda 3 v2.2/v2.3 — SESIÓN LARGA, 5/5 tareas, empujadas a main)

## Hecho (últimas 24 h)

- [x] demo-assets-nuevos (ALTA, petición del propietario) — 7 capturas reales con fixture offline
  example.com (dashboard-dark, cli-progress, wizard-auth vía pty abortado en el gate, report-pdf,
  graph-view, demo-scan.gif 14 s, mp4); grafo con GraphBuilder real. 992d131. PUL-1 ya las cableó.
- [x] tui-completa — Textual navegable: tabs Overview/Assets/DNS/Network/Findings (1-5), tabla de
  activos con _collect_assets + filtro (ctrl+f), ficha modal por activo, --tui cableado. 14 tests
  pilot offline. b1de59c.
- [x] tema-claro — prefers-color-scheme (paleta clara completa); --topbar-bg, timeline sin la var
  inexistente --panel-bg, export del grafo lee tokens. Verificado en Chromium. 9 tests. 8beb3b0.
- [x] dashboard-vacio-guiado (propuesta TEST) — panel «No scan data yet» con 3 comandos exactos y
  copiado, visible solo sin datos/demo; CSP-safe. 6 tests. eb14ffa.
- [x] fix-tech-shapes-dashboard (autodetectado) — un escaneo REAL de web_scanner mostraba 0
  tecnologías (stat/panel/explorer/TUI); _tech_names() normaliza todas las formas sin filtrar
  claves del payload; contrato SEG ({url:...} → []) respetado. 5 tests. 7dccd9f.
- Suite: 897 → 979 en verde. Sin claims activos de IMP-2.

## En curso
- Nada (sesión cerrada 5/5).

## Bloqueado
- Nada.

## Peticiones a otras zonas

- (PUL-2) i18n (siguiente en la cola IMP-2) conviene tras partir-rich-cli: no traducir textos que van a mudar de módulo.
- (IMP-1) documentar que modules.web.technologies es {url, technologies[], status_code} (informativo).

## Propuestas para el roadmap

- [ ] (IMP-2) tui-export — exportar el escaneo abierto desde la TUI (JSON/CSV/MD) reutilizando la
  capa de export del dashboard — ui/tui_app.py
- [ ] (IMP-2) wizard-resumen-previo — resumen (targets, scope, exclusiones, profundidad) antes del
  gate de autorización — ui/wizard.py
- [ ] (IMP-2) dashboard-graph-sidebar — lista de nodos sincronizada con el grafo (clic resalta y
  centra) — ui/dashboard_template.html
