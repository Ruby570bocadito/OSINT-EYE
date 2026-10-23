# Estado IMP-2 — Interfaz

Actualizado: 2026-10-23 (ronda 3 v2.2/v2.3 — SESIÓN LARGA, 5/5 tareas, empujadas a main)

## Hecho (últimas 24 h)

- [x] demo-assets-nuevos (ALTA, petición del propietario) — 7 capturas reales de la UI con fixture
  offline example.com: dashboard-dark, cli-progress (tracker real), wizard-auth (wizard real en pty,
  abortado en el gate de autorización — cero red), report-pdf, graph-view, demo-scan.gif (14 s,
  0.57 MB) y demo-scan.mp4. Grafo construido con GraphBuilder real. 992d131. PUL-1 ya las cableó.
- [x] tui-completa — Textual navegable: TabbedContent Overview/Assets/DNS/Network/Findings (teclas
  1-5), tabla de activos con la vista canónica _collect_assets + filtro en vivo (ctrl+f), ficha
  modal por activo (módulos que lo reportan + evidencia), --tui cableado (getattr tolerante).
  14 tests pilot offline. b1de59c (rebase sobre fix-h007 resuelto).
- [x] tema-claro — prefers-color-scheme con paleta clara completa; topbar con --topbar-bg, timeline
  sin la var inexistente --panel-bg, export SVG/PNG del grafo lee tokens computados. Verificado en
  Chromium (media light). 9 tests. 8beb3b0.
- [x] dashboard-vacio-guiado (propuesta TEST) — panel «No scan data yet» con los 3 comandos exactos
  y copiado al portapapeles cuando no hay escaneos o es demo; oculto con datos reales; CSP-safe.
  6 tests. eb14ffa.
- [x] fix-tech-shapes-dashboard (autodetectado) — summary y _collect_assets solo aceptaban el doble
  envoltorio: un escaneo REAL de web_scanner mostraba 0 tecnologías (stat, panel, explorer, TUI).
  _tech_names() normaliza todas las formas sin filtrar claves del payload; contrato SEG ({url:...}
  → []) respetado. 5 tests. 7dccd9f.
- Suite: 897 → 979 en verde. Sin claims activos de IMP-2.

## En curso

- Nada (sesión cerrada 5/5).

## Bloqueado

- Nada. (Fleet push muy activo: 3 conflictos de rebase resueltos conservando ambos lados.)

## Peticiones a otras zonas

- (PUL-2) i18n (siguiente en la cola IMP-2) conviene hacerla DESPUÉS de partir-rich-cli: no quiero
  traducir textos que van a mudar de módulo; así no duplicamos trabajo.
- (IMP-1) documentar en el contrato que modules.web.technologies es {url, technologies[], status_code}
  (mi _tech_names ya lo tolera junto a lista directa y wrapper; solo informativo).

## Propuestas para el roadmap

- [ ] (IMP-2) tui-export — exportar el escaneo abierto desde la TUI (JSON/CSV/MD) reutilizando la
  capa de export del dashboard — ui/tui_app.py
- [ ] (IMP-2) wizard-resumen-previo — resumen (targets finales, scope, exclusiones, profundidad)
  justo antes del gate de autorización — ui/wizard.py
- [ ] (IMP-2) dashboard-graph-sidebar — lista de nodos sincronizada con el grafo (clic resalta y
  centra el nodo) — ui/dashboard_template.html
