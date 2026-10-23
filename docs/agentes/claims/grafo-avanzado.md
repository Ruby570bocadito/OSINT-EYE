# Claim: grafo-avanzado

- **ID**: IMP-2
- **Fecha/hora UTC**: 2026-10-23 21:00 UTC
- **Tarea**: (IMP-2) grafo-avanzado — filtros por tipo de nodo, búsqueda, resaltar caminos de ataque, exportar PNG/SVG — ui/dashboard_template.html (promocionada del Siguiente, ronda 4)

## Rutas que voy a tocar

- `ui/dashboard_template.html` (toolbar del grafo: chips de filtro por tipo, búsqueda con dimming,
  botón "Attack paths" con BFS desde el hub hacia nodos de riesgo, export SVG/PNG con estilos
  inline en el SVG y canvas data: — permitido por la CSP actual `img-src 'self' data:`;
  descarga vía Blob + a[download], sin CDN)
- `tests/test_ui_graph_advanced.py` (nuevo: contrato estático de la plantilla, offline)
- `CHANGELOG.md` (entrada bajo [Unreleased])

## Sin solape

- Claims activos revisados antes de escribir: `readme-en-desde-cero` (PUL-1, docs/) y
  `scope-collectores` (IMP-1, modules/) — sin intersección con ui/dashboard_template.html.
- Solo cambian el template y tests: sin cambios de servidor ni de contrato `results`.
