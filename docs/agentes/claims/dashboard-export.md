# Claim: dashboard-export

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 09:35 UTC
- **Tarea (ROADMAP):** (IMP-2) dashboard-export — botón de descarga JSON/CSV/MD del escaneo abierto en el dashboard
- **Rutas que voy a tocar:**
  - `ui/dashboard.py` (endpoint `GET /api/scan/<target>/export?format=json|csv|md`, filename saneado,
    neutralización de fórmulas en el CSV, reutiliza `reporting.markdown_reporter.MarkdownReporter`)
  - `ui/dashboard_template.html` (grupo de botones Export en la topbar, descarga del escaneo activo)
  - `tests/test_ui_dashboard_export.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Nota:** solo CONSUMO `reporting/markdown_reporter.py` (zona IMP-3, no lo modifico).
