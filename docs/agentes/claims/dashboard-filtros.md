# Claim: dashboard-filtros

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 07:50 UTC
- **Tarea (ROADMAP):** (IMP-2) dashboard-filtros — búsqueda y filtros (severidad, tipo de activo, módulo) en el dashboard, sin CDN
- **Rutas que voy a tocar:**
  - `ui/dashboard.py` (nuevo endpoint `/api/scan/<target>/assets` + agregador de activos)
  - `ui/dashboard_template.html` (barra de búsqueda + filtros, todo con textContent, sin CDN)
  - `tests/test_ui_dashboard_assets.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
