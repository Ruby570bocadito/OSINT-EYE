# Claim: dashboard-multiscan

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 08:05 UTC
- **Tarea (ROADMAP):** (IMP-2) dashboard-multiscan — selector de escaneos guardados + vista diff entre dos escaneos (reusa core/scan_diff.py)
- **Rutas que voy a tocar:**
  - `ui/dashboard.py` (endpoint `GET /api/scan/<target>/diff?against=<otro>` + sanitizado de shapes)
  - `ui/dashboard_template.html` (panel "Scan Comparison" con selector From/To, render textContent)
  - `tests/test_ui_dashboard_diff.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Nota:** solo CONSUMO `core/scan_diff.ScanDiff` (no lo modifico; zona de IMP-3). Instancio uno por
  petición porque `self.diff` se muta entre llamadas (anotado en mi estado como petición a IMP-3).
