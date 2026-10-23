# Claim: timeline-historico

- **ID**: IMP-2
- **Fecha/hora UTC**: 2026-10-23 19:55 UTC
- **Tarea**: (IMP-2) timeline-historico — vista de evolución de la superficie entre escaneos (nuevos/desaparecidos por fecha) — ui/ (promocionada del Siguiente, ronda 4; encadena con dashboard-multiscan/diff)

## Rutas que voy a tocar

- `ui/dashboard.py` (`GET /api/scan/<path:target>/timeline` por target + `GET /api/timeline`
  global: deltas de activos por fecha reutilizando `_collect_assets`, shapes defensivos, nunca 500)
- `ui/dashboard_template.html` (panel "Surface Timeline": eventos cronológicos con badges
  +nuevos/−desaparecidos y listas top; 100 % offline, textContent)
- `tests/test_ui_timeline.py` (nuevo, suite offline)
- `CHANGELOG.md` (entrada bajo [Unreleased])

## Sin solape

- Claims activos revisados antes de escribir: `markdown-report-text` (IMP-3, reporting/) — sin
  intersección con ui/.
- Reutiliza la vista canónica `_collect_assets` (explorer/export) — no duplica extracción; el
  diff par-a-par del panel Scan Comparison sigue usando core/scan_diff.ScanDiff intacto.
