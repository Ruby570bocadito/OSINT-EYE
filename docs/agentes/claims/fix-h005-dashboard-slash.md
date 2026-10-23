# Claim: fix-h005-dashboard-slash

- **ID**: IMP-2
- **Fecha/hora UTC**: 2026-10-23 19:05 UTC
- **Tarea**: (IMP-2) fix-h005-dashboard-slash — H-005 de TEST: targets con `/` inalcanzables desde el dashboard (rutas URL); escapar o indexar por hash — ui/dashboard.py

## Rutas que voy a tocar

- `ui/dashboard.py` (solo converters de ruta: `<target>` → `<path:target>` en las 10 rutas
  `/api/scan/...`; el cliente ya envía `encodeURIComponent` y Werkzeug 3.1 decodifica `%2F`
  correctamente — verificado empíricamente; nota de diseño en el docstring del módulo)
- `tests/test_ui_dashboard_slash_targets.py` (nuevo, suite offline con targets URL/hostiles)
- `CHANGELOG.md` (entrada bajo [Unreleased] / Corregido)

## Sin solape

- Claims activos revisados antes de escribir: `scan-diff-stateless` (IMP-3, core/scan_diff.py),
  `cache-deserializacion` (SEG, core/), `deps-sync` (PUL-1), `type-hints-core` (PUL-2, core/graph) —
  ninguno toca ui/dashboard.py.
- fix-h004-escape-injection (IMP-3, ALTA) renderiza salidas CLI/HTML: mi cambio no toca puntos de
  render, solo el routing; los paneles siguen renderizando por textContent.
- Comportamiento residual documentado: un target patológico tipo "a.com/summary" colisiona con el
  ancla literal de la subruta (404 honesto, nunca 500); queda apuntado en la Peticiones del estado
  por si SEG prefiere resolución por sid en el hardening.
