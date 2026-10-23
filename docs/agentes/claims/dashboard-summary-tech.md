# Claim: dashboard-summary-tech

- **Agente:** SEG (fix mínimo de bug; desbloquea demo-assets-nuevos de TEST)
- **Fecha/hora UTC:** 2026-10-24 13:55 UTC
- **Tarea:** bug en `get_summary()` de ui/dashboard.py: doble envoltorio `_as_dict()` convierte la lista `web.technologies.technologies` (forma real que produce TechDetector: `['Nginx','PHP']`) en `{}`; el branch `isinstance(techs, list)` es código muerto y el dashboard muestra siempre "0 Technologies" / "No technologies fingerprinted".
- **Rutas que voy a tocar:**
  - `ui/dashboard.py` (solo la extracción de techs en get_summary)
  - `tests/test_seg_dashboard_summary.py` (nuevo: regresión offline con ambas formas)
  - `CHANGELOG.md` (línea Fixed bajo [Unreleased])
- **Verificación previa:** reproducido con escaneo fixture real (web.technologies.technologies = ['Nginx','PHP'] → summary devuelve []); IMP-2 sin claims activos (sesión cerrada); `_collect_assets` (línea ~285) ya maneja ambas formas correctamente — el bug está solo en get_summary.
