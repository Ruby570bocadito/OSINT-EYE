# Claim: fix-tech-shapes-dashboard

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 18:05 UTC
- **Tarea (autodetectada al preparar demo-assets; no estaba en el ROADMAP):** el summary y
  `_collect_assets` de ui/dashboard.py solo aceptan la forma `{"technologies": {...}}` doble;
  la salida REAL de web_scanner (`{"url": ..., "technologies": ["..."]}`) y otras formas en
  salvaje (lista directa, dict de claves) muestran 0 tecnologías en el stat, el panel
  Technologies, el explorer y el TUI.
- **Rutas que voy a tocar:**
  - `ui/dashboard.py` (normalizador `_tech_names()` que acepta lista / dict-de-claves / wrapper
    dict / payload real del scanner; usado por summary y _collect_assets)
  - `tests/test_ui_dashboard_assets.py` (clase nueva TestTechnologiesShapes, offline)
  - `CHANGELOG.md` (una línea bajo [Unreleased] → Fixed)
- **Contrato `results`:** solo lo consumo (normalizo lectura); no cambio el productor (IMP-1).
- **NO toco:** modules/, ui/tui_app.py (hereda el fix vía _collect_assets), osint_eye.py
