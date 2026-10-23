# Claim: dashboard-vacio-guiado

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 18:00 UTC
- **Tarea (ROADMAP · Banco de ideas, propuesta TEST ronda 5):** panel con los 3 comandos exactos para generar un escaneo real cuando el dashboard carga datos demo — ui/dashboard_template.html
- **Rutas que voy a tocar:**
  - `ui/dashboard_template.html` (sección quickstart oculta: se muestra cuando no hay escaneos o el activo es demo; 3 comandos reales del CLI con botón de copiado por portapapeles; solo addEventListener/textContent — cero recursos externos, compatible CSP)
  - `tests/test_ui_dashboard_quickstart.py` (NUEVO — assertions offline sobre template + ruta)
  - `CHANGELOG.md` (una línea bajo [Unreleased])
- **Comandos del panel (verificados en osint_eye.py):** `python osint_eye.py example.com --dashboard`, `python osint_eye.py example.com --dashboard --monitor`, `python osint_eye.py example.com --rich`
- **NO toco:** ui/dashboard.py, ui/tui_app.py, ui/wizard.py, ui/rich_cli.py, osint_eye.py
