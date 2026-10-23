# Claim: tema-claro

- **Agente:** IMP-2
- **Fecha/hora UTC:** 2026-10-23 17:55 UTC
- **Tarea (ROADMAP · Siguiente v2.3):** tema claro/oscuro en el dashboard respetando prefers-color-scheme — ui/dashboard_template.html
- **Rutas que voy a tocar:**
  - `ui/dashboard_template.html` (override de tokens en @media (prefers-color-scheme: light) + color-scheme, topbar con var(--topbar-bg), export SVG/PNG del grafo leyendo los tokens computados con fallback oscuro)
  - `tests/test_ui_dashboard_theme.py` (NUEVO — assertions offline sobre el template, patrón de test_ui_dashboard_assets)
  - `CHANGELOG.md` (una línea bajo [Unreleased])
- **Garantías:** sin CDN ni recursos nuevos; sin botón de toggle (solo media query, como pide la tarea); el resto de ui/ intacto
- **NO toco:** ui/dashboard.py, ui/tui_app.py, ui/rich_cli.py, ui/wizard.py, osint_eye.py
