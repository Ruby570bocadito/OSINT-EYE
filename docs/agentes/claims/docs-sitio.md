# Claim: docs-sitio

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-24 16:35 UTC
- **Tarea (ROADMAP · Siguiente v2.3):** docs/ reorganizado: arquitectura, módulos (uno por página), cómo escribir un plugin, FAQ — docs/
- **Rutas que voy a tocar:**
  - `docs/index.md` (NUEVO — hub de documentación con TOC)
  - `docs/architecture.md` (NUEVO — capas, flujo de datos, diseño offline-first)
  - `docs/modules/*.md` (NUEVO — una página por módulo built-in: dns, certs, wayback, web, network, whois, github, google, cloud, emails, cdn_waf, cve; 12 páginas)
  - `docs/plugins.md` (NUEVO — guía BaseModule/PluginManager con ejemplo offline-testable)
  - `docs/FAQ.md` (NUEVO)
  - `README.md` línea de documentación (link a docs/index.md), `CHANGELOG.md` (líneas bajo [Unreleased] → Añadido)
- **Garantías:** contenido derivado del código actual (docstrings, --help real, core/schema.py); sin tocar código; USAGE.md queda donde está (README ya enlaza)
- **NO toco:** ui/dashboard_template.html y tests/test_ui_dashboard_theme.py (claim tema-claro de IMP-2), ningún .py
