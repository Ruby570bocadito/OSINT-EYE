# Claim: dashboard-api-hardening

- **Agente:** SEG
- **Fecha/hora UTC:** 2026-10-23 16:20 UTC
- **Tarea (ROADMAP):** (SEG) dashboard-api-hardening — revisar path traversal en la carga de JSON por <target>, cabeceras de seguridad (CSP sin inline) y límites de tamaño — ui/dashboard.py
- **Rutas que voy a tocar:**
  - `ui/dashboard.py` (cabeceras de seguridad, CSP, límite de tamaño, RecursionError, Response verbatim en vez de render_template_string)
  - `tests/test_seg_dashboard_hardening.py` (nuevo, 18 tests offline con test_client)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** sin claims activos sobre ui/dashboard.py (IMP-2 está en progreso-por-modulo sobre ui/rich_cli.py); el claim dashboard-filtros ya fue liberado y dashboard-multiscan está entregado (d79fabf). `git log --since="3 hours ago" -- ui/dashboard.py`: sin actividad ajena.
- **Nota:** la parte "CSP sin inline" (nonces por petición) exige tocar `ui/dashboard_template.html`, que IMP-2 está iterando; queda como Peticiones a IMP-2 en estado/SEG.md para que la adopte en su próxima pasada de la plantilla.
