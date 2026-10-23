# Claim: dashboard-autorefresco

- **ID**: IMP-2
- **Fecha/hora UTC**: 2026-10-23 17:55 UTC
- **Tarea**: (IMP-2) dashboard-autorefresco — auto-refresco del dashboard en modo monitor (polling de la API cada N s, respeta --monitor-interval) — ui/dashboard.py, ui/dashboard_template.html (promocionada del Banco, ronda 3)

## Rutas que voy a tocar

- `ui/dashboard.py` (DASHBOARD_CONFIG + `GET /api/dashboard/config` + `reload_scan_results()` sin duplicar historial + hilo watcher opcional en `start_dashboard(monitor=..., interval=..., watch_paths=[...])`)
- `ui/dashboard_template.html` (polling del cliente: badge LIVE, pausa/reanudar, refresco suave que preserva el target seleccionado, todo vía textContent, sin CDN)
- `osint_eye.py` (SOLO cableado mínimo según OWNERSHIP: en la rama `--monitor`, si `--dashboard`, lanzar el dashboard en hilo daemon con monitor=True/interval; nada más)
- `tests/test_ui_dashboard_autorefresh.py` (nuevo, suite offline)
- `CHANGELOG.md` (entrada bajo [Unreleased])

## Sin solape

- Claims activos revisados antes de escribir: `config-file` (IMP-3, core/config.py + osint_eye.py flags de config) y `ruff-config` (PUL-2 — declara NO tocar ui/{rich_cli,wizard,dashboard}.py; sí tocaría ui/tui_app.py, no lo uso en esta tarea).
- El cableado en osint_eye.py es la excepción prevista en OWNERSHIP (import + lanzamiento condicional en la rama monitor ya existente); no toco parser ni catálogo.
- H-005 (target con `/` en el dashboard) es hallazgo de SEG con tarea propia (dashboard-api-hardening): no lo ataco aquí, mis rutas reutilizan los endpoints existentes.
