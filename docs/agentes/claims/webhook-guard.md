# Claim: webhook-guard

- **Agente:** SEG
- **Fecha/hora UTC:** 2026-10-24 12:25 UTC
- **Tarea:** webhook-guard (Banco de ideas, etiqueta SEG; evidencia de código: `AlertManager.webhook_handler` hace `requests.post(url)` sin validación — SSRF hacia IPs privadas/metadatos con `--webhook`). Fix mínimo: validación https-only + host público reutilizando ssrf_guard.
- **Rutas que voy a tocar:**
  - `modules/web/ssrf_guard.py` (helper is_safe_webhook_url)
  - `core/monitor.py` (cinturón: webhook_handler rechaza URL no segura)
  - `osint_eye.py` (fail-fast con parser.error, patrón scope/config existente)
  - `tests/test_seg_webhook.py` (nuevo: regresión offline)
  - `CHANGELOG.md` (línea bajo [Unreleased]; excepción OWNERSHIP)
- **Verificación previa:** sin claims activos sobre estas rutas (readme-en-desde-cero PUL-1, scope-collectores IMP-1); `git log --since="3 days ago"` sin commits recientes en ssrf_guard.py ni en el bloque webhook de monitor/osint_eye.
