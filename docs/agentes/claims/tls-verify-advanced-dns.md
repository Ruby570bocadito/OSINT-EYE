# Claim: tls-verify-advanced-dns

- **Agente:** SEG
- **Fecha/hora UTC:** 2026-10-23 15:55 UTC
- **Tarea:** fix de seguridad detectado en revisión (backport del fix de la rama `audit-improvements` d72e786, nunca fusionado en master): `SecurityHeadersAuditor` y el fallback de `ScreenshotCapture` usan `requests.get(..., verify=False)` — la verificación TLS se desactiva silenciosamente al auditar objetivos hostiles (riesgo MITM; un certificado inválido es un hallazgo, no un motivo para degradar la sonda).
- **Rutas que voy a tocar:**
  - `modules/dns/advanced_dns.py` (2 llamadas: línea ~612 y ~935)
  - `tests/test_tls_handling.py` (nuevo, offline: servidor local 127.0.0.1 HTTP/HTTPS)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** `git log --since="3 days ago" -- modules/dns/advanced_dns.py` sin actividad de otros agentes; sin claims solapados (activos: IMP-2 dashboard-filtros en ui/, PUL-1 readme-fiel en README/CHANGELOG).
