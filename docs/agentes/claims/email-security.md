# Claim: email-security

- **Agente:** IMP-1
- **Fecha/hora UTC:** 2026-10-23 11:35 UTC
- **Tarea (ROADMAP):** (IMP-1) email-security — DKIM (selectores comunes), MTA-STS, TLS-RPT, BIMI y puntuación de spoofing junto a SPF/DMARC
- **Rutas que voy a tocar:**
  - `modules/dns/email_security.py` (nuevo: EmailSecurityAuditor con puntuación explicable)
  - `modules/dns/dns_scanner.py` (integración en modo "full", reutilizando spf/dmarc ya calculados)
  - `modules/dns/__init__.py` (export)
  - `tests/test_modules_email_security.py` (nuevo, offline con resolver inyectado)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
