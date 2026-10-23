# Claim: security-headers

- **Agente:** IMP-1
- **Fecha/hora UTC:** 2026-10-23 12:30 UTC
- **Tarea (ROADMAP):** (IMP-1) security-headers — auditoría de cabeceras (CSP, HSTS, XFO, CORS permisivo, cookies sin Secure/HttpOnly) con severidad
- **Rutas que voy a tocar:**
  - `modules/web/headers_audit.py` (nuevo: SecurityHeadersAuditor ampliada — CORS, cookies, severidades; mantiene el contrato/shape previo)
  - `modules/dns/advanced_dns.py` (la clase pasa a re-export de la nueva ubicación; sin duplicación)
  - `modules/web/__init__.py` (export)
  - `modules/web/web_scanner.py` (cableado: results["web"]["headers_audit"] con degradación)
  - `tests/test_modules_headers.py` (nuevo, offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Compatibilidad:** test_core.py sigue importando desde modules.dns (re-export); deductions previas intactas (solo se añaden CORS/cookies); verify=True y path SSLError de SEG se conservan.
