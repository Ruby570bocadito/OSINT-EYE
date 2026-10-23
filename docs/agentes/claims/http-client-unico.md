# Claim: http-client-unico

- **Agente:** IMP-1
- **Fecha/hora UTC:** 2026-10-23 08:05 UTC
- **Tarea (ROADMAP):** (IMP-1) http-client-unico — cliente HTTP compartido (timeout por defecto, reintentos con backoff, User-Agent configurable, rate-limit por host, proxy) y migrar los requests.get sueltos
- **Rutas que voy a tocar:**
  - `modules/_http.py` (nuevo: HTTPClient + get_client)
  - `modules/web/web_scanner.py`, `modules/web/wayback.py`
  - `modules/dns/advanced_dns.py`, `modules/dns/subdomain_permutator.py`
  - `modules/certs/cert_scanner.py`, `modules/cve/nvd.py`
  - `modules/osint/github.py`, `modules/osint/google.py`, `modules/osint/cloud_email.py`
  - `tests/test_modules_http.py` (nuevo, offline), `tests/test_core.py` (solo los 2 parches `patch("requests.get")` → `patch("requests.Session.request")` para SecurityHeadersAuditor)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **No toco:** `core/monitor.py` (zona IMP-3; petición anotada en mi estado), sesiones aiohttp de advanced_dns.py (no son requests).
