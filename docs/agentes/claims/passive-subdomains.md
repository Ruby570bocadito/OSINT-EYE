# Claim: passive-subdomains

- **Agente:** IMP-1
- **Fecha/hora UTC:** 2026-10-23 09:10 UTC
- **Tarea (ROADMAP):** (IMP-1) passive-subdomains — nuevas fuentes pasivas sin API key: HackerTarget, AlienVault OTX, Anubis/jldc, RapidDNS, CertSpotter; dedupe con crt.sh
- **Rutas que voy a tocar:**
  - `modules/dns/passive_sources.py` (nuevo: PassiveSubdomainEnumerator, 5 fuentes)
  - `modules/dns/dns_scanner.py` (integración en scan_type="full": merge + dedupe)
  - `tests/test_modules_passive.py` (nuevo, offline con respuestas fijas)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **No toco:** osint_eye.py (integración via DNSScanner, que ya está cableado en run_dns), módulos de crt.sh existentes (CertScanner) — el dedupe se hace contra lo ya hallado en el escaneo.
