# Claim: ssrf-redirects

- **Agente:** SEG
- **Fecha/hora UTC:** 2026-10-23 16:05 UTC
- **Tarea (ROADMAP):** (SEG) ssrf-redirects — revisar que los colectores web no siguen redirecciones a IP privadas/metadatos cloud (169.254.169.254)
- **Rutas que voy a tocar:**
  - `modules/web/ssrf_guard.py` (nuevo: validación por hop)
  - `modules/web/web_scanner.py` (2 llamadas: TechDetector.detect, SensitiveDataDetector.scan_url)
  - `modules/osint/cloud_email.py` (1 llamada: CDNDetector.detect)
  - `modules/dns/subdomain_permutator.py` (1 llamada: SubdomainTakeoverDetector.check_takeover — CNAMEs colgantes = dominios controlados por el atacante, el punto de mayor riesgo; se reclama explícitamente aunque dns/ es zona de IMP-1)
  - `tests/test_seg_ssrf_guard.py` (nuevo, 46 tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** sin claims solapados (IMP-2 dashboard-filtros en ui/; PUL-1 readme-fiel en README/CHANGELOG — solo añado línea); `git log --since="3 days ago"` en las rutas: sin actividad ajena. Alcance acotado a los fetch de superficies hostiles; los clientes de API de endpoints fijos (github/google/crt.sh/NVD/wayback) quedan como riesgo residual para el cliente HTTP único de IMP-1 (anotado en estado SEG).
