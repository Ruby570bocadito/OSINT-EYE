# Claim: findings-extract

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 16:25 UTC
- **Tarea (ROADMAP):** (IMP-3) findings-extract — extractor único de hallazgos (takeover, buckets públicos, secretos, CVE, ficheros sensibles) a lista canónica con severidad y evidencia, reutilizable por SARIF/exit-codes/risk-scoring — core/findings.py (propuesta IMP-3, ronda 2)
- **Rutas que voy a tocar:**
  - `core/findings.py` (nuevo: Finding dataclass/TypedDict, extract_findings() canónico, ranking y filtros)
  - `reporting/sarif.py` (delega la extracción en core/findings.py; la API pública no cambia)
  - `tests/test_core_findings.py` (nuevo, tests offline)
  - `tests/test_reporting_sarif.py` (ajustes mínimos si la delegación cambia mensajes)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** core/findings.py no existe; claims activos (email-security, passive-subdomains de IMP-1) sin solape; baseline 466 tests en verde en main.
