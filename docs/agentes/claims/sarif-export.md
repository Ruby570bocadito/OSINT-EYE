# Claim: sarif-export

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 16:55 UTC
- **Tarea (ROADMAP):** (IMP-3) sarif-export — exportación SARIF 2.1 de hallazgos (takeover, buckets públicos, secretos, CVE) para GitHub Code Scanning
- **Rutas que voy a tocar:**
  - `reporting/sarif.py` (nuevo: SarifExporter + extract_findings con niveles SARIF)
  - `osint_eye.py` (cableado en export_all + import)
  - `tests/test_reporting_sarif.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** reporting/sarif.py no existe; claims activos sin solape (revisados 16:55 UTC); baseline 356 tests en verde en el último push.
