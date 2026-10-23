# Claim: logging-real

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 16:05 UTC
- **Tarea (ROADMAP):** (IMP-3) logging-real — sustituir print() en core/graph/reporting por logging con --log-level y --log-file; Rich solo para la salida de usuario
- **Rutas que voy a tocar:**
  - `core/logging_config.py` (nuevo: setup_logging(level, log_file), logger "osint_eye", idempotente)
  - `core/monitor.py` (prints de alertas/ciclos → logger)
  - `graph/builder.py` (prints de export_html → logger)
  - `reporting/export.py`, `reporting/markdown_reporter.py`, `reporting/pdf_reporter.py`, `reporting/export_tools.py` (prints de "saved to" → logger)
  - `osint_eye.py` (flags --log-level / --log-file + setup al arrancar)
  - `tests/test_core_logging.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** `rg logging` sin setup previo; ningún test captura esos prints por stdout (grep en tests/); claims activos (IMP-2, PUL-1) sin solape; bloque `__main__` de scripts sueltos se deja tal cual (son CLIs de depuración manuales).
