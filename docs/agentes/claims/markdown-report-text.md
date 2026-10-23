# Claim: markdown-report-text

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 17:55 UTC
- **Tarea (Petición IMP-2 en estado/IMP-2.md):** reporting/markdown_reporter.py — exponer el informe como TEXTO sin escribir fichero (para descargas en memoria del dashboard)
- **Rutas que voy a tocar:**
  - `reporting/markdown_reporter.py` (nuevo build_text() público; generate() lo reutiliza; sin cambio de API existente)
  - `tests/test_reporting_markdown_text.py` (nuevo, tests offline)
- **Verificación previa:** consumers actuales usan generate() con ruta (dashboard escribe a tmp handle); añadir build_text() no rompe nada; claims activos sin solape.
