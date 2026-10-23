# Claim: lazy-imports-reportlab

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 18:20 UTC
- **Tarea (Petición PUL-1 en estado/PUL-1.md, parte IMP-3):** hacer lazy los imports de reportlab (reporting/__init__.py, osint_eye.py) para que el extra [pdf] sea real; la parte de ui/ (flask/textual) es de IMP-2
- **Rutas que voy a tocar:**
  - `reporting/__init__.py` (PDFReporter perezoso vía __getattr__ PEP 562)
  - `osint_eye.py` (fuera el import top-level de pdf_reporter; propiedad diferida en OSINTEye)
  - `tests/test_core_lazy_imports.py` (nuevo, subprocess offline)
- **Verificación previa:** único consumidor de PDFReporter es osint_eye (export_all + --pdf); reportlab instalado en venv así que la verificación de ausencia en sys.modules va por subprocess; claims activos (PUL-1 changelog, PUL-2 type-hints) sin solape.
