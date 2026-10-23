# Claim: fix-h008-pdf-duplicado

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 18:05 UTC
- **Tarea:** H-008 de TEST — `-o base --pdf` genera DOS PDFs (`base.pdf` por export_all + `osint_eye_<target>_<ts>.pdf` suelto en CWD por la rama --pdf). Cuando `args.output` está presente: si 'pdf' está entre los formatos de exportación, la rama --pdf no renderiza (export_all ya produce `base.pdf`); si no está, la rama deriva la ruta de la base `-o` (con sufijo saneado por target en multi-target) en vez del nombre por defecto. Sin `-o` se mantiene el nombre por defecto.
- **Rutas que voy a tocar:**
  - `osint_eye.py` (rama --pdf de scan_targets)
  - `tests/test_pdf_dedupe.py` (nuevo: regresión offline)
  - `CHANGELOG.md` (línea [Unreleased])
  - `docs/agentes/hallazgos/H-008-pdf-duplicado.md` (Estado: resuelto-pendiente-verificación)
  - `docs/agentes/estado/IMP-3.md`, `docs/agentes/claims/`
