# Claim: csv-formula-dash

- **Agente:** SEG
- **Fecha/hora UTC:** 2026-10-24 12:05 UTC
- **Tarea:** revisión de seguridad pedida por IMP-2 (estado/IMP-2.md): neutralización CSV y saneo de filename en ui/dashboard.py. Veredicto: `_safe_download_name` seguro; `_csv_cell` sin `-` en los prefijos de fórmula (OWASP CSV injection: = + - @).
- **Rutas que voy a tocar:**
  - `ui/dashboard.py` (fix mínimo: añadir "-" a _CSV_FORMULA_PREFIXES)
  - `tests/test_seg_csv.py` (nuevo: regresión offline)
- **Verificación previa:** sin claims activos sobre ui/ (readme-en-desde-cero y scope-collectores son de PUL-1/IMP-1); fix-h005 (096e190) tocó ui/dashboard.py hace >12 h.
