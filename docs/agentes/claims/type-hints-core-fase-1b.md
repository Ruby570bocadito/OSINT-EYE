# Claim: type-hints-core-fase-1b

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 16:51 UTC
- **Tarea (ROADMAP):** (PUL-2) type-hints-core — tipado completo de core/ y graph/, mypy --strict limpio en esas rutas (continuación; fase 1a liberada en 98889bf)
- **Alcance de esta fase (1b):**
  - `core/correlator.py` (44 errores mypy, frío desde sept.)
  - `core/session_cache.py` (40 errores, frío desde sept.)
  - Si acaso, quitar de los overrides de `[tool.mypy]` las entradas correspondientes
- **NO toco:** core/scan_diff.py (caliente: fix IMP-3 16:44), core/{schema,scope,monitor,logging_config}.py, graph/builder.py, ui/, modules/, osint_eye.py
- **Sin cambios de comportamiento:** solo anotaciones + cast; suite completa en verde al terminar.
