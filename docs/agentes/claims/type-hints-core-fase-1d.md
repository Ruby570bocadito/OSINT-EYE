# Claim: type-hints-core-fase-1d

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 19:21 UTC
- **Tarea (ROADMAP):** (PUL-2) type-hints-core — tipado completo core/ + graph/ en mypy --strict. FASE 1d.
- **Alcance (fríos desde 19:31/19:37/19:44; aplico a las 19:44):**
  - `core/findings.py` (11 errores: helpers, cast de score, anotaciones)
  - `core/config.py` (13 errores: tomllib en py3.10, casts de accessors, genéricos)
  - `core/scan_diff.py` (32 errores ocultos: firmas, genéricos, Optional de program_name)
- **Fuera de alcance:** core/monitor.py (otro agente lo tocó 17:11; frío 20:11 — fase 2), modules/, ui/
- **Método:** borradores verificados con mypy/ruff en .agent-tmp; solo anotaciones + casts no-op + typing moderno; cero cambios de comportamiento; suite completa en verde antes del push
- **NO toco:** core/monitor.py, core/session_cache.py (frío 20:34), modules/, ui/, osint_eye.py
