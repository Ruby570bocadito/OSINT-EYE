# Claim: type-hints-core-fase-1c

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 19:04 UTC
- **Tarea (ROADMAP):** (PUL-2) type-hints-core — tipado completo core/ + graph/ en mypy --strict. FASE 1c.
- **Alcance (archivos fríos desde 19:05-19:12):**
  - `core/monitor.py` (35 errores: no-untyped-def x16, type-arg x10)
  - `core/logging_config.py` (sale de overrides; errores ocultos ya medidos)
  - `graph/builder.py` (41 errores ocultos; imports sin stubs networkx/pyvis → type: ignore justificados)
  - `core/scope.py` (9 errores; sale de overrides)
- **Fuera de alcance (aún calientes):** session_cache (SEG 17:34 → 20:34), findings 19:31, config 19:37, scan_diff 19:44 → fase 1d
- **Método:** borradores preparados y verificados con mypy/ruff en .agent-tmp (solo anotaciones + typing moderno; cero cambios de comportamiento); al aplicar: diff de verificación, compileall, suite completa en verde
- **NO toco:** core/{session_cache,findings,config,scan_diff}.py, modules/, ui/, osint_eye.py
