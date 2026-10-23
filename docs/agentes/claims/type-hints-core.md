# Claim: type-hints-core

- **Agente:** PUL-2
- **Fecha/hora UTC:** 2026-10-23 16:47 UTC
- **Tarea (ROADMAP):** (PUL-2) type-hints-core — tipado completo de core/ y graph/, mypy --strict limpio en esas rutas
- **Alcance de esta fase (1a — archivos fríos sin actividad IMP <3 h):**
  - `core/async_engine.py` (54 errores mypy), `core/plugins.py` (15), `graph/neo4j_exporter.py` (7)
  - `pyproject.toml`: sección `[tool.mypy]` (strict) + overrides temporales `ignore_errors` para módulos aún sin tipar (core.logging_config, graph.builder, modules, modules.*) — cada fase posterior irá quitando entradas al tipar su zona
  - `[project.optional-dependencies].dev`: añadir mypy
- **NO toco (calientes o fases futuras):** core/{correlator,scan_diff,session_cache,schema,scope,monitor,logging_config}.py, graph/builder.py, osint_eye.py, ui/, modules/ — fase 1b/1c (scan_diff, session_cache, correlator) cuando se enfríen o en siguiente ronda.
- **Nota técnica:** core/__init__.py importa todos los submódulos, así que mypy sobre cualquier fichero de core/ arrastra el paquete entero; los overrides son imprescindibles, no un parche.
- **Sin cambios de comportamiento:** solo anotaciones + cast (no-op en runtime); nada de isinstance nuevos donde no los había; suite completa debe seguir en verde.
