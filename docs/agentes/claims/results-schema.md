# Claim: results-schema

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 15:52 UTC
- **Tarea (ROADMAP):** (IMP-3) results-schema — definir el contrato de results (dataclasses/TypedDict + validate_results()), versión de esquema en el JSON y test de que cada módulo cumple
- **Rutas que voy a tocar:**
  - `core/schema.py` (nuevo: SCHEMA_VERSION, TypedDicts, validate_results(), validadores por módulo)
  - `osint_eye.py` (añadir `schema_version` al dict results + validación no fatal al cerrar el scan)
  - `tests/test_core_schema.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** core/schema.py y tests/test_core_schema.py no existen; `rg validate_results` sin resultados; claims activos (IMP-2 dashboard-filtros, PUL-1 readme-fiel) sin solape de rutas; baseline 118 tests en verde.
