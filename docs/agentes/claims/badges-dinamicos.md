# Claim: badges-dinamicos

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 17:25 UTC
- **Tarea (ROADMAP · Banco):** (PUL-1) badges-dinamicos / badge-auto (propuesta PUL-1 ronda 2) — workflow que actualiza el badge de tests y versión en cada push a main; fin de la deriva manual (badge decía 706, suite va por 767)
- **Rutas que voy a tocar:**
  - `.github/workflows/ci.yml` (job `badges` nuevo: cuenta tests con `pytest --collect-only`, lee versión de pyproject.toml, escribe `.github/badges/*.json` y commitea con `[skip ci]` si cambian)
  - `.github/badges/tests.json`, `.github/badges/version.json` (NUEVOS — endpoint JSON de shields.io, semilla inicial)
  - `README.md`, `README.es.md` (solo los 2 badges estáticos Tests/Version → endpoint dinámico; nada más)
  - `CHANGELOG.md` (una línea bajo [Unreleased] → Añadido, excepción OWNERSHIP)
- **Garantías:** sin dependencias nuevas (tomllib stdlib + pytest ya presente); el job solo corre en push a main; el commit del badge lleva `[skip ci]` (no hay bucle); sin tocar rutas con claim activo (osint_eye.py de SEG/IMP-3/IMP-1, modules/, docs/assets/ de TEST)
- **NO toco:** osint_eye.py, modules/, tests/, docs/assets/, Dockerfile
