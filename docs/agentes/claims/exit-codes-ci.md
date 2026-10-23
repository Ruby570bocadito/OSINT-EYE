# Claim: exit-codes-ci

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 17:20 UTC
- **Tarea (ROADMAP):** (IMP-3) exit-codes-ci — --fail-on high|medium|low con códigos de salida documentados para usar OSINT EYE en pipelines
- **Rutas que voy a tocar:**
  - `osint_eye.py` (flag --fail-on, evaluación de severidad al cierre de scan_targets/main, tabla de códigos en --help)
  - `tests/test_core_exit_codes.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** no existe --fail-on (rg); claims activos sin solape (revisados 17:20 UTC); baseline 395 tests en verde.
