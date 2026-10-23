# Claim: scope-file

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 16:22 UTC
- **Tarea (ROADMAP):** (IMP-3) scope-file — --scope scope.txt / --exclude (dominios, wildcards, CIDR): ningún módulo activo toca algo fuera de scope; los descartes se registran
- **Rutas que voy a tocar:**
  - `core/scope.py` (nuevo: Scope con dominios/wildcards/CIDR, exclude con prioridad, registro de descartes)
  - `osint_eye.py` (flags --scope/--exclude, gating de targets en scan_targets, filtrado en permutation/takeover, results["scope"])
  - `tests/test_core_scope.py` (nuevo, tests offline)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** core/scope.py no existe; claims activos sin solape (revisados 16:20 UTC); baseline 278 tests en verde en el último push.
