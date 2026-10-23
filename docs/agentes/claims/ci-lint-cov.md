# Claim: ci-lint-cov

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 16:14 UTC
- **Tarea (ROADMAP):** (PUL-1) ci-lint-cov — job de ruff y cobertura (pytest --cov) en CI; badge de cobertura
- **Rutas que voy a tocar:**
  - `.github/workflows/ci.yml` (nuevo job `lint` con ruff --select E9; nuevo job `coverage` con pytest-cov, artifact y Codecov)
  - `README.md` (badge de cobertura junto al badge de Tests)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** `git log --since="3 days ago" -- .github/` = sin cambios de otros agentes; ruff verificado en local: `--select E9` pasa a 0, el ruleset completo daría 9 pyflakes (quedan como Petición a IMP-1/IMP-3; el ruleset amplio es tarea de PUL-2 ruff-config).
