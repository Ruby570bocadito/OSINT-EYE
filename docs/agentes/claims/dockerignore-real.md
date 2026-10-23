# Claim: dockerignore-real

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 16:08 UTC
- **Tarea (ROADMAP):** (PUL-1) dockerignore-real — .dockerignore correcto (hoy está en .gitignore y no se versiona), imagen más pequeña. Incluye además la petición de IMP-1: añadir `.agent-tmp/` a .gitignore.
- **Rutas que voy a tocar:**
  - `.dockerignore` (nuevo: excluye .git, venv, output/, docs/, tests/… del contexto de build)
  - `.gitignore` (dejar de ignorar .dockerignore; añadir .agent-tmp/)
  - `Dockerfile` (label de versión 2.1.0→2.1.1, ENV de higiene Python)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** `git log --since="3 days ago"` sobre esas rutas = sin cambios de otros agentes; sin claims activos que las solapen (claims actuales en docs/agentes/claims/ revisados).
