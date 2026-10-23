# Claim: pyproject

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 16:02 UTC
- **Tarea (ROADMAP):** (PUL-1) pyproject — pyproject.toml con metadatos, extras ([ui], [pdf], [dev]) y entry point osint-eye; pip install -e . funciona
- **Rutas que voy a tocar:**
  - `pyproject.toml` (nuevo: metadatos, dependencias en paridad con requirements.txt, extras, entry point, packages.find)
  - `CHANGELOG.md` (solo añadir línea bajo `## [Unreleased]`)
- **Verificación previa:** no existe pyproject.toml en el repo; `git log --since="3 days ago" -- pyproject.toml requirements.txt` = sin cambios de otros agentes; sin claims activos sobre esas rutas.
