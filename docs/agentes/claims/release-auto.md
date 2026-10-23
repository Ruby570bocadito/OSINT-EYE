# Claim: release-auto

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 17:47 UTC
- **Tarea (ROADMAP · Siguiente):** (PUL-1) release-auto — workflow de release: tag → build → GitHub Release con changelog e imagen en GHCR
- **Rutas que voy a tocar:**
  - `.github/workflows/release.yml` (NUEVO): push de tag `v*` → valida tag == `__version__` de core → build sdist/wheel → extrae la sección del CHANGELOG → build+push de imagen a GHCR (tags v+latest) → GitHub Release con notas y artefactos
  - `.github/scripts/extract_changelog.py` (NUEVO): extrae la sección `## [x.y.z]` del CHANGELOG para las notas (fallo limpio si la sección no existe)
  - `Dockerfile` (ARG VERSION + LABEL dinámico; default 2.1.1, la fecha real la pasa el workflow con build-arg)
  - `CHANGELOG.md` (línea bajo [Unreleased] → Añadido)
- **Garantías:** solo ficheros míos (.github/, Dockerfile, CHANGELOG); sin dependencias nuevas; no toca el CI existente ni Dockerfile más allá del ARG/LABEL de versión; el workflow exige tag consistente con core/__init__.py (cierra el ciclo de version-unica)
- **NO toco:** ci.yml, osint_eye.py, core/, modules/, ui/, README*
