# Claim: pre-commit-hooks

- **Agente:** PUL-1
- **Fecha/hora UTC:** 2026-10-23 17:43 UTC
- **Tarea (ROADMAP · Banco/Pulimiento):** (PUL-1) Pre-commit hooks (ruff, end-of-file, trailing whitespace)
- **Rutas que voy a tocar:**
  - `.pre-commit-config.yaml` (NUEVO): ruff con la puerta actual de CI (`--select E9 --no-fix`, se subirá al ruleset completo cuando PUL-2 cierre ruff-config), end-of-file-fixer y trailing-whitespace (excluye .md por los saltos duros)
  - `pyproject.toml` (pre-commit al extra [dev])
  - `CONTRIBUTING.md` (sección opcional de hooks en el setup)
  - `CHANGELOG.md` (línea bajo [Unreleased] → Añadido)
- **Garantías:** solo ficheros míos o nuevos; sin dependencias de runtime (pre-commit va al extra [dev], igual que ruff/pytest); los hooks no cambian comportamiento del producto; 692 avisos del ruleset completo quedan para (PUL-2) ruff-config, no bloqueo a nadie con E9
- **NO toco:** **/*.py (los fixes de ruff son de PUL-2), osint_eye.py, modules/, docs/assets/
